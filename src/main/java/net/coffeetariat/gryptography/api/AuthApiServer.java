package net.coffeetariat.gryptography.api;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.pebbletemplates.pebble.PebbleEngine;
import io.pebbletemplates.pebble.template.PebbleTemplate;
import net.coffeetariat.gryptography.auth.ChallengeInquiry;
import net.coffeetariat.gryptography.auth.JWTToken;
import net.coffeetariat.gryptography.auth.HostOriginBoundAuthorization;
import net.coffeetariat.gryptography.lib.ClientPublicKeysYaml;
import net.coffeetariat.gryptography.lib.ClientPrivateKeysYaml;
import net.coffeetariat.gryptography.lib.RSAKeyPairGenerator;
import net.coffeetariat.gryptography.lib.Utilities;

import java.io.IOException;
import java.io.OutputStream;
import java.io.StringWriter;
import java.io.Writer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

// todo -> create a POST endpoint that will process a challenge from the client.

/**
 * A tiny HTTP API that exposes and manages clients' public keys using a YAML store.
 *
 * Endpoints:
 * - GET /health -> 200 OK with "ok"
 * - GET /api/clients/{clientId}/public-key -> 200 OK text/plain (PEM public key)
 *      404 Not Found if client is unknown, 500 on server error
 * - POST /api/clients/{clientId}/keypair -> 201 Created text/plain (PEM private key)
 *      Generates a new RSA key pair, stores only the public key, and returns the private key.
 *
 * Server configuration:
 *  - Port can be provided as the first CLI arg (default 8080)
 *  - YAML path is clients-and-public-keys.yaml in the current working directory
 */
public class AuthApiServer {

  private static final String TEXT_PLAIN = MediaTypes.TEXT_PLAIN.value();

  private final HttpServer server;
  private final ClientPublicKeysYaml publicKeysYaml;
  private final ClientPrivateKeysYaml privateKeysYaml;

  public AuthApiServer(int port, Path yamlPath) throws IOException {
    PebbleEngine engine = new PebbleEngine.Builder().build();
    PebbleTemplate compiledTemplate = engine.getTemplate("templates/index.peb");

    this.publicKeysYaml = new ClientPublicKeysYaml(yamlPath);
    // Private keys store (used to sign JWTs for demo purposes)
    Path privYamlPath = Path.of("clients-and-private-keys.yaml");
    this.privateKeysYaml = new ClientPrivateKeysYaml(privYamlPath);
    this.server = HttpServer.create(new InetSocketAddress(port), 0);

    // Web Static Files
    // Serve static files from classpath: src/main/resources/www/** -> GET /www/**
    server.createContext("/www", exchange -> {
      String method = exchange.getRequestMethod();
      if ("OPTIONS".equalsIgnoreCase(method)) {
        respond(exchange, 204, "", MediaTypes.TEXT_PLAIN.value());
        return;
      }
      if (!"GET".equalsIgnoreCase(method) && !"HEAD".equalsIgnoreCase(method)) {
        respond(exchange, 405, "method not allowed", MediaTypes.TEXT_PLAIN.value());
        return;
      }

      // Compute the requested resource path under classpath folder "www"
      String requestPath = exchange.getRequestURI().getPath(); // e.g. /www/index.css
      String subPath = requestPath.substring("/www".length()); // e.g. /index.css or ""
      if (subPath.isEmpty() || "/".equals(subPath)) {
        // default file if someone hits /www or /www/
        subPath = "/index.html"; // change if you prefer another default
      }

      // Prevent path traversal and normalize
      String normalized = subPath.replace('\\', '/');
      if (normalized.contains("..")) {
        respond(exchange, 400, "bad path", MediaTypes.TEXT_PLAIN.value());
        return;
      }

      String classpathLocation = "www" + normalized; // e.g. www/index.css

      try (java.io.InputStream is = Thread.currentThread()
          .getContextClassLoader()
          .getResourceAsStream(classpathLocation)) {
        if (is == null) {
          respond(exchange, 404, "not found", MediaTypes.TEXT_PLAIN.value());
          return;
        }

        // Content-Type based on extension
        String contentType = contentTypeFor(classpathLocation);

        // Small caching for static assets (adjust as you like)
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", contentType);
        headers.set("Cache-Control", "public, max-age=3600");

        if ("HEAD".equalsIgnoreCase(method)) {
          exchange.sendResponseHeaders(200, -1);
          exchange.close();
          return;
        }

        byte[] bytes = is.readAllBytes();
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
          os.write(bytes);
        }
      } catch (IOException e) {
        respond(exchange, 500, "internal server error", MediaTypes.TEXT_PLAIN.value());
      }
    });

    // Basic endpoints
    server.createContext("/health", this::handleHealth);
    server.createContext("/api/clients", this::handleClientsRoot);
    server.createContext("/api/challenge", this::handleChallenge);
    server.createContext("/api/answer", this::handleAnswer);
    server.createContext("/", exchange -> {
      String method = exchange.getRequestMethod();
      if ("OPTIONS".equalsIgnoreCase(method)) {
        respond(exchange, 204, "", MediaTypes.TEXT_PLAIN.value());
        return;
      }
      if (!"GET".equalsIgnoreCase(method)) {
        respond(exchange, 405, "method not allowed", MediaTypes.TEXT_PLAIN.value());
        return;
      }

      // Only render the index for the exact root path. Any other unknown path -> 404.
      String requestPath = exchange.getRequestURI().getPath();
      if (!"/".equals(requestPath)) {
        respond(exchange, 404, "not found", MediaTypes.TEXT_PLAIN.value());
        return;
      }

      Writer writer = new StringWriter();

      Map<String, Object> context = new HashMap<>();
      context.put("apiTitleAndVersion", "Grypto API Server - version 1.0");
      context.put("countOfClients", publicKeysYaml.listClients().size());
      context.put("clientsAndPublicKeys", publicKeysYaml.listClientsAndPublicKeys());

      compiledTemplate.evaluate(writer, context);

      String output = writer.toString();

      respond(exchange, 200, output, "text/html");
    });

    // Use a small thread pool
    server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
  }

  private static String contentTypeFor(String path) {
    String p = path.toLowerCase();
    if (p.endsWith(".html") || p.endsWith(".htm")) return "text/html";
    if (p.endsWith(".css")) return "text/css";
    if (p.endsWith(".js")) return "application/javascript";
    if (p.endsWith(".json")) return "application/json";
    if (p.endsWith(".svg")) return "image/svg+xml";
    if (p.endsWith(".png")) return "image/png";
    if (p.endsWith(".jpg") || p.endsWith(".jpeg")) return "image/jpeg";
    if (p.endsWith(".gif")) return "image/gif";
    if (p.endsWith(".ico")) return "image/x-icon";
    return "application/octet-stream";
  }

  public void start() {
    server.start();
    Runtime.getRuntime().addShutdownHook(new Thread(() -> server.stop(0)));
    System.out.println("AuthApiServer started on http://localhost:" + server.getAddress().getPort());
  }

  private void handleHealth(HttpExchange exchange) throws IOException {
    if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
      respond(exchange, 405, "method not allowed", MediaTypes.TEXT_PLAIN.value());
      return;
    }
    addNoCache(exchange.getResponseHeaders());
    respond(exchange, 200, "ok", MediaTypes.TEXT_PLAIN.value());
  }

  private void handleClientsRoot(HttpExchange exchange) throws IOException {
    try {
      String method = exchange.getRequestMethod();

      // Preflight support for CORS
      if ("OPTIONS".equalsIgnoreCase(method)) {
        respond(exchange, 204, "", MediaTypes.TEXT_PLAIN.value());
        return;
      }

      URI uri = exchange.getRequestURI();
      String path = uri.getPath(); // e.g., /api/clients/{id}/public-key or /new-private-key

      String[] parts = path.split("/");
      // ["", "api", "clients", "{id}", "public-key"|"keypair"]
      if (parts.length == 5) {
        String rawId = parts[3];
        String clientId = URLDecoder.decode(rawId, StandardCharsets.UTF_8);
        if ("GET".equalsIgnoreCase(method) && "public-key".equals(parts[4])) {
          handleGetPublicKey(exchange, clientId);
          return;
        }
        if ("GET".equalsIgnoreCase(method) && "new-private-key".equals(parts[4])) {
          handleCreateKeyPair(exchange, clientId);
          return;
        }
      }

      // Method not allowed or not found
      if ("GET".equalsIgnoreCase(method) || "POST".equalsIgnoreCase(method)) {
        respond(exchange, 404, "not found", MediaTypes.TEXT_PLAIN.value());
      } else {
        respond(exchange, 405, "method not allowed", MediaTypes.TEXT_PLAIN.value());
      }
    } catch (Exception e) {
      respond(exchange, 500, "internal server error", MediaTypes.TEXT_PLAIN.value());
    }
  }

  private void handleGetPublicKey(HttpExchange exchange, String clientId) throws IOException {
    addNoCache(exchange.getResponseHeaders());
    Optional<PublicKey> maybe = publicKeysYaml.getPublicKey(clientId);
    if (maybe.isEmpty()) {
      respond(exchange, 404, "client not found", MediaTypes.TEXT_PLAIN.value());
      return;
    }
    PublicKey pub = maybe.get();
    String pem = Utilities.toPem(pub);
    respond(exchange, 200, pem, MediaTypes.TEXT_PLAIN.value());
  }

  private void handleCreateKeyPair(HttpExchange exchange, String clientId) throws IOException {
    addNoCache(exchange.getResponseHeaders());

    try {
      KeyPair keyPair = RSAKeyPairGenerator.generate();
      PrivateKey privateKey = publicKeysYaml.register(clientId, keyPair); // stores only public key
      privateKeysYaml.register(clientId, privateKey);
      String pem = Utilities.toPem(privateKey);
      respond(exchange, 201, pem, MediaTypes.TEXT_PLAIN.value());
    } catch (Exception e) {
      respond(exchange, 500, "internal server error", MediaTypes.TEXT_PLAIN.value());
    }
  }

  private static void addNoCache(Headers headers) {
    headers.add("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
    headers.add("Pragma", "no-cache");
  }

  private void handleChallenge(HttpExchange exchange) throws IOException {
    String method = exchange.getRequestMethod();
    if ("OPTIONS".equalsIgnoreCase(method)) {
      respond(exchange, 204, "", MediaTypes.TEXT_PLAIN.value());
      return;
    }
    if (!"GET".equalsIgnoreCase(method)) {
      respond(exchange, 405, "method not allowed", MediaTypes.TEXT_PLAIN.value());
      return;
    }
    addNoCache(exchange.getResponseHeaders());

    // Parse query param clientId
    URI uri = exchange.getRequestURI();
    String query = uri.getQuery();
    String clientId = getQueryParam(query, "clientId");
    if (clientId == null || clientId.isBlank()) {
      respond(exchange, 400, "missing required query parameter: clientId", MediaTypes.TEXT_PLAIN.value());
      return;
    }

    try {
      ChallengeInquiry inquiry = HostOriginBoundAuthorization.createChallenge(clientId, publicKeysYaml, privateKeysYaml);

      // Content negotiation for Accept header
      Headers reqHeaders = exchange.getRequestHeaders();
      String accept = Optional.ofNullable(reqHeaders.getFirst("Accept")).orElse("*/*").toLowerCase();

      String body;
      String contentType;
      if (accept.contains(MediaTypes.APPLICATION_YAML.value()) || accept.contains(MediaTypes.TEXT_YAML.value()) || accept.contains(MediaTypes.APPLICATION_X_YAML.value())) {
        body = inquiry.toYaml();
        contentType = MediaTypes.APPLICATION_YAML.value();
      } else {
        body = inquiry.toJson();
        contentType = MediaTypes.APPLICATION_JSON.value();
      }

      respond(exchange, 200, body, contentType);
    } catch (IllegalArgumentException e) {
      respond(exchange, 404, "client not found", MediaTypes.TEXT_PLAIN.value());
    } catch (Exception e) {
      respond(exchange, 500, "internal server error", MediaTypes.TEXT_PLAIN.value());
    }
  }

  private void handleAnswer(HttpExchange exchange) throws IOException {
    String method = exchange.getRequestMethod();
    if ("OPTIONS".equalsIgnoreCase(method)) {
      respond(exchange, 204, "", MediaTypes.TEXT_PLAIN.value());
      return;
    }
    if (!"POST".equalsIgnoreCase(method)) {
      respond(exchange, 405, "method not allowed", MediaTypes.TEXT_PLAIN.value());
      return;
    }
    addNoCache(exchange.getResponseHeaders());

    // Parse query param clientId
    URI uri = exchange.getRequestURI();
    String query = uri.getQuery();
    String clientId = getQueryParam(query, "clientId");
    if (clientId == null || clientId.isBlank()) {
      respond(exchange, 400, "missing required query parameter: clientId", MediaTypes.TEXT_PLAIN.value());
      return;
    }

    // Expect application/x-www-form-urlencoded body with fields: sessionId, answer (Base64)
    String contentType = Optional.ofNullable(exchange.getRequestHeaders().getFirst("Content-Type")).orElse("");
    if (!contentType.toLowerCase().contains("application/x-www-form-urlencoded")) {
      respond(exchange, 415, "unsupported media type (expected application/x-www-form-urlencoded)", MediaTypes.TEXT_PLAIN.value());
      return;
    }

    String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    Map<String, String> form = new HashMap<>();
    if (!body.isEmpty()) {
      String[] pairs = body.split("&");
      for (String p : pairs) {
        int idx = p.indexOf('=');
        String key = idx >= 0 ? p.substring(0, idx) : p;
        String val = idx >= 0 ? p.substring(idx + 1) : "";
        try {
          key = URLDecoder.decode(key, StandardCharsets.UTF_8);
          val = URLDecoder.decode(val, StandardCharsets.UTF_8);
        } catch (Exception ignored) {}
        form.put(key, val);
      }
    }

    String sessionId = form.get("sessionId");
    String signedAnswer = form.get("answer");
    if (sessionId == null || sessionId.isBlank() || signedAnswer == null || signedAnswer.isBlank()) {
      respond(exchange, 400, "missing required form fields: sessionId and answer", MediaTypes.TEXT_PLAIN.value());
      return;
    }

    try {
      boolean ok = HostOriginBoundAuthorization.verifyAndConsumeAnswer(sessionId, signedAnswer, publicKeysYaml);
      // Verify it matches the expected session answer
      if (!ok) {
        respond(exchange, 401, "invalid answer", MediaTypes.TEXT_PLAIN.value());
        return;
      }

      // On success, issue a short-lived JWT for this client
      var maybePriv = privateKeysYaml.getPrivateKey(clientId);
      if (maybePriv.isEmpty()) {
        respond(exchange, 500, "signing key not available for client", MediaTypes.TEXT_PLAIN.value());
        return;
      }
      var priv = maybePriv.get();
      long ttlSeconds = 3600;
      String token = JWTToken.generate(priv, clientId, "grypto-auth", "grypto-api", ttlSeconds, Map.of("clientId", clientId));

      String json = "{" +
          "\"token\":\"" + token + "\"," +
          "\"token_type\":\"Bearer\"," +
          "\"expires_in\":" + ttlSeconds +
          "}";

      respond(exchange, 200, json, MediaTypes.APPLICATION_JSON.value());
    } catch (IllegalArgumentException e) {
      respond(exchange, 404, "client or session not found", MediaTypes.TEXT_PLAIN.value());
    } catch (Exception e) {
      respond(exchange, 500, "internal server error", MediaTypes.TEXT_PLAIN.value());
    }
  }

  private static String getQueryParam(String query, String name) {
    if (query == null || query.isEmpty()) return null;
    String[] pairs = query.split("&");
    for (String p : pairs) {
      int idx = p.indexOf('=');
      String key = idx >= 0 ? p.substring(0, idx) : p;
      String val = idx >= 0 ? p.substring(idx + 1) : "";
      if (name.equals(key)) {
        try {
          return URLDecoder.decode(val, StandardCharsets.UTF_8);
        } catch (Exception ignored) {
          return val;
        }
      }
    }
    return null;
  }

  private static void respond(HttpExchange exchange, int status, String body, String contentType) throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    Headers headers = exchange.getResponseHeaders();
    headers.set("Content-Type", contentType + "; charset=utf-8");
    // Basic CORS for GET and POST
    headers.set("Access-Control-Allow-Origin", "*");
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Content-Type");

    if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
      exchange.sendResponseHeaders(204, -1);
      exchange.close();
      return;
    }

    exchange.sendResponseHeaders(status, bytes.length);
    try (OutputStream os = exchange.getResponseBody()) {
      os.write(bytes);
    }
  }

  public static void main(String[] args) throws IOException {
    int port = 8080;
    if (args != null && args.length > 0) {
      try { port = Integer.parseInt(args[0]); } catch (NumberFormatException ignored) {}
    }
    Path yamlPath = Path.of("clients-and-public-keys.yaml");
    AuthApiServer s = new AuthApiServer(port, yamlPath);
    s.start();
  }
}
