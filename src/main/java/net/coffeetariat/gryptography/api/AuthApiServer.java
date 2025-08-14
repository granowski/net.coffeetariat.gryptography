package net.coffeetariat.gryptography.api;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import net.coffeetariat.gryptography.auth.ChallengeInquiry;
import net.coffeetariat.gryptography.auth.HostOriginBoundAuthorization;
import net.coffeetariat.gryptography.lib.ClientPublicKeysYaml;
import net.coffeetariat.gryptography.lib.RSAKeyPairGenerator;
import net.coffeetariat.gryptography.lib.Utilities;
import net.coffeetariat.gryptography.api.MediaTypes;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
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

  public AuthApiServer(int port, Path yamlPath) throws IOException {
    this.publicKeysYaml = new ClientPublicKeysYaml(yamlPath);
    this.server = HttpServer.create(new InetSocketAddress(port), 0);

    // Basic endpoints
    server.createContext("/health", this::handleHealth);
    server.createContext("/api/clients", this::handleClientsRoot);
    server.createContext("/api/challenge", this::handleChallenge);
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

      String path = exchange.getRequestURI().getPath();
      if (path == null || "/".equals(path)) {
        path = "/index.html"; // default document
      }
      // Normalize and prevent path traversal
      if (path.contains("..")) {
        respond(exchange, 400, "bad request", MediaTypes.TEXT_PLAIN.value());
        return;
      }

      // Serve from classpath under /public
      String resourcePath = "public" + path; // e.g., public/index.html
      try (var in = Thread.currentThread().getContextClassLoader().getResourceAsStream(resourcePath)) {
        if (in == null) {
          respond(exchange, 404, "not found", MediaTypes.TEXT_PLAIN.value());
          return;
        }
        byte[] bytes = in.readAllBytes();

        // Pick content type
        String contentType = contentTypeFor(path);

        // Headers and caching policy (reusing your style)
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", contentType + "; charset=utf-8");
        headers.set("Access-Control-Allow-Origin", "*");
        headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        headers.set("Access-Control-Allow-Headers", "Content-Type");
        // For HTML, avoid caching while developing; adjust for prod as needed
        addNoCache(headers);

        exchange.sendResponseHeaders(200, bytes.length);
        try (var os = exchange.getResponseBody()) {
          os.write(bytes);
        }
      } catch (IOException e) {
        respond(exchange, 500, "internal server error", MediaTypes.TEXT_PLAIN.value());
      }
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
      ChallengeInquiry inquiry = HostOriginBoundAuthorization.createChallenge(clientId, publicKeysYaml);

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

  // todo -> review this code since it's very primitive looking.
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
