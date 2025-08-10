package net.coffeetariat.gryptography.api;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import net.coffeetariat.gryptography.auth.ChallengeInquiry;
import net.coffeetariat.gryptography.auth.HostOriginBoundAuthorization;
import net.coffeetariat.gryptography.lib.ClientPublicKeysYaml;
import net.coffeetariat.gryptography.lib.RSAKeyPairGenerator;

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
import java.util.Base64;
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
public class PublicKeyApiServer {

  private final HttpServer server;
  private final ClientPublicKeysYaml publicKeysYaml;

  public PublicKeyApiServer(int port, Path yamlPath) throws IOException {
    this.publicKeysYaml = new ClientPublicKeysYaml(yamlPath);
    this.server = HttpServer.create(new InetSocketAddress(port), 0);

    // Basic endpoints
    server.createContext("/health", this::handleHealth);
    server.createContext("/api/clients", this::handleClientsRoot);
    server.createContext("/api/challenge", this::handleChallenge);

    // Use a small thread pool
    server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
  }

  public void start() {
    server.start();
    Runtime.getRuntime().addShutdownHook(new Thread(() -> server.stop(0)));
    System.out.println("PublicKeyApiServer started on http://localhost:" + server.getAddress().getPort());
  }

  private void handleHealth(HttpExchange exchange) throws IOException {
    if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
      respond(exchange, 405, "method not allowed", "text/plain");
      return;
    }
    addNoCache(exchange.getResponseHeaders());
    respond(exchange, 200, "ok", "text/plain");
  }

  private void handleClientsRoot(HttpExchange exchange) throws IOException {
    try {
      String method = exchange.getRequestMethod();

      // Preflight support for CORS
      if ("OPTIONS".equalsIgnoreCase(method)) {
        respond(exchange, 204, "", "text/plain");
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
        respond(exchange, 404, "not found", "text/plain");
      } else {
        respond(exchange, 405, "method not allowed", "text/plain");
      }
    } catch (Exception e) {
      respond(exchange, 500, "internal server error", "text/plain");
    }
  }

  private void handleGetPublicKey(HttpExchange exchange, String clientId) throws IOException {
    addNoCache(exchange.getResponseHeaders());
    Optional<PublicKey> maybe = publicKeysYaml.getPublicKey(clientId);
    if (maybe.isEmpty()) {
      respond(exchange, 404, "client not found", "text/plain");
      return;
    }
    PublicKey pub = maybe.get();
    String pem = toPem(pub);
    respond(exchange, 200, pem, "text/plain");
  }

  private void handleCreateKeyPair(HttpExchange exchange, String clientId) throws IOException {
    addNoCache(exchange.getResponseHeaders());

    try {
      KeyPair keyPair = RSAKeyPairGenerator.generate();
      PrivateKey privateKey = publicKeysYaml.register(clientId, keyPair); // stores only public key
      String pem = toPem(privateKey);
      respond(exchange, 201, pem, "text/plain");
    } catch (Exception e) {
      respond(exchange, 500, "internal server error", "text/plain");
    }
  }

  private static void addNoCache(Headers headers) {
    headers.add("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
    headers.add("Pragma", "no-cache");
  }

  private static String toPem(PublicKey publicKey) {
    byte[] der = publicKey.getEncoded(); // X.509 SubjectPublicKeyInfo
    String base64 = Base64.getEncoder().encodeToString(der);
    StringBuilder sb = new StringBuilder();
    sb.append("-----BEGIN PUBLIC KEY-----\n");
    // Wrap at 64 chars per line
    for (int i = 0; i < base64.length(); i += 64) {
      int end = Math.min(i + 64, base64.length());
      sb.append(base64, i, end).append('\n');
    }
    sb.append("-----END PUBLIC KEY-----\n");
    return sb.toString();
  }

  private static String toPem(PrivateKey privateKey) {
    byte[] der = privateKey.getEncoded(); // PKCS#8
    String base64 = Base64.getEncoder().encodeToString(der);
    StringBuilder sb = new StringBuilder();
    sb.append("-----BEGIN PRIVATE KEY-----\n");
    for (int i = 0; i < base64.length(); i += 64) {
      int end = Math.min(i + 64, base64.length());
      sb.append(base64, i, end).append('\n');
    }
    sb.append("-----END PRIVATE KEY-----\n");
    return sb.toString();
  }

  private void handleChallenge(HttpExchange exchange) throws IOException {
    String method = exchange.getRequestMethod();
    if ("OPTIONS".equalsIgnoreCase(method)) {
      respond(exchange, 204, "", "text/plain");
      return;
    }
    if (!"GET".equalsIgnoreCase(method)) {
      respond(exchange, 405, "method not allowed", "text/plain");
      return;
    }
    addNoCache(exchange.getResponseHeaders());

    // Parse query param clientId
    URI uri = exchange.getRequestURI();
    String query = uri.getQuery();
    String clientId = getQueryParam(query, "clientId");
    if (clientId == null || clientId.isBlank()) {
      respond(exchange, 400, "missing required query parameter: clientId", "text/plain");
      return;
    }

    try {
      ChallengeInquiry inquiry = HostOriginBoundAuthorization.createChallenge(clientId, publicKeysYaml);

      // Content negotiation for Accept header
      Headers reqHeaders = exchange.getRequestHeaders();
      String accept = Optional.ofNullable(reqHeaders.getFirst("Accept")).orElse("*/*").toLowerCase();

      String body;
      String contentType;
      if (accept.contains("application/yaml") || accept.contains("text/yaml") || accept.contains("application/x-yaml")) {
        body = toYaml(inquiry);
        contentType = "application/yaml";
      } else {
        body = toJson(inquiry);
        contentType = "application/json";
      }

      respond(exchange, 200, body, contentType);
    } catch (IllegalArgumentException e) {
      respond(exchange, 404, "client not found", "text/plain");
    } catch (Exception e) {
      respond(exchange, 500, "internal server error", "text/plain");
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

  // todo -> this is AI generated crap I don't want...
  // It makes more sense to replace this with a simple serialization lib like Jackson.
  // For now I'll let it stand though because I prefer simple solutions.
  private static String toJson(ChallengeInquiry ci) {
    // Minimal JSON serialization without external libs; ensure basic escaping for quotes and backslashes
    String sess = jsonEscape(ci.sessionId);
    String inq = jsonEscape(ci.inquiry);
    return "{\"sessionId\":\"" + sess + "\",\"inquiry\":\"" + inq + "\"}";
  }

  // Minimal YAML serialization for ChallengeInquiry supporting requested mime type
  private static String toYaml(ChallengeInquiry ci) {
    String sess = yamlEscape(ci.sessionId);
    String inq = yamlEscape(ci.inquiry);
    return "sessionId: '" + sess + "'\n" +
           "inquiry: '" + inq + "'\n";
  }

  private static String yamlEscape(String s) {
    if (s == null) return "";
    // Single-quote style in YAML: escape single quotes by doubling them
    return s.replace("'", "''");
  }

  // todo -> Okay this is a bit much... we're gonna need Jackson instead...
  // But for later...
  private static String jsonEscape(String s) {
    if (s == null) return "";
    StringBuilder sb = new StringBuilder(s.length() + 16);
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"': sb.append("\\\""); break;
        case '\\': sb.append("\\\\"); break;
        case '\b': sb.append("\\b"); break;
        case '\f': sb.append("\\f"); break;
        case '\n': sb.append("\\n"); break;
        case '\r': sb.append("\\r"); break;
        case '\t': sb.append("\\t"); break;
        default:
          if (c < 0x20) {
            sb.append(String.format("\\u%04x", (int) c));
          } else {
            sb.append(c);
          }
      }
    }
    return sb.toString();
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
    PublicKeyApiServer s = new PublicKeyApiServer(port, yamlPath);
    s.start();
  }
}
