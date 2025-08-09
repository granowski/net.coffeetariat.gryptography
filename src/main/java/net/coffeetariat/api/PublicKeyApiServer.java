package net.coffeetariat.api;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import net.coffeetariat.gryptography.ClientPrivateKeysYaml;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Optional;

/**
 * A tiny HTTP API that exposes clients' public keys derived from a YAML store.
 *
 * Endpoints:
 * - GET /health -> 200 OK with "ok"
 * - GET /api/clients/{clientId}/public-key -> 200 OK text/plain (PEM public key)
 *      404 Not Found if client is unknown, 500 on server error
 *
 * Server configuration:
 *  - Port can be provided as the first CLI arg (default 8080)
 *  - YAML path is clients-and-keys.yaml in the current working directory
 */
public class PublicKeyApiServer {

  private final HttpServer server;
  private final ClientPrivateKeysYaml store;

  public PublicKeyApiServer(int port, Path yamlPath) throws IOException {
    this.store = new ClientPrivateKeysYaml(yamlPath);
    this.server = HttpServer.create(new InetSocketAddress(port), 0);

    // Basic endpoints
    server.createContext("/health", this::handleHealth);
    server.createContext("/api/clients", this::handleClientsRoot);

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
      if (!"GET".equalsIgnoreCase(method)) {
        respond(exchange, 405, "method not allowed", "text/plain");
        return;
      }

      URI uri = exchange.getRequestURI();
      String path = uri.getPath(); // e.g., /api/clients/{id}/public-key

      // Expected pattern: /api/clients/{clientId}/public-key
      String[] parts = path.split("/");
      // ["", "api", "clients", "{id}", "public-key"]
      if (parts.length == 5 && "public-key".equals(parts[4])) {
        String rawId = parts[3];
        String clientId = URLDecoder.decode(rawId, StandardCharsets.UTF_8);
        handleGetPublicKey(exchange, clientId);
        return;
      }

      // Not found
      respond(exchange, 404, "not found", "text/plain");
    } catch (Exception e) {
      respond(exchange, 500, "internal server error", "text/plain");
    }
  }

  private void handleGetPublicKey(HttpExchange exchange, String clientId) throws IOException {
    addNoCache(exchange.getResponseHeaders());
    Optional<PublicKey> maybe = store.getPublicKey(clientId);
    if (maybe.isEmpty()) {
      respond(exchange, 404, "client not found", "text/plain");
      return;
    }
    PublicKey pub = maybe.get();
    String pem = toPem(pub);
    respond(exchange, 200, pem, "text/plain");
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

  private static void respond(HttpExchange exchange, int status, String body, String contentType) throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    Headers headers = exchange.getResponseHeaders();
    headers.set("Content-Type", contentType + "; charset=utf-8");
    // Basic CORS for GET
    headers.set("Access-Control-Allow-Origin", "*");
    headers.set("Access-Control-Allow-Methods", "GET, OPTIONS");
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
    Path yamlPath = Path.of("clients-and-keys.yaml");
    PublicKeyApiServer s = new PublicKeyApiServer(port, yamlPath);
    s.start();
  }
}
