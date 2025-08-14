package net.coffeetariat.gryptography.auth;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Utility for generating compact JWT (JWS) tokens signed with RS256.
 */
public final class JWTToken {
  private JWTToken() {}

  /**
   * Generates a compact JWT (JWS) signed with RS256 using the provided PrivateKey.
   *
   * Standard claims included:
   * - iss (issuer), sub (subject), aud (audience), iat (issued-at), exp (expiration)
   *
   * You can provide additional claims via additionalClaims (String, Number, Boolean values only).
   *
   * @param privateKey RSA private key for RS256 signing
   * @param subject JWT subject (sub)
   * @param issuer JWT issuer (iss)
   * @param audience JWT audience (aud)
   * @param ttlSeconds time-to-live in seconds from now
   * @param additionalClaims optional additional claims to include (String, Number, Boolean)
   * @return compact serialized JWT string
   */
  public static String generate(PrivateKey privateKey,
                                String subject,
                                String issuer,
                                String audience,
                                long ttlSeconds,
                                Map<String, Object> additionalClaims) {
    Objects.requireNonNull(privateKey, "privateKey");
    long nowSec = System.currentTimeMillis() / 1000L;
    long expSec = nowSec + Math.max(0, ttlSeconds);

    String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";

    Map<String, Object> payload = new LinkedHashMap<>();
    if (issuer != null) payload.put("iss", issuer);
    if (subject != null) payload.put("sub", subject);
    if (audience != null) payload.put("aud", audience);
    payload.put("iat", nowSec);
    payload.put("exp", expSec);
    if (additionalClaims != null) {
      for (Map.Entry<String, Object> e : additionalClaims.entrySet()) {
        String k = e.getKey();
        Object v = e.getValue();
        if (k == null || k.isBlank()) continue;
        if (v == null) continue;
        if (v instanceof String || v instanceof Number || v instanceof Boolean) {
          payload.put(k, v);
        }
      }
    }

    String payloadJson = toJsonObject(payload);

    String headerB64 = base64UrlEncode(headerJson.getBytes(StandardCharsets.UTF_8));
    String payloadB64 = base64UrlEncode(payloadJson.getBytes(StandardCharsets.UTF_8));
    String signingInput = headerB64 + "." + payloadB64;

    byte[] sigBytes = signRs256(privateKey, signingInput.getBytes(StandardCharsets.UTF_8));
    String sigB64 = base64UrlEncode(sigBytes);
    return signingInput + "." + sigB64;
  }

  private static byte[] signRs256(PrivateKey privateKey, byte[] data) {
    try {
      Signature signature = Signature.getInstance("SHA256withRSA");
      signature.initSign(privateKey);
      signature.update(data);
      return signature.sign();
    } catch (Exception e) {
      throw new RuntimeException("Failed to sign JWT with RS256", e);
    }
  }

  private static String base64UrlEncode(byte[] input) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(input);
  }

  // Minimal JSON serializer for simple map with String keys and primitive values
  private static String toJsonObject(Map<String, Object> map) {
    StringBuilder sb = new StringBuilder();
    sb.append('{');
    boolean first = true;
    for (Map.Entry<String, Object> e : map.entrySet()) {
      if (!first) sb.append(',');
      first = false;
      sb.append('"').append(escapeJson(e.getKey())).append('"').append(':');
      Object v = e.getValue();
      if (v instanceof String) {
        sb.append('"').append(escapeJson((String) v)).append('"');
      } else if (v instanceof Number || v instanceof Boolean) {
        sb.append(v.toString());
      } else if (v == null) {
        sb.append("null");
      } else {
        // Fallback to string representation
        sb.append('"').append(escapeJson(String.valueOf(v))).append('"');
      }
    }
    sb.append('}');
    return sb.toString();
  }

  private static String escapeJson(String s) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"' -> sb.append("\\\"");
        case '\\' -> sb.append("\\\\");
        case '\b' -> sb.append("\\b");
        case '\f' -> sb.append("\\f");
        case '\n' -> sb.append("\\n");
        case '\r' -> sb.append("\\r");
        case '\t' -> sb.append("\\t");
        default -> {
          if (c < 0x20) {
            sb.append(String.format("\\u%04x", (int) c));
          } else {
            sb.append(c);
          }
        }
      }
    }
    return sb.toString();
  }
}
