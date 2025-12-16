package net.coffeetariat.gryptography.lib;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Objects;

/**
 * Miscellaneous helper utilities for cryptography-related tasks.
 */
public final class Utilities {

  private Utilities() {
    // no instances
  }

  /**
   * Converts a {@link PublicKey} to PEM format (X.509 SubjectPublicKeyInfo) with 64-character line wrapping.
   */
  public static String toPem(PublicKey publicKey) {
    byte[] der = publicKey.getEncoded(); // X.509 SubjectPublicKeyInfo
    String base64 = Base64.getEncoder().encodeToString(der);
    StringBuilder sb = new StringBuilder();
    sb.append("-----BEGIN PUBLIC KEY-----\n");
    for (int i = 0; i < base64.length(); i += 64) {
      int end = Math.min(i + 64, base64.length());
      sb.append(base64, i, end).append('\n');
    }
    sb.append("-----END PUBLIC KEY-----\n");
    return sb.toString();
  }

  /**
   * Converts a {@link PrivateKey} to PEM format (PKCS#8) with 64-character line wrapping.
   */
  public static String toPem(PrivateKey privateKey) {
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

  /**
   * Minimal YAML single-quoted style escaping: duplicate single quotes.
   */
  public static String yamlEscape(String s) {
    if (s == null) return "";
    return s.replace("'", "''");
  }

  /**
   * Minimal JSON string escaping for quotes, backslashes, and control characters.
   */
  public static String jsonEscape(String s) {
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
}
