package net.coffeetariat.gryptography.auth;

import net.coffeetariat.gryptography.lib.ClientPublicKeysYaml;
import net.coffeetariat.gryptography.lib.ClientPrivateKeysYaml;
import org.yaml.snakeyaml.Yaml;

import javax.crypto.Cipher;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class HostOriginBoundAuthorization {
  // In-memory session store: sessionId -> clientId
  // Note: ephemeral by design; process memory only.
  private static final Map<String, String> SESSION_TO_CLIENT = new ConcurrentHashMap<>();

  /**
   * Given a ChallengeAnswer, looks up the associated clientId from the in-memory
   * session store, fetches that client's PublicKey from the provided ClientPublicKeysYaml,
   * and uses the public key to decrypt the Base64-encoded 'answer' contained in the
   * ChallengeAnswer.
   *
   * Note: This assumes the 'answer' was produced by the client using its private key in a
   * manner compatible with RSA/ECB/PKCS1Padding, allowing decryption with the public key.
   *
   * @param challengeAnswer the answer object containing sessionId and Base64-encoded answer
   * @param publicKeysYaml the public key store for resolving the client's public key
   * @return the decrypted plaintext answer as a UTF-8 string
   * @throws IllegalArgumentException if the sessionId is unknown or the client's public key is missing
   * @throws RuntimeException if decryption fails
   */
  public static String decryptAnswerWithClientPublicKey(ChallengeAnswer challengeAnswer,
                                                        ClientPublicKeysYaml publicKeysYaml) {
    Objects.requireNonNull(challengeAnswer, "challengeAnswer");
    Objects.requireNonNull(publicKeysYaml, "publicKeysYaml");

    String sessionId = challengeAnswer.sessionId;
    if (sessionId == null) {
      throw new IllegalArgumentException("ChallengeAnswer.sessionId is null");
    }

    String clientId = getClientIdForSession(sessionId);
    if (clientId == null) {
      throw new IllegalArgumentException("Unknown or expired sessionId: " + sessionId);
    }

    PublicKey publicKey = publicKeysYaml.getPublicKey(clientId)
        .orElseThrow(() -> new IllegalArgumentException("Unknown clientId or public key not found: " + clientId));

    return decryptWithPublicKeyToText(challengeAnswer.answer, publicKey);
  }

  /**
   * Creates a challenge for the given client by selecting a random question from the
   * silly-qna-jokes.yaml resource, encrypting it with the client's public key, and
   * returning it as a ChallengeInquiry. Also generates a random sessionId and stores
   * the mapping sessionId -> clientId in an in-memory lookup table.
   *
   * @param clientId the client's identifier (UUID or other unique ID)
   * @param publicKeysYaml the store used to retrieve the client's PublicKey
   * @return ChallengeInquiry containing sessionId and Base64-encoded encrypted inquiry
   */
  public static ChallengeInquiry createChallenge(String clientId, ClientPublicKeysYaml publicKeysYaml) {
    Objects.requireNonNull(clientId, "clientId");
    Objects.requireNonNull(publicKeysYaml, "publicKeysYaml");

    // 1) Load a random question from silly-qna-jokes.yaml
    String question = pickRandomQuestion();

    System.out.println("selected question -> " + question);

    // 2) Look up client's public key
    PublicKey publicKey = publicKeysYaml.getPublicKey(clientId)
        .orElseThrow(() -> new IllegalArgumentException("Unknown clientId or public key not found: " + clientId));

    // 3) Encrypt the question using RSA
    String encryptedBase64 = encryptToBase64(question, publicKey);

    // todo -> should add the answer to the in-memory session table
    // we're going to expect them to provide the right answer
    // note -> this isn't a HOBA specific thing, normally we would just
    // send a random text encrypted with their public key and the challenge
    // is they decrypt, then sign the payload and then we verify the sig.
    // By nature of them being able to decrypt and sign proves they are the
    // holder of the private key.
    // We just need to verify the signature with the public key.

    // 4) Create session id and store mapping
    String sessionId = UUID.randomUUID().toString();
    SESSION_TO_CLIENT.put(sessionId, clientId);

    // 5) Return challenge inquiry
    return new ChallengeInquiry(sessionId, encryptedBase64);
  }

  /** Returns the clientId associated with a given sessionId, or null if not present. */
  public static String getClientIdForSession(String sessionId) {
    return SESSION_TO_CLIENT.get(sessionId);
  }

  // todo -> need to review, this looks very questionable with the wild card types and etc.
  private static String pickRandomQuestion() {
    try (InputStream is = HostOriginBoundAuthorization.class.getClassLoader()
        .getResourceAsStream("silly-qna-jokes.yaml")) {
      if (is == null) {
        throw new IllegalStateException("Resource silly-qna-jokes.yaml not found on classpath");
      }
      Yaml yaml = new Yaml();
      Object obj = yaml.load(is);
      if (!(obj instanceof Map)) {
        throw new IllegalStateException("Invalid YAML format: expected a map root");
      }
      Map<?, ?> root = (Map<?, ?>) obj;
      Object jokesObj = root.get("jokes");
      if (!(jokesObj instanceof List)) {
        throw new IllegalStateException("Invalid YAML: 'jokes' list not found");
      }
      List<?> jokes = (List<?>) jokesObj;
      if (jokes.isEmpty()) {
        throw new IllegalStateException("No jokes found in YAML");
      }
      Random rnd = new Random();
      Object pick = jokes.get(rnd.nextInt(jokes.size()));
      if (!(pick instanceof Map)) {
        throw new IllegalStateException("Invalid joke entry format");
      }
      Map<?, ?> entry = (Map<?, ?>) pick;
      Object q = entry.get("question");
      if (q == null) {
        throw new IllegalStateException("Joke missing 'question'");
      }
      return String.valueOf(q);
    } catch (Exception e) {
      throw new RuntimeException("Failed to load random question from YAML", e);
    }
  }

  private static String encryptToBase64(String plaintext, PublicKey publicKey) {
    try {
      // Prefer OAEP if available; fall back to PKCS1
      Cipher cipher;
      cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
//      try {
//        cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
//      } catch (Exception ignored) {
//        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//      }
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(ct);
    } catch (Exception e) {
      throw new RuntimeException("Failed to encrypt challenge", e);
    }
  }

  /**
   * Decrypts a Base64-encoded RSA ciphertext into UTF-8 text using the provided private key.
   * This tries OAEP with SHA-256 first (to match the preferred encryption mode),
   * and falls back to PKCS#1 v1.5 padding if OAEP is unavailable or decryption fails.
   *
   * @param encryptedText Base64-encoded ciphertext
   * @param privateKey the RSA private key corresponding to the public key used for encryption
   * @return the decrypted plaintext as a UTF-8 String
   * @throws RuntimeException if decryption fails for any reason
   */
  public static String decryptToText(String encryptedText, PrivateKey privateKey) {
    Objects.requireNonNull(encryptedText, "encryptedText");
    Objects.requireNonNull(privateKey, "privateKey");
    byte[] ciphertext = Base64.getDecoder().decode(encryptedText);

    // Try OAEP first
    try {
      Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
      cipher.init(Cipher.DECRYPT_MODE, privateKey);
      byte[] pt = cipher.doFinal(ciphertext);
      return new String(pt, StandardCharsets.UTF_8);
    } catch (Exception oaepFailure) {
      // Fallback to PKCS1
      try {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] pt = cipher.doFinal(ciphertext);
        return new String(pt, StandardCharsets.UTF_8);
      } catch (Exception pkcsFailure) {
        RuntimeException ex = new RuntimeException("Failed to decrypt text with either OAEP(SHA-256) or PKCS1 padding", pkcsFailure);
        ex.addSuppressed(oaepFailure);
        throw ex;
      }
    }
  }

  /**
   * Decrypts a Base64-encoded RSA ciphertext using a public key. This is only
   * applicable when the counterpart operation used the private key (e.g., raw
   * RSA with PKCS#1 padding), which is not the same as an RSASSA signature.
   *
   * For safety and interoperability, we try PKCS1 padding first, which is the
   * only practical mode for public-key decryption. OAEP is not applicable for
   * public-key decryption because OAEP is defined for public-key encryption
   * and private-key decryption.
   */
  public static String decryptWithPublicKeyToText(String encryptedText, PublicKey publicKey) {
    Objects.requireNonNull(encryptedText, "encryptedText");
    Objects.requireNonNull(publicKey, "publicKey");
    byte[] ciphertext = Base64.getDecoder().decode(encryptedText);
    try {
      Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      cipher.init(Cipher.DECRYPT_MODE, publicKey);
      byte[] pt = cipher.doFinal(ciphertext);
      return new String(pt, StandardCharsets.UTF_8);
    } catch (Exception e) {
      throw new RuntimeException("Failed to decrypt text with public key (PKCS1)", e);
    }
  }

  /**
   * Returns a defensive copy of the current sessionId -> clientId mappings.
   * Because keys and values are Strings (immutable), copying the entries
   * constitutes a deep copy for practical purposes.
   */
  public static Map<String, String> listSessionsAndClientIds() {
    return new HashMap<>(SESSION_TO_CLIENT);
  }

  /**
   * Creates a "signature" string for the provided text using the client's public key.
   *
   * <p>Important: In standard cryptography, a signature is created with a private key and
   * verified with a public key (e.g., via RSASSA). This helper instead uses the client's
   * public key to produce a Base64-encoded RSA ciphertext of the input text, which can serve
   * as a public-key-encrypted token in flows where the counterpart will decrypt it with the
   * private key. It does not produce an RSASSA signature.</p>
   *
   * @param clientId the client's identifier whose public key will be used
   * @param text the plaintext to transform
   * @param publicKeysYaml the store used to resolve the client's public key
   * @return Base64-encoded RSA ciphertext of the text using the client's public key
   * @throws IllegalArgumentException if the clientId is unknown or the key cannot be found
   * @throws RuntimeException if the encryption fails
   */
  public static String createSignatureForText(String clientId,
                                              String text,
                                              ClientPublicKeysYaml publicKeysYaml) {
    Objects.requireNonNull(clientId, "clientId");
    Objects.requireNonNull(text, "text");
    Objects.requireNonNull(publicKeysYaml, "publicKeysYaml");

    PublicKey publicKey = publicKeysYaml.getPublicKey(clientId)
        .orElseThrow(() -> new IllegalArgumentException("Unknown clientId or public key not found: " + clientId));

    return encryptToBase64(text, publicKey);
  }

  // todo -> Need to verify that this works. Looks right...
  /**
   * Verifies a Base64-encoded RSA signature over the provided UTF-8 text using the
   * client's registered public key from the provided ClientPublicKeysYaml store.
   *
   * <p>This uses the algorithm SHA256withRSA. If the clientId isn't registered,
   * this method throws IllegalArgumentException. Any internal error during
   * verification (e.g., malformed signature) results in a false return.</p>
   *
   * @param clientId the client's identifier
   * @param text the original plaintext that was signed (UTF-8)
   * @param signatureBase64 the signature bytes encoded as Base64
   * @param publicKeysYaml the public key store to look up the client's key
   * @return true if the signature is valid for the given text and client; false otherwise
   * @throws IllegalArgumentException if the clientId is unknown or key retrieval fails
   */
  public static boolean verifySignedText(String clientId,
                                         String text,
                                         String signatureBase64,
                                         ClientPublicKeysYaml publicKeysYaml) {
    Objects.requireNonNull(clientId, "clientId");
    Objects.requireNonNull(text, "text");
    Objects.requireNonNull(signatureBase64, "signatureBase64");
    Objects.requireNonNull(publicKeysYaml, "publicKeysYaml");

    PublicKey publicKey = publicKeysYaml.getPublicKey(clientId)
        .orElseThrow(() -> new IllegalArgumentException("Unknown clientId or public key not found: " + clientId));

    return verifySignedText(text, signatureBase64, publicKey);
  }

  /**
   * Verifies a Base64-encoded RSA signature over the provided UTF-8 text using the
   * provided PublicKey. Uses SHA256withRSA algorithm.
   */
  public static boolean verifySignedText(String text, String signatureBase64, PublicKey publicKey) {
    Objects.requireNonNull(text, "text");
    Objects.requireNonNull(signatureBase64, "signatureBase64");
    Objects.requireNonNull(publicKey, "publicKey");
    try {
      byte[] sigBytes = Base64.getDecoder().decode(signatureBase64);
      Signature sig = Signature.getInstance("SHA256withRSA");
      sig.initVerify(publicKey);
      sig.update(text.getBytes(StandardCharsets.UTF_8));
      return sig.verify(sigBytes);
    } catch (Exception e) {
      return false;
    }
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
