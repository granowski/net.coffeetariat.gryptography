package net.coffeetariat.gryptography.auth;

import net.coffeetariat.gryptography.lib.ClientPublicKeysYaml;
import net.coffeetariat.gryptography.lib.ClientPrivateKeysYaml;
import org.yaml.snakeyaml.Yaml;

import javax.crypto.Cipher;
import java.io.InputStream;
import java.net.URLEncoder;
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
  // In-memory expected answer store: sessionId -> expectedAnswer
  private static final Map<String, String> SESSION_TO_EXPECTED_ANSWER = new ConcurrentHashMap<>();

  /**
   * Decrypts the Base64-encoded answer in the provided ChallengeAnswer using the
   * given client's PrivateKey and returns the plaintext as UTF-8 text.
   *
   * @param challengeAnswer the answer object containing Base64 ciphertext
   * @param privateKeys the client private keys used for decryption
   * @return plaintext answer
   * @throws NullPointerException if any argument is null
   * @throws RuntimeException if decryption fails
   */
  public static String decryptAnswerWithClientPrivateKey(ChallengeAnswer challengeAnswer,
                                                         ClientPrivateKeysYaml privateKeys) {
    Objects.requireNonNull(challengeAnswer, "challengeAnswer");
    Objects.requireNonNull(privateKeys, "privateKey");

    String sessionId = challengeAnswer.sessionId;
    if (sessionId == null) {
      throw new IllegalArgumentException("ChallengeAnswer.sessionId is null");
    }

    String clientId = getClientIdForSession(sessionId);
    if (clientId == null) {
      throw new IllegalArgumentException("Unknown or expired sessionId: " + sessionId);
    }

    PrivateKey privateKey = privateKeys.getPrivateKey(clientId).orElseThrow(() -> new IllegalArgumentException(("Unknown clientId or private key not found: " + clientId)));
    return decryptToText(challengeAnswer.answer, privateKey);
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

    // 1) Load a random Q&A pair from silly-qna-jokes.yaml
    QA selected = pickRandomQA();
    String question = selected.question();

    //System.out.println("selected question -> " + question);

    // 2) Look up client's public key
    PublicKey publicKey = publicKeysYaml.getPublicKey(clientId)
        .orElseThrow(() -> new IllegalArgumentException("Unknown clientId or public key not found: " + clientId));

    // 3) Encrypt the question using RSA
    String encryptedBase64 = encryptToBase64(question, publicKey);
    String encyptedAnswerBase64 = encryptToBase64(selected.answer(), publicKey);

    //System.out.println("expected encrypted answer will be -> " + URLEncoder.encode(encyptedAnswerBase64, StandardCharsets.UTF_8));

    // 4) Create session id and store mapping and expected answer
    String sessionId = UUID.randomUUID().toString();
    SESSION_TO_CLIENT.put(sessionId, clientId);
    SESSION_TO_EXPECTED_ANSWER.put(sessionId, selected.answer());

    // 5) Return challenge inquiry
    return new ChallengeInquiry(sessionId, encryptedBase64);
  }

  /** Returns the clientId associated with a given sessionId, or null if not present. */
  public static String getClientIdForSession(String sessionId) {
    return SESSION_TO_CLIENT.get(sessionId);
  }

  /** Verifies a supplied plaintext answer for the session; on success, invalidates the session. */
  public static boolean verifyAndConsumeAnswer(String sessionId, String plaintextAnswer) {
    if (sessionId == null) return false;
    String expected = SESSION_TO_EXPECTED_ANSWER.get(sessionId);
    if (expected == null) return false;
    boolean ok = Objects.equals(expected, plaintextAnswer);
    if (ok) {
      // Invalidate session state to prevent replay
      SESSION_TO_EXPECTED_ANSWER.remove(sessionId);
      SESSION_TO_CLIENT.remove(sessionId);
    }
    return ok;
  }

  // Load a random QA pair
  private static QA pickRandomQA() {
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
      Object a = entry.get("answer");
      if (q == null) {
        throw new IllegalStateException("Joke missing 'question'");
      }
      if (a == null) {
        throw new IllegalStateException("Joke missing 'answer'");
      }
      return new QA(String.valueOf(q), String.valueOf(a));
    } catch (Exception e) {
      throw new RuntimeException("Failed to load random QA from YAML", e);
    }
  }

  // Simple record to hold a QA pair
  private record QA(String question, String answer) {}

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
   * Returns a defensive copy of the current sessionId -> clientId mappings.
   * Because keys and values are Strings (immutable), copying the entries
   * constitutes a deep copy for practical purposes.
   */
  public static Map<String, String> listSessionsAndClientIds() {
    return new HashMap<>(SESSION_TO_CLIENT);
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

  /**
   * Creates a Base64-encoded RSASSA-PKCS1-v1_5 (SHA256withRSA) signature over the provided text.
   * The text is encoded as UTF-8 prior to signing.
   *
   * @param privateKey the RSA private key to sign with
   * @param text the plaintext to sign (UTF-8)
   * @return the signature bytes encoded as Base64
   * @throws NullPointerException if any argument is null
   * @throws RuntimeException if signing fails for any reason
   */
  public static String createSignatureForText(PrivateKey privateKey, String text) {
    Objects.requireNonNull(privateKey, "privateKey");
    Objects.requireNonNull(text, "text");
    byte[] data = text.getBytes(StandardCharsets.UTF_8);
    byte[] sig = signRs256(privateKey, data);
    return Base64.getEncoder().encodeToString(sig);
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
}
