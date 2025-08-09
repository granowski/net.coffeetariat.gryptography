package net.coffeetariat.gryptography;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

/**
 * Utility class to generate RSA key pairs.
 *
 * <p>Example usage:
 * <pre>
 *   KeyPair kp = RSAKeyPairGenerator.generate(); // default 2048 bits
 *   KeyPair kp4096 = RSAKeyPairGenerator.generate(4096);
 * </pre>
 */
public final class RSAKeyPairGenerator {

  private static final String ALGORITHM = "RSA";
  private static final int DEFAULT_KEY_SIZE = 2048;

  private RSAKeyPairGenerator() {
  }

  /**
   * Generates an RSA {@link KeyPair} with the default key size (2048 bits).
   *
   * @return a newly generated RSA key pair
   * @throws GeneralSecurityException if RSA algorithm or strong RNG is unavailable
   */
  public static KeyPair generate() throws GeneralSecurityException {
    return generate(DEFAULT_KEY_SIZE);
  }

  /**
   * Generates an RSA {@link KeyPair} with the specified key size.
   *
   * @param keySize the key size in bits (e.g., 2048, 3072, 4096)
   * @return a newly generated RSA key pair
   * @throws IllegalArgumentException if keySize is not a positive multiple of 8 or is too small
   * @throws GeneralSecurityException if RSA algorithm or strong RNG is unavailable
   */
  public static KeyPair generate(int keySize) throws GeneralSecurityException {
    if (keySize % 8 != 0)
      throw new IllegalArgumentException("RSA key size must be a multiple of 8 bits");

    KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);

    SecureRandom random = SecureRandom.getInstanceStrong();
    kpg.initialize(keySize, random);
    return kpg.generateKeyPair();
  }
}
