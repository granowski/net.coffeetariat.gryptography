package net.coffeetariat.gryptography;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * YAML-backed store for clients' private keys.
 *
 * <p>The YAML file format is a simple mapping from clientId to a Base64-encoded
 * PKCS#8 (DER) private key. This implementation assumes RSA private keys
 * (decode uses KeyFactory with algorithm "RSA").</p>
 *
 * <p>Example file content:</p>
 * <pre>
 * alice: MIIEvQIBADANBgkq... (base64)
 * bob:   MIIEpgIBAAKCAQEAs... (base64)
 * </pre>
 */
public class ClientPrivateKeysYaml {

  private final Path yamlPath;
  private final Yaml yaml;
  private final Map<String, String> data = new HashMap<>();

  public class Record {
    public String id;
    public String key;
  }

  /**
   * Creates a new store for the given YAML file path. If the file exists,
   * it is loaded immediately; otherwise, the store starts empty.
   */
  public ClientPrivateKeysYaml(Path yamlPath) throws IOException {
    this.yamlPath = Objects.requireNonNull(yamlPath, "yamlPath");

    DumperOptions options = new DumperOptions();
    options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
    options.setPrettyFlow(true);
    this.yaml = new Yaml(options);
//    this.yaml = new Yaml(new Constructor(Record.class));

    // Load existing data if present
    load();
  }

  /**
   * Registers a clientId with the given PrivateKey and persists to disk.
   * If the clientId already exists, its key will be overwritten.
   */
  public synchronized void register(String clientId, PrivateKey privateKey) throws IOException {
    Objects.requireNonNull(clientId, "clientId");
    Objects.requireNonNull(privateKey, "privateKey");
    String base64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());
    data.put(clientId, base64);
    save();
  }

  /** Convenience method to register using a KeyPair (uses private part). */
  public void register(String clientId, KeyPair keyPair) throws IOException {
    Objects.requireNonNull(keyPair, "keyPair");
    register(clientId, keyPair.getPrivate());
  }

  /** Returns the set of registered client IDs. */
  public synchronized Set<String> listClients() {
    return Collections.unmodifiableSet(data.keySet());
  }

  /**
   * Retrieves a client's RSA private key from the store.
   *
   * @return Optional.empty() if the clientId isn't registered.
   */
  public synchronized Optional<PrivateKey> getPrivateKey(String clientId) {
    String base64 = data.get(clientId);
    if (base64 == null) return Optional.empty();
    try {
      byte[] der = Base64.getDecoder().decode(base64);
      PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
      // Assumes RSA keys for decoding
      KeyFactory kf = KeyFactory.getInstance("RSA");
      return Optional.of(kf.generatePrivate(spec));
    } catch (Exception e) {
      return Optional.empty();
    }
  }

  /**
   * Derives and returns a client's RSA public key from the stored private key.
   * This works when the stored private key contains CRT parameters (typical for RSA PKCS#8),
   * allowing reconstruction of the public key via modulus and public exponent.
   *
   * @param clientId the client identifier
   * @return Optional of the derived PublicKey, or Optional.empty() if unavailable or on error
   */
  public synchronized Optional<PublicKey> getPublicKey(String clientId) {
    try {
      Optional<PrivateKey> maybePriv = getPrivateKey(clientId);
      if (maybePriv.isEmpty()) return Optional.empty();
      PrivateKey priv = maybePriv.get();
      if (!(priv instanceof RSAPrivateCrtKey crt)) {
        // Cannot derive public key without CRT parameters
        return Optional.empty();
      }
      RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent());
      KeyFactory kf = KeyFactory.getInstance("RSA");
      PublicKey pub = kf.generatePublic(pubSpec);
      return Optional.of(pub);
    } catch (Exception e) {
      return Optional.empty();
    }
  }

  /** Removes a client entry and persists to disk. */
  public synchronized void remove(String clientId) throws IOException {
    if (data.remove(clientId) != null) {
      save();
    }
  }

  /** Loads the YAML file from disk into memory. Missing file is treated as empty. */
  public synchronized void load() throws IOException {
    data.clear();
    if (!Files.exists(yamlPath)) return;

    try (InputStream is = Files.newInputStream(yamlPath)) {
      try (BufferedReader br = new BufferedReader(new InputStreamReader(is))) {
        String line;
        while ((line = br.readLine()) != null) {
          String[] parts = line.split(":");
          data.put(parts[0], parts[1]);
        }
      }
    }
  }

  /** Persists the in-memory map to the YAML file, creating directories as needed. */
  public synchronized void save() throws IOException {
    if (yamlPath.getParent() != null) {
      Files.createDirectories(yamlPath.getParent());
    }
    try (OutputStream os = Files.newOutputStream(yamlPath)) {
      yaml.dump(data, new java.io.OutputStreamWriter(os));
    }
  }
}
