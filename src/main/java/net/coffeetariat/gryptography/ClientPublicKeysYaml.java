package net.coffeetariat.gryptography;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * YAML-backed store for clients' public keys.
 *
 * <p>The YAML file format is a simple mapping from clientId to a Base64-encoded
 * X.509 SubjectPublicKeyInfo public key (DER). This implementation assumes RSA
 * public keys for decoding (uses KeyFactory with algorithm "RSA").</p>
 *
 * <p>Example file content:</p>
 * <pre>
 * alice: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A... (base64)
 * bob:   MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A... (base64)
 * </pre>
 */
public class ClientPublicKeysYaml {

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
  public ClientPublicKeysYaml(Path yamlPath) throws IOException {
    this.yamlPath = Objects.requireNonNull(yamlPath, "yamlPath");

    DumperOptions options = new DumperOptions();
    options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
    options.setPrettyFlow(true);
    this.yaml = new Yaml(options);

    load();
  }

  /**
   * Registers a clientId with the given KeyPair: stores only the public key
   * and returns the private key to the caller.
   * If the clientId already exists, its stored public key will be overwritten.
   *
   * @return the private key corresponding to the stored public key
   */
  public synchronized PrivateKey register(String clientId, KeyPair keyPair) throws IOException {
    Objects.requireNonNull(clientId, "clientId");
    Objects.requireNonNull(keyPair, "keyPair");
    PublicKey publicKey = keyPair.getPublic();
    String base64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
    data.put(clientId, base64);
    save();
    return keyPair.getPrivate();
  }

  /**
   * Registers a clientId with a given PublicKey and persists to disk.
   * If the clientId already exists, its key will be overwritten.
   */
  public synchronized void register(String clientId, PublicKey publicKey) throws IOException {
    Objects.requireNonNull(clientId, "clientId");
    Objects.requireNonNull(publicKey, "publicKey");
    String base64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
    data.put(clientId, base64);
    save();
  }

  /** Returns the set of registered client IDs. */
  public synchronized Set<String> listClients() {
    return Collections.unmodifiableSet(data.keySet());
  }

  /**
   * Retrieves a client's RSA public key from the store.
   *
   * @return Optional.empty() if the clientId isn't registered or on error.
   */
  public synchronized Optional<PublicKey> getPublicKey(String clientId) {
    String base64 = data.get(clientId);
    if (base64 == null) return Optional.empty();
    try {
      byte[] der = Base64.getDecoder().decode(base64);
      X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
      // Assumes RSA keys for decoding
      KeyFactory kf = KeyFactory.getInstance("RSA");
      return Optional.of(kf.generatePublic(spec));
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
          if (parts.length >= 2) {
            // Join back any additional colons after the first to be safer
            String id = parts[0].trim();
            String value = line.substring(line.indexOf(':') + 1).trim();
            if (!id.isEmpty() && !value.isEmpty()) {
              data.put(id, value);
            }
          }
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
      yaml.dump(data, new OutputStreamWriter(os));
    }
  }
}
