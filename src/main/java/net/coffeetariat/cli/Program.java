package net.coffeetariat.cli;

import net.coffeetariat.gryptography.ClientPrivateKeysYaml;

import java.nio.file.Path;
import java.security.PublicKey;
import java.util.Optional;
import java.util.UUID;

public class Program {
  public static void main(String[] args) throws Exception {
//
//    net.coffeetariat.gryptography.ClientPrivateKeysYaml cpky = new ClientPrivateKeysYaml(Path.of("clients-and-keys.yaml"));
//    cpky.load();
//    cpky.register(UUID.randomUUID().toString(), net.coffeetariat.gryptography.RSAKeyPairGenerator.generate());
//    cpky.save();
    net.coffeetariat.gryptography.ClientPrivateKeysYaml cpky = new ClientPrivateKeysYaml(Path.of("clients-and-keys.yaml"));
    cpky.load();
    Optional<PublicKey> pubk = cpky.getPublicKey("00000000-0000-0000-0000-000000000001");

    pubk.ifPresent(publicKey -> System.out.println("Public key: " + publicKey));
  }
}
