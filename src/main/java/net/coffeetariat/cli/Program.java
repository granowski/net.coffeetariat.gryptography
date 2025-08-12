package net.coffeetariat.cli;

import net.coffeetariat.gryptography.auth.ChallengeInquiry;
import net.coffeetariat.gryptography.auth.HostOriginBoundAuthorization;
import net.coffeetariat.gryptography.lib.ClientPrivateKeysYaml;
import net.coffeetariat.gryptography.lib.ClientPublicKeysYaml;
import net.coffeetariat.gryptography.lib.RSAKeyPairGenerator;

import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.UUID;

public class Program {
  public static void main(String[] args) throws Exception {
//
//    net.coffeetariat.gryptography.ClientPrivateKeysYaml cpky = new ClientPrivateKeysYaml(Path.of("clients-and-keys.yaml"));
//    cpky.load();
//    cpky.register(UUID.randomUUID().toString(), net.coffeetariat.gryptography.RSAKeyPairGenerator.generate());
//    cpky.save();
//    net.coffeetariat.gryptography.ClientPrivateKeysYaml cpky = new ClientPrivateKeysYaml(Path.of("clients-and-keys.yaml"));
//    cpky.load();
//    Optional<PublicKey> pubk = cpky.getPublicKey("00000000-0000-0000-0000-000000000001");
//
//    pubk.ifPresent(publicKey -> System.out.println("Public key: " + publicKey));
//
//    var newId = UUID.randomUUID().toString();    ClientPublicKeysYaml cpky = new ClientPublicKeysYaml(Path.of("clients-and-public-keys.yaml"));
//    PrivateKey privKey = cpky.register(newId, RSAKeyPairGenerator.generate());
//
//    ClientPrivateKeysYaml cprivky = new  ClientPrivateKeysYaml(Path.of("clients-and-private-keys.yaml"));
//    cprivky.load();
//    cprivky.register(newId, privKey);
//    cprivky.save();

//    for (int i = 0; i < 7; i++) {
//      String randomClientId = UUID.randomUUID().toString();
//      ClientPublicKeysYaml cpky = new ClientPublicKeysYaml(Path.of("temp-pub-keys.yaml"));
//      cpky.register(randomClientId, RSAKeyPairGenerator.generate().getPublic());
//
//      ChallengeInquiry challenge = HostOriginBoundAuthorization.createChallenge(randomClientId, cpky);
//
//      challenge.debugPrint();
//    }
//
//    var result = HostOriginBoundAuthorization.listSessionsAndClientIds();
//    for  (var entry : result.entrySet()) {
//      System.out.println(entry.getKey() + " -> " + entry.getValue());
//    }

    var tok = HostOriginBoundAuthorization.generateJwtToken(
        RSAKeyPairGenerator.generate().getPrivate(),
        "Derrick Granowski",
        "grypto-api-v0.01",
        "everyone",
        600,
        null
    );

    System.out.println(tok.toString());
  }
}
