package com.example.gpgservice;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class GpgKeyGenerationService {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public Map<String, String> generateBankAndClientKeySet(String bankUserId, String bankPassphrase,
                                                            String clientUserId, String clientPassphrase)
            throws Exception {
        Map<String, String> result = new HashMap<>();

        KeyMaterial bank = generatePgpKeyPair(bankUserId, bankPassphrase);
        KeyMaterial client = generatePgpKeyPair(clientUserId, clientPassphrase);

        result.put("bank-public.asc", bank.publicKey);
        result.put("bank-private.asc", bank.privateKey);
        result.put("client-public.asc", client.publicKey);
        result.put("client-private.asc", client.privateKey);

        return result;
    }

    private KeyMaterial generatePgpKeyPair(String userId, String passphrase) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048);
        KeyPair kp = keyPairGenerator.generateKeyPair();

        PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, kp, new Date());

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

        PGPKeyRingGenerator keyRingGenerator = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                pgpKeyPair,
                userId,
                sha1Calc,
                null,
                null,
                new JcaPGPContentSignerBuilder(pgpKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256)
                        .setProvider("BC"),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc)
                        .setProvider("BC")
                        .build(passphrase != null ? passphrase.toCharArray() : new char[0])
        );

        PGPPublicKeyRing publicKeyRing = keyRingGenerator.generatePublicKeyRing();
        PGPSecretKeyRing secretKeyRing = keyRingGenerator.generateSecretKeyRing();

        return new KeyMaterial(toArmored(publicKeyRing), toArmored(secretKeyRing));
    }

    private String toArmored(PGPKeyRing keyRing) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(out)) {
            keyRing.encode(armoredOutputStream);
        }
        return out.toString();
    }

    private record KeyMaterial(String publicKey, String privateKey) {
    }
}
