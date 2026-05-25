package com.example.gpgservice;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.springframework.stereotype.Service;

import java.io.*;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

@Service
public class GpgCryptoService {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public byte[] encryptAndSign(byte[] inputData, byte[] encryptionPublicKeyData, byte[] signingPrivateKeyData,
                                 String passphrase) throws IOException, PGPException {
        PGPPublicKey encryptionKey = readEncryptionPublicKey(encryptionPublicKeyData);
        PGPSecretKey signingSecretKey = readSigningSecretKey(signingPrivateKeyData);
        PGPPrivateKey signingPrivateKey = signingSecretKey.extractPrivateKey(
                new JcePBESecretKeyDecryptorBuilder().setProvider("BC")
                        .build(passphrase != null ? passphrase.toCharArray() : new char[0])
        );

        ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
        try (ArmoredOutputStream armoredOut = new ArmoredOutputStream(encryptedOut)) {
            PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                            .setWithIntegrityPacket(true)
                            .setSecureRandom(new SecureRandom())
                            .setProvider("BC")
            );
            encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey).setProvider("BC"));

            try (OutputStream encryptedStream = encryptedDataGenerator.open(armoredOut, new byte[1 << 16])) {
                PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
                try (OutputStream compressedOut = compressedDataGenerator.open(encryptedStream)) {
                    PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                            new JcaPGPContentSignerBuilder(
                                    signingSecretKey.getPublicKey().getAlgorithm(),
                                    HashAlgorithmTags.SHA256
                            ).setProvider("BC")
                    );
                    signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, signingPrivateKey);

                    Iterator<String> userIds = signingSecretKey.getPublicKey().getUserIDs();
                    if (userIds.hasNext()) {
                        PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
                        spGen.setSignerUserID(false, userIds.next());
                        signatureGenerator.setHashedSubpackets(spGen.generate());
                    }

                    signatureGenerator.generateOnePassVersion(false).encode(compressedOut);

                    PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
                    try (OutputStream literalOut = literalDataGenerator.open(compressedOut, PGPLiteralData.BINARY,
                            PGPLiteralData.CONSOLE, inputData.length, new Date())) {
                        literalOut.write(inputData);
                        signatureGenerator.update(inputData);
                    }

                    signatureGenerator.generate().encode(compressedOut);
                }
            }
        }
        return encryptedOut.toByteArray();
    }

    public byte[] decryptAndVerify(byte[] encryptedData, byte[] decryptionPrivateKeyData, byte[] signingPublicKeyData,
                                   String passphrase) throws IOException, PGPException {
        PGPPrivateKey decryptionPrivateKey = readDecryptionPrivateKey(decryptionPrivateKeyData, encryptedData, passphrase);
        PGPPublicKey signingPublicKey = readSigningPublicKey(signingPublicKeyData);

        InputStream decoderStream = PGPUtil.getDecoderStream(new ByteArrayInputStream(encryptedData));
        PGPObjectFactory pgpFactory = new PGPObjectFactory(decoderStream, new JcaKeyFingerprintCalculator());

        Object obj = pgpFactory.nextObject();
        PGPEncryptedDataList encryptedDataList = (obj instanceof PGPEncryptedDataList list)
                ? list : (PGPEncryptedDataList) pgpFactory.nextObject();

        PGPPublicKeyEncryptedData pked = null;
        Iterator<?> encObjects = encryptedDataList.getEncryptedDataObjects();
        while (encObjects.hasNext()) {
            PGPPublicKeyEncryptedData candidate = (PGPPublicKeyEncryptedData) encObjects.next();
            pked = candidate;
            break;
        }
        if (pked == null) {
            throw new PGPException("No encrypted data found.");
        }

        PublicKeyDataDecryptorFactory decryptorFactory =
                new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(decryptionPrivateKey);

        PGPObjectFactory plainFact = new PGPObjectFactory(pked.getDataStream(decryptorFactory), new JcaKeyFingerprintCalculator());
        PGPCompressedData compressedData = (PGPCompressedData) plainFact.nextObject();
        PGPObjectFactory compressedFactory = new PGPObjectFactory(compressedData.getDataStream(), new JcaKeyFingerprintCalculator());

        PGPOnePassSignatureList onePassList = (PGPOnePassSignatureList) compressedFactory.nextObject();
        PGPOnePassSignature onePassSignature = onePassList.get(0);
        onePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), signingPublicKey);

        PGPLiteralData literalData = (PGPLiteralData) compressedFactory.nextObject();
        ByteArrayOutputStream contentOut = new ByteArrayOutputStream();
        try (InputStream literalIn = literalData.getInputStream()) {
            int ch;
            while ((ch = literalIn.read()) >= 0) {
                onePassSignature.update((byte) ch);
                contentOut.write(ch);
            }
        }

        PGPSignatureList signatureList = (PGPSignatureList) compressedFactory.nextObject();
        boolean verified = onePassSignature.verify(signatureList.get(0));
        if (!verified) {
            throw new PGPException("Signature verification failed.");
        }

        if (pked.isIntegrityProtected() && !pked.verify()) {
            throw new PGPException("Integrity check failed.");
        }

        return contentOut.toByteArray();
    }

    private PGPPublicKey readEncryptionPublicKey(byte[] armoredPublicKey) throws IOException, PGPException {
        PGPPublicKeyRingCollection keyRings = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(new ByteArrayInputStream(armoredPublicKey)),
                new JcaKeyFingerprintCalculator()
        );
        Iterator<PGPPublicKeyRing> ringIterator = keyRings.getKeyRings();
        while (ringIterator.hasNext()) {
            PGPPublicKeyRing ring = ringIterator.next();
            Iterator<PGPPublicKey> keyIterator = ring.getPublicKeys();
            while (keyIterator.hasNext()) {
                PGPPublicKey key = keyIterator.next();
                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }
        throw new PGPException("No encryption key found.");
    }

    private PGPSecretKey readSigningSecretKey(byte[] armoredPrivateKey) throws IOException, PGPException {
        PGPSecretKeyRingCollection keyRings = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(new ByteArrayInputStream(armoredPrivateKey)),
                new JcaKeyFingerprintCalculator()
        );
        Iterator<PGPSecretKeyRing> ringIterator = keyRings.getKeyRings();
        while (ringIterator.hasNext()) {
            PGPSecretKeyRing ring = ringIterator.next();
            Iterator<PGPSecretKey> keyIterator = ring.getSecretKeys();
            while (keyIterator.hasNext()) {
                PGPSecretKey key = keyIterator.next();
                if (key.isSigningKey()) {
                    return key;
                }
            }
        }
        throw new PGPException("No signing key found in private key file.");
    }

    private PGPPublicKey readSigningPublicKey(byte[] armoredPublicKey) throws IOException, PGPException {
        PGPPublicKeyRingCollection keyRings = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(new ByteArrayInputStream(armoredPublicKey)),
                new JcaKeyFingerprintCalculator()
        );
        Iterator<PGPPublicKeyRing> ringIterator = keyRings.getKeyRings();
        while (ringIterator.hasNext()) {
            PGPPublicKeyRing ring = ringIterator.next();
            Iterator<PGPPublicKey> keyIterator = ring.getPublicKeys();
            while (keyIterator.hasNext()) {
                PGPPublicKey key = keyIterator.next();
                if (key.isMasterKey() || key.isEncryptionKey()) {
                    return key;
                }
            }
        }
        throw new PGPException("No public verification key found.");
    }

    private PGPPrivateKey readDecryptionPrivateKey(byte[] armoredPrivateKey, byte[] encryptedData,
                                                    String passphrase) throws IOException, PGPException {
        PGPSecretKeyRingCollection secretKeyRings = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(new ByteArrayInputStream(armoredPrivateKey)),
                new JcaKeyFingerprintCalculator()
        );
        InputStream decoderStream = PGPUtil.getDecoderStream(new ByteArrayInputStream(encryptedData));
        PGPObjectFactory pgpFactory = new PGPObjectFactory(decoderStream, new JcaKeyFingerprintCalculator());
        Object obj = pgpFactory.nextObject();
        PGPEncryptedDataList encryptedDataList = (obj instanceof PGPEncryptedDataList list)
                ? list : (PGPEncryptedDataList) pgpFactory.nextObject();

        Iterator<?> it = encryptedDataList.getEncryptedDataObjects();
        while (it.hasNext()) {
            PGPPublicKeyEncryptedData pked = (PGPPublicKeyEncryptedData) it.next();
            PGPSecretKey secretKey = findSecretKey(secretKeyRings, pked.getKeyID());
            if (secretKey != null) {
                return secretKey.extractPrivateKey(
                        new JcePBESecretKeyDecryptorBuilder().setProvider("BC")
                                .build(passphrase != null ? passphrase.toCharArray() : new char[0])
                );
            }
        }
        throw new PGPException("No matching private decryption key found.");
    }

    private PGPSecretKey findSecretKey(PGPSecretKeyRingCollection keyRings, long keyId) throws PGPException {
        Iterator<PGPSecretKeyRing> ringIterator = keyRings.getKeyRings();
        while (ringIterator.hasNext()) {
            PGPSecretKeyRing ring = ringIterator.next();
            PGPSecretKey key = ring.getSecretKey(keyId);
            if (key != null) {
                return key;
            }
        }
        return null;
    }
}
