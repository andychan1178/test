package com.example.gpgservice;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;

@Service
public class GpgCryptoService {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public byte[] encrypt(byte[] inputData, String publicKeyAscii) throws IOException, PGPException {
        PGPPublicKey encryptionKey = readPublicKey(publicKeyAscii);

        ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
        try (ArmoredOutputStream armoredOut = new ArmoredOutputStream(encryptedOut)) {
            PGPEncryptedDataGenerator generator = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                            .setWithIntegrityPacket(true)
                            .setSecureRandom(new SecureRandom())
                            .setProvider("BC")
            );
            generator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey).setProvider("BC"));

            try (ByteArrayOutputStream literalDataOut = new ByteArrayOutputStream()) {
                PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
                try (var pOut = literalDataGenerator.open(literalDataOut, PGPLiteralData.BINARY,
                        PGPLiteralData.CONSOLE, inputData.length, new Date())) {
                    pOut.write(inputData);
                }

                byte[] literalBytes = literalDataOut.toByteArray();
                try (var cOut = generator.open(armoredOut, literalBytes.length)) {
                    cOut.write(literalBytes);
                }
            }
        }
        return encryptedOut.toByteArray();
    }

    public byte[] decrypt(byte[] encryptedData, String privateKeyAscii, String passphrase) throws IOException, PGPException {
        PGPSecretKeyRingCollection secretKeyRings = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(new ByteArrayInputStream(privateKeyAscii.getBytes())),
                new JcaKeyFingerprintCalculator()
        );

        InputStream decoderStream = PGPUtil.getDecoderStream(new ByteArrayInputStream(encryptedData));
        PGPObjectFactory pgpFactory = new PGPObjectFactory(decoderStream, new JcaKeyFingerprintCalculator());

        Object obj = pgpFactory.nextObject();
        PGPEncryptedDataList encryptedDataList;
        if (obj instanceof PGPEncryptedDataList list) {
            encryptedDataList = list;
        } else {
            encryptedDataList = (PGPEncryptedDataList) pgpFactory.nextObject();
        }

        PGPPrivateKey privateKey = null;
        PGPPublicKeyEncryptedData encryptedSessionData = null;

        Iterator<?> it = encryptedDataList.getEncryptedDataObjects();
        while (it.hasNext()) {
            PGPPublicKeyEncryptedData pked = (PGPPublicKeyEncryptedData) it.next();
            PGPSecretKey secretKey = findSecretKey(secretKeyRings, pked.getKeyID());
            if (secretKey != null) {
                privateKey = secretKey.extractPrivateKey(
                        new JcePBESecretKeyDecryptorBuilder().setProvider("BC")
                                .build(passphrase != null ? passphrase.toCharArray() : new char[0])
                );
                encryptedSessionData = pked;
                break;
            }
        }

        if (privateKey == null || encryptedSessionData == null) {
            throw new PGPException("No matching private key found for encrypted file.");
        }

        PublicKeyDataDecryptorFactory decryptorFactory =
                new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey);

        PGPObjectFactory clearFactory = new PGPObjectFactory(
                encryptedSessionData.getDataStream(decryptorFactory),
                new JcaKeyFingerprintCalculator()
        );

        Object message = clearFactory.nextObject();
        if (message instanceof PGPCompressedData compressedData) {
            clearFactory = new PGPObjectFactory(compressedData.getDataStream(), new JcaKeyFingerprintCalculator());
            message = clearFactory.nextObject();
        }

        if (!(message instanceof PGPLiteralData literalData)) {
            throw new PGPException("Decrypted content is not literal data.");
        }

        try (InputStream literalIn = literalData.getInputStream();
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            literalIn.transferTo(out);
            return out.toByteArray();
        }
    }

    private PGPPublicKey readPublicKey(String armoredPublicKey) throws IOException, PGPException {
        PGPPublicKeyRingCollection keyRings = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(new ByteArrayInputStream(armoredPublicKey.getBytes())),
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
        throw new PGPException("No encryption key found in provided public key.");
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
