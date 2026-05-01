package com.example.gpgservice;

import org.bouncycastle.openpgp.PGPException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/api/gpg")
public class GpgController {

    private final GpgCryptoService gpgCryptoService;

    public GpgController(GpgCryptoService gpgCryptoService) {
        this.gpgCryptoService = gpgCryptoService;
    }

    @PostMapping(value = "/process", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<byte[]> processFile(
            @RequestParam("purpose") String purpose,
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "encryptionPublicKey", required = false) MultipartFile encryptionPublicKey,
            @RequestParam(value = "signingPrivateKey", required = false) MultipartFile signingPrivateKey,
            @RequestParam(value = "signingPublicKey", required = false) MultipartFile signingPublicKey,
            @RequestParam(value = "decryptionPrivateKey", required = false) MultipartFile decryptionPrivateKey,
            @RequestParam(value = "passphrase", required = false) String passphrase
    ) throws IOException, PGPException {

        byte[] result;
        String outputName;

        if ("encrypt".equalsIgnoreCase(purpose)) {
            requireFile(encryptionPublicKey, "encryptionPublicKey");
            requireFile(signingPrivateKey, "signingPrivateKey");
            result = gpgCryptoService.encryptAndSign(
                    file.getBytes(),
                    encryptionPublicKey.getBytes(),
                    signingPrivateKey.getBytes(),
                    passphrase
            );
            outputName = safeName(file.getOriginalFilename()) + ".pgp";
        } else if ("decrypt".equalsIgnoreCase(purpose)) {
            requireFile(decryptionPrivateKey, "decryptionPrivateKey");
            requireFile(signingPublicKey, "signingPublicKey");
            result = gpgCryptoService.decryptAndVerify(
                    file.getBytes(),
                    decryptionPrivateKey.getBytes(),
                    signingPublicKey.getBytes(),
                    passphrase
            );
            outputName = "decrypted-" + safeName(file.getOriginalFilename());
        } else {
            throw new IllegalArgumentException("purpose must be encrypt or decrypt.");
        }

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + outputName + "\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(result);
    }

    @ExceptionHandler({IllegalArgumentException.class, PGPException.class, IOException.class})
    public ResponseEntity<String> handleException(Exception ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
    }

    private void requireFile(MultipartFile file, String name) {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException(name + " is required.");
        }
    }

    private String safeName(String input) {
        return (input == null || input.isBlank()) ? "file" : input;
    }
}
