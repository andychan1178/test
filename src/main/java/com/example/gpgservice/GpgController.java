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
            @RequestParam(value = "publicKey", required = false) String publicKey,
            @RequestParam(value = "privateKey", required = false) String privateKey,
            @RequestParam(value = "passphrase", required = false) String passphrase
    ) throws IOException, PGPException {

        byte[] result;
        String outputName;

        if ("encrypt".equalsIgnoreCase(purpose)) {
            if (publicKey == null || publicKey.isBlank()) {
                throw new IllegalArgumentException("publicKey is required for encrypt purpose.");
            }
            result = gpgCryptoService.encrypt(file.getBytes(), publicKey);
            outputName = safeName(file.getOriginalFilename()) + ".pgp";
        } else if ("decrypt".equalsIgnoreCase(purpose)) {
            if (privateKey == null || privateKey.isBlank()) {
                throw new IllegalArgumentException("privateKey is required for decrypt purpose.");
            }
            result = gpgCryptoService.decrypt(file.getBytes(), privateKey, passphrase);
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

    private String safeName(String input) {
        return (input == null || input.isBlank()) ? "file" : input;
    }
}
