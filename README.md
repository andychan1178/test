# GPG File Service (Spring Boot)

This service accepts file uploads for GPG operations and processes them based on `purpose` (`encrypt` or `decrypt`).

## Run

```bash
mvn spring-boot:run
```

## API

`POST /api/gpg/process` (multipart/form-data)

### Encrypt (encrypt + sign)
Required fields:
- `purpose=encrypt`
- `file`: plaintext file
- `encryptionPublicKey`: recipient public key file (`.asc`)
- `signingPrivateKey`: sender private key file (`.asc`)
- `passphrase`: optional private key passphrase

### Decrypt (decrypt + verify signature)
Required fields:
- `purpose=decrypt`
- `file`: encrypted `.pgp` file
- `decryptionPrivateKey`: recipient private key file (`.asc`)
- `signingPublicKey`: sender public key file (`.asc`) for signature verification
- `passphrase`: optional private key passphrase

## cURL examples

Encrypt and sign:
```bash
curl -X POST http://localhost:8080/api/gpg/process \
  -F "purpose=encrypt" \
  -F "file=@plain.txt" \
  -F "encryptionPublicKey=@recipient-public.asc" \
  -F "signingPrivateKey=@sender-private.asc" \
  -F "passphrase=your-passphrase" \
  --output plain.txt.pgp
```

Decrypt and verify:
```bash
curl -X POST http://localhost:8080/api/gpg/process \
  -F "purpose=decrypt" \
  -F "file=@plain.txt.pgp" \
  -F "decryptionPrivateKey=@recipient-private.asc" \
  -F "signingPublicKey=@sender-public.asc" \
  -F "passphrase=your-passphrase" \
  --output plain.txt
```
