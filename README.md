# GPG File Service (Spring Boot)

This service accepts file uploads for GPG operations and processes them based on `purpose` (`encrypt` or `decrypt`).

## Run

```bash
mvn spring-boot:run
```

## APIs

### 1) Generate PGP key sets (BANK + CLIENT)

`POST /api/gpg/generate-keys`

Optional form/query params:
- `bankUserId` (default: `Bank <bank@example.com>`)
- `bankPassphrase` (default: empty)
- `clientUserId` (default: `Client <client@example.com>`)
- `clientPassphrase` (default: empty)

Returns: `pgp-keyset.zip` containing:
- `bank-public.asc`
- `bank-private.asc`
- `client-public.asc`
- `client-private.asc`

### 2) Process file

`POST /api/gpg/process` (multipart/form-data)

#### Encrypt (encrypt + sign)
Required fields:
- `purpose=encrypt`
- `file`: plaintext file
- `encryptionPublicKey`: recipient public key file (`.asc`)
- `signingPrivateKey`: sender private key file (`.asc`)
- `passphrase`: optional private key passphrase

#### Decrypt (decrypt + verify signature)
Required fields:
- `purpose=decrypt`
- `file`: encrypted `.pgp` file
- `decryptionPrivateKey`: recipient private key file (`.asc`)
- `signingPublicKey`: sender public key file (`.asc`) for signature verification
- `passphrase`: optional private key passphrase

## All cURL commands

### Health/quick check (invalid request expected, should return 400)
```bash
curl -i -X POST http://localhost:8080/api/gpg/process
```

### Generate BANK + CLIENT keys (defaults)
```bash
curl -X POST "http://localhost:8080/api/gpg/generate-keys" \
  --output pgp-keyset.zip
```

### Generate BANK + CLIENT keys (custom user IDs)
```bash
curl -X POST "http://localhost:8080/api/gpg/generate-keys" \
  -F "bankUserId=Bank Ops <bankops@bank.com>" \
  -F "clientUserId=Client App <client@app.com>" \
  --output pgp-keyset-custom.zip
```

### Generate BANK + CLIENT keys (with passphrases)
```bash
curl -X POST "http://localhost:8080/api/gpg/generate-keys" \
  -F "bankPassphrase=bank-secret" \
  -F "clientPassphrase=client-secret" \
  --output pgp-keyset-passphrase.zip
```

### Encrypt + Sign file
```bash
curl -X POST http://localhost:8080/api/gpg/process \
  -F "purpose=encrypt" \
  -F "file=@plain.txt" \
  -F "encryptionPublicKey=@test-keys/recipient-public.asc" \
  -F "signingPrivateKey=@test-keys/sender-private.asc" \
  --output plain.txt.pgp
```

### Encrypt + Sign file (with signing key passphrase)
```bash
curl -X POST http://localhost:8080/api/gpg/process \
  -F "purpose=encrypt" \
  -F "file=@plain.txt" \
  -F "encryptionPublicKey=@bank-public.asc" \
  -F "signingPrivateKey=@client-private.asc" \
  -F "passphrase=client-secret" \
  --output plain.txt.pgp
```

### Decrypt + Verify file
```bash
curl -X POST http://localhost:8080/api/gpg/process \
  -F "purpose=decrypt" \
  -F "file=@plain.txt.pgp" \
  -F "decryptionPrivateKey=@test-keys/recipient-private.asc" \
  -F "signingPublicKey=@test-keys/sender-public.asc" \
  --output plain.txt
```

### Decrypt + Verify file (with decryption key passphrase)
```bash
curl -X POST http://localhost:8080/api/gpg/process \
  -F "purpose=decrypt" \
  -F "file=@plain.txt.pgp" \
  -F "decryptionPrivateKey=@bank-private.asc" \
  -F "signingPublicKey=@client-public.asc" \
  -F "passphrase=bank-secret" \
  --output plain.txt
```

### Error case: invalid purpose
```bash
curl -i -X POST http://localhost:8080/api/gpg/process \
  -F "purpose=invalid" \
  -F "file=@plain.txt"
```

### Error case: missing encryption key for encrypt
```bash
curl -i -X POST http://localhost:8080/api/gpg/process \
  -F "purpose=encrypt" \
  -F "file=@plain.txt" \
  -F "signingPrivateKey=@test-keys/sender-private.asc"
```

### Error case: missing signing public key for decrypt
```bash
curl -i -X POST http://localhost:8080/api/gpg/process \
  -F "purpose=decrypt" \
  -F "file=@plain.txt.pgp" \
  -F "decryptionPrivateKey=@test-keys/recipient-private.asc"
```
