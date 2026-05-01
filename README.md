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

Example:
```bash
curl -X POST "http://localhost:8080/api/gpg/generate-keys" --output pgp-keyset.zip
```

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

## cURL examples

Encrypt and sign:
```bash
curl -X POST http://localhost:8080/api/gpg/process \
  -F "purpose=encrypt" \
  -F "file=@plain.txt" \
  -F "encryptionPublicKey=@test-keys/recipient-public.asc" \
  -F "signingPrivateKey=@test-keys/sender-private.asc" \
  --output plain.txt.pgp
```

Decrypt and verify:
```bash
curl -X POST http://localhost:8080/api/gpg/process \
  -F "purpose=decrypt" \
  -F "file=@plain.txt.pgp" \
  -F "decryptionPrivateKey=@test-keys/recipient-private.asc" \
  -F "signingPublicKey=@test-keys/sender-public.asc" \
  --output plain.txt
```
