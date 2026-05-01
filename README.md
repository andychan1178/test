# GPG File Service (Spring Boot)

This service accepts a file and GPG key material and either encrypts or decrypts based on `purpose` (`encrypt` or `decrypt`).

## Run

```bash
mvn spring-boot:run
```

## API

`POST /api/gpg/process` (multipart/form-data)

Parameters:
- `purpose`: `encrypt` or `decrypt`
- `file`: file to process
- `publicKey`: required for `encrypt` (ASCII-armored public key)
- `privateKey`: required for `decrypt` (ASCII-armored private key)
- `passphrase`: optional passphrase for private key

### Encrypt example

```bash
curl -X POST http://localhost:8080/api/gpg/process \
  -F "purpose=encrypt" \
  -F "file=@plain.txt" \
  -F "publicKey=$(cat public.asc)" \
  --output plain.txt.pgp
```

### Decrypt example

```bash
curl -X POST http://localhost:8080/api/gpg/process \
  -F "purpose=decrypt" \
  -F "file=@plain.txt.pgp" \
  -F "privateKey=$(cat private.asc)" \
  -F "passphrase=your-passphrase" \
  --output plain.txt
```

## Maven GPG Plugin

The `maven-gpg-plugin` is configured in `pom.xml` to sign artifacts during the `verify` phase.
