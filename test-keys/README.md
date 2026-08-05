# Test OpenPGP keys

These keys are generated for local integration testing of this project.

- Sender key pair: used for signing.
- Recipient key pair: used for encryption/decryption.

Generated with:
```bash
gpg --batch --passphrase '' --quick-generate-key 'Test Sender <sender@example.com>' rsa2048 sign 1y
gpg --batch --passphrase '' --quick-generate-key 'Test Recipient <recipient@example.com>' rsa2048 encrypt 1y
gpg --armor --export 'Test Sender <sender@example.com>' > sender-public.asc
gpg --armor --export-secret-keys 'Test Sender <sender@example.com>' > sender-private.asc
gpg --armor --export 'Test Recipient <recipient@example.com>' > recipient-public.asc
gpg --armor --export-secret-keys 'Test Recipient <recipient@example.com>' > recipient-private.asc
```
