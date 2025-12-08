## Usage

### Key Management

The `KeyProvider` interface manages keys for envelope encryption. The `GetKeyPair`
function will return a `KeyPair` struct containing a plaintext data key and the
corresponding encryption of the data key using the Transit key. The `DecryptKeyPair`
function takes in a ciphertext and uses the Transit key to decrypt the data key.

Each `KeyProvider` must be configured with a Vault client that is authenticated to
Vault and has permission to read Transit keys and encrypt and decrypt with Transit
keys.

### `TransitKeyProvider`
The `TransitKeyProvider` uses the Transit secrets engine to generate and encrypt data
keys. The `GetKeyPair` function uses the `datakey` endpoint to generate a new data key
and encrypt it using the Transit key in its configuration. Each call to `GetKeyPair`
generates a new data key. The `EDK` field contains the encrypted data key, which can be
decrypted using the `DecryptKeyPair` function.

### `ScheduledKeyProvider`
The `ScheduledKeyProvider` uses the configured Transit key for both key derivation and
encryption.