# Vault Envelope Encryption SDK

This SDK provides utilities for using Vault Transit keys for large file encryption.

The use of the SDK requires a Vault Enterprise instance with the Transit secrets
engine enabled. There must be an AES key available in Transit for data key encryption.

The tests expect a Vault dev server with root token `root`.

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
keys. The `GetKeyPair` function uses the `datakeys` endpoint to generate a new data key
and encrypt it using the Transit key in its configuration. Each call to `GetKeyPair`
generates a new data key. The `EDK` field contains the encrypted data key, which can be
decrypted using the `DecryptKeyPair` function.

#### Example
```go
kp, err := NewTransitKeyProvider(ProviderConfig{
	Client:    client, // a Vault client authenticated to Vault
	CacheSize: 1,
	KeyName:   "test-key",
	Backend:   "transit",
})
```

### `ScheduledKeyProvider`
The `ScheduledKeyProvider` uses the configured Transit key for both key derivation and
encryption. The `NewScheduledKeyProvider` function creates all the data keys for
the provider at construction time. The `DaysPast`, `DaysFuture`, and `DailyKeyInterval`
parameters determine how many keys it requests from Transit. Starting from `DaysPast`
days in the past and going until `DaysFuture` days in the future, it uses the Transit
`derivedkeys` endpoint to generate keys for each day. The number of keys for each day
is `24*time.Hour/DailyKeyInterval` (e.g., a `DailyKeyInterval` of `8*time.Hour` will
create 3 keys per day).

Each call to `GetKeyPair` uses the current time to determine which key to return.
This means that two calls to `GetKeyPair` that fall within the same interval will
return the same key.

#### Example
```go
kp, err := NewScheduledKeyProvider(ProviderConfig{
	Client:           client, // a Vault client authenticated to Vault
	CacheSize:        1,
	KeyName:          "test-key",
	Backend:          "transit",
	DaysPast:         1,
	DaysFuture:       1,
	DailyKeyInterval: 12*time.Hour,
})
```

### Encryption and Decryption

Encryption and decryption operations use the `tink` library for streaming encryption.

`NewEncryptingWriter` uses the provided `KeyProvider` to generate a DEK then uses the
DEK to create a writer that encrypts data with `AES-GCM`. The ciphertext is prepended
with a magic value followed by a header. The header contains the EDK and metadata
describing the Transit key that produced the ciphertext.

`NewDecryptingReader` reads the EDK from the header and uses the provided `KeyProvider`
to decrypt it. If `headerOut` is provided, it will write the header to the channel.
It then returns a reader that decrypts data as it reads.

#### Example
```go
f, err := os.Open(ciphertextPath)
//handle err

w, err := NewEncryptingWriter(kp, f, nil, nil)
//handle err

w.Write([]byte("test plaintext"))
w.Close()

r, err := os.Open(ciphertextPath)
//handle err
```