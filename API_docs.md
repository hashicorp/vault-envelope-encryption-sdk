# API

## `KeyProvider` Config Parameters

These parameters are common to both `TransitKeyProvider` and `ScheduledKeyProvider`.

- `Client` `(Client: <required>)` - A Vault API client authenticated to Vault. The client must have read permission
  for the Transit `keys` endpoint. For the `TransitKeyProvider`, the client must have write permission for the `datakey`
  endpoint. For the `ScheduledKeyProvider`, it must have write permission for the `derivedkeys` endpoint.

- `CacheSize` `(int: 0)` - The size of the key cache in the `KeyProvider`. If the size
  is `0`, the provider will not cache data keys.

- `KeyName` `(string: <required>)` - The name of the Transit key to use for deriving and
  encrypting data keys.

- `Backend` `(string: <required>)` - The name of the Transit backend.

- `KeyVersion` `(int: 0)` - The version to use of the Transit key. If the version is
  `0`, Vault will use the latest key version.

- `KeyBits` `(int: 256)` - The size of data keys to generate.

### `ScheduledKeyProvider` Config Parameters

These Parameters are specific to `ScheduledKeyProvider`. `TransitKeyProvider` will
ignore these values.

- `DaysPast` `(int: 0)` - The number of days in the past for which the `ScheduledKeyProvider`
  will generate data keys.

- `DaysFuture` `(int: 0)` - The number of days into the future for which the `ScheduledKeyProvider`
  will generate data keys.

- `DailyKeyInterval` `(Duration: <required>)` - The length of time for which each data
  key will be returned by `GetKeyPair`. This determines how many keys the `ScheduledKeyProvider`
  generates per day. The number of keys generated per day is calculated as `24*time.Hour / DailyKeyInterval`.

  e.g., if the `DailyKeyInterval` is `24*time.Hour`, the `ScheduledKeyProvider` will
  generate one key per day in the range specified by `DaysPast` and `DaysFuture`.

## `NewEncryptingWriter` Parameters
- `kp` `(required)` - A KeyProvider configured with a Transit key

- `dest` `(required)` - The `Writer` to which the ciphertext will be written

- `header` - The Header to prepend to the ciphertext. If a header is not provided,
the function will create one. The `KeyData` field of the header will be populated
with the key data from `kp`.

- `aad` - The AAD to use in the encryption

- `length` - The length of the header in bytes


## `NewDecryptingReader` Parameters
- `kp` `(required)` - A `KeyProvider` configured with the Transit key used to create
the DEK of the ciphertext.

- `src` `(required)` - The `Reader` that provides the ciphertext

- `aad` - The AAD used in the encryption of the ciphertext

- `length` - The length of the header in bytes

- `headerOut` - A channel to which the header from the ciphertext will be written