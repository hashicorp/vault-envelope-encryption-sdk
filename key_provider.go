// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package envelope

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
)

// ProviderConfig contains config options for creating a KeyProvider
// using NewTransitKeyProvider or NewScheduledKeyProvider.
type ProviderConfig struct {
	// A client authenticated to Vault
	Client *api.Client
	// The size of the KeyProvider's internal cache.
	// A zero value disables caching.
	CacheSize int
	// The name of the key to use for encrypting data keys
	KeyName string
	// The name of the Transit backend
	Backend string
	// The version of the key to use. A zero value
	// indicates the latest key version.
	KeyVersion int
	// The size of data keys. Valid values are 128, 256,
	// and 512. The default is 256.
	KeyBits int
	// The number of days in the past for which to
	// generate data keys.
	// This field is only used by NewScheduledKeyProvider
	DaysPast int
	// The number of days into the future for which to
	// generate data keys.
	// This field is only used by NewScheduledKeyProvider
	DaysFuture int
	// The amount of time for which each data key is used.
	// This field is only used by NewScheduledKeyProvider
	DailyKeyInterval time.Duration
	// Context for key derivation if derived is set to true on the Transit key
	Context []byte
}

// KeyPair contains a Data Encryption Key (DEK)
// and the Encrypted Data Key (EDK) resulting from
// encrypting the DEK with a Transit key.
type KeyPair struct {
	KeyVersion int
	EDK        []byte
	DEK        []byte
}

// KeyProvider provides functions for managing data
// keys using the Transit secrets engine.
type KeyProvider interface {
	GetKeyPair() (*KeyPair, error)
	DecryptDataKey(edk string) ([]byte, error)
	GetKeyData() KeyData
}

func checkCommonConfig(config ProviderConfig) error {
	if config.Client == nil {
		return errors.New("missing client")
	}

	if config.CacheSize < 0 {
		return errors.New("cache size must not be negative")
	}

	if config.Backend == "" {
		return errors.New("missing backend")
	}

	if config.KeyName == "" {
		return errors.New("missing key name")
	}

	if config.KeyBits != 0 && config.KeyBits != 128 && config.KeyBits != 256 && config.KeyBits != 512 {
		return errors.New("invalid key size: must be 128, 256, or 512")
	}

	resp, err := config.Client.Logical().Read(fmt.Sprintf("%s/keys/%s", config.Backend, config.KeyName))
	if err != nil {
		return fmt.Errorf("error reading key: %v", err)
	}
	if resp == nil {
		return errors.New("key not found")
	}

	if config.KeyVersion > 0 {
		keys, ok := resp.Data["keys"].(map[string]interface{})
		if !ok {
			return errors.New("keys not found in response")
		}

		if _, ok := keys[strconv.Itoa(config.KeyVersion)]; !ok {
			return fmt.Errorf("invalid key version %d for key %s", config.KeyVersion, config.KeyName)
		}
	}

	return nil
}

func decryptKey(backend, keyName, ciphertext, context string, client *api.Client) ([]byte, error) {
	data := map[string]interface{}{"ciphertext": ciphertext}
	if len(context) > 0 {
		data["context"] = context
	}
	resp, err := client.Logical().Write(fmt.Sprintf("%s/decrypt/%s", backend, keyName), data)
	if err != nil {
		return nil, fmt.Errorf("error decrypting key: %v", err)
	}

	if resp == nil {
		return nil, errors.New("got nil response from transit")
	}

	plaintext, ok := resp.Data["plaintext"]
	if !ok {
		return nil, errors.New("missing plaintext in response")
	}

	dek, err := base64.StdEncoding.DecodeString(plaintext.(string))
	if err != nil {
		return nil, fmt.Errorf("error decoding dek: %v", err)
	}

	return dek, nil
}

func parseEDKCiphertext(edk string) (int, []byte, error) {
	segments := strings.Split(edk, ":")
	if len(segments) != 3 {
		return 0, nil, errors.New("invalid edk")
	}

	version, err := strconv.Atoi(strings.TrimPrefix(segments[1], "v"))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to parse version from EDK: %v", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(segments[2])
	if err != nil {
		return 0, nil, fmt.Errorf("error decoding ciphertext: %v", err)
	}

	return version, ciphertext, nil
}
