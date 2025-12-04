// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package envelope

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/hashicorp/vault/api"
)

type ProviderConfig struct {
	Client           *api.Client
	CacheSize        int
	KeyName          string
	Backend          string
	Namespace        string
	KeyVersion       int
	KeyBits          int
	DaysPast         int
	DaysFuture       int
	DailyKeyInterval time.Duration
}

type KeyPair struct {
	EDK string
	DEK []byte
}

type KeyProvider interface {
	GetKeyPair() (*KeyPair, error)
	DecryptKeyPair(edk string) ([]byte, error)
	GetKeyData() KeyData
}

func checkCommonConfig(config ProviderConfig) error {
	if config.Client == nil {
		return errors.New("missing client")
	}

	if config.CacheSize <= 0 {
		return errors.New("cache size must be greater than zero")
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

func decryptKey(backend, keyName, ciphertext string, client *api.Client) ([]byte, error) {
	resp, err := client.Logical().Write(fmt.Sprintf("%s/decrypt/%s", backend, keyName), map[string]interface{}{"ciphertext": ciphertext})
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
