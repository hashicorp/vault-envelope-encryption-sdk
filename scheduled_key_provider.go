// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault_envelope_encryption_sdk

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/hashicorp/vault/api"
)

func init() {
	if signed := os.Getenv("VAULT_LICENSE_CI"); signed != "" {
		if err := os.Setenv("VAULT_LICENSE", signed); err != nil {
			panic(err.Error())
		}
	}
}

type scheduledKeyProvider struct {
	client   *api.Client
	cache    *lru.Cache
	keyName  string
	backend  string
	interval time.Duration
	keys     map[string][]string
}

func NewScheduledKeyProvider(config ProviderConfig) (KeyProvider, error) {
	err := checkCommonConfig(config)
	if err != nil {
		return nil, err
	}

	if config.DaysPast < 0 {
		return nil, errors.New("DaysPast cannot be negative")
	}

	if config.DaysFuture < 0 {
		return nil, errors.New("DaysFuture cannot be negative")
	}

	if config.DailyKeyInterval <= 0 {
		return nil, errors.New("DailyKeyInterval must be positive")
	}

	provider := &scheduledKeyProvider{
		client:   config.Client,
		keyName:  config.KeyName,
		backend:  config.Backend,
		interval: config.DailyKeyInterval,
		keys:     make(map[string][]string),
	}

	provider.cache, err = lru.New(config.CacheSize)
	if err != nil {
		return nil, fmt.Errorf("error initializing cache: %v", err)
	}

	now := time.Now()
	startDate := now.AddDate(0, 0, -config.DaysPast)
	endDate := now.AddDate(0, 0, config.DaysFuture)
	keysPerDay := 24 * time.Hour / config.DailyKeyInterval

	for i := startDate; !i.After(endDate); i = i.AddDate(0, 0, 1) {
		date := i.Format("2006-01-02") // the layout string must represent the date Jan 2, 2006

		data := map[string]interface{}{
			"salt":           date,
			"key_index_from": 0,
			"key_index_to":   keysPerDay,
			"key_version":    config.KeyVersion,
		}

		if config.KeyBits != 0 {
			data["key_bits"] = config.KeyBits
		}

		resp, err := provider.client.Logical().Write(fmt.Sprintf("%s/derivedkeys/wrapped/%s", provider.backend, provider.keyName), data)
		if err != nil {
			return nil, fmt.Errorf("error fetching deriving keys: %v", err)
		}

		if resp == nil {
			return nil, errors.New("got nil response from transit")
		}

		provider.keys[date] = make([]string, keysPerDay)
		for k, v := range resp.Data {
			if keyIndex, err := strconv.Atoi(k); err == nil {
				returnedMap, ok := v.(map[string]interface{})
				if !ok {
					return nil, fmt.Errorf("got unexpected type %T from response data", v)
				}

				provider.keys[date][keyIndex] = returnedMap["ciphertext"].(string)
			}
		}
	}

	return provider, nil
}

func (p *scheduledKeyProvider) GetKeyPair() (*KeyPair, error) {
	now := time.Now()
	date := now.Format("2006-01-02")
	todayKeys, ok := p.keys[date]
	if !ok {
		return nil, errors.New("no keys configured for the current date")
	}

	timeElapsedInDay := now.Sub(time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC))
	keyIndex := int(timeElapsedInDay / p.interval)

	if keyIndex >= len(todayKeys) {
		return nil, fmt.Errorf("key index %d out of range", keyIndex)
	}

	edk := todayKeys[keyIndex]
	if v, ok := p.cache.Get(edk); ok {
		dek, ok := v.([]byte)
		if !ok {
			return nil, fmt.Errorf("got unexpected type %T from cache value", v)
		}

		return &KeyPair{
			EDK: edk,
			DEK: dek,
		}, nil
	}

	dek, err := decryptKey(p.backend, p.keyName, edk, p.client)
	if err != nil {
		return nil, err
	}

	p.cache.Add(edk, dek)

	return &KeyPair{
		EDK: edk,
		DEK: dek,
	}, nil
}

func (p *scheduledKeyProvider) DecryptKeyPair(edk string) ([]byte, error) {
	if v, ok := p.cache.Get(edk); ok {
		dek, ok := v.([]byte)
		if !ok {
			return nil, fmt.Errorf("got unexpected type %T from cache value", v)
		}

		return dek, nil
	}

	dek, err := decryptKey(p.backend, p.keyName, edk, p.client)
	if err != nil {
		return nil, err
	}

	p.cache.Add(edk, dek)
	return dek, nil
}
