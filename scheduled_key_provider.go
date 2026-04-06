// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package envelope

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/hashicorp/vault/api"
)

type scheduledKeyProvider struct {
	client     *api.Client
	cache      *lru.Cache
	keyName    string
	keyVersion int
	backend    string
	interval   time.Duration
	keys       map[string][]*KeyPair
	context    string
	edkMap     map[string]*KeyPair
}

// NewScheduledKeyProvider creates a KeyProvider using the provided config.
// This KeyProvider generates all data keys upon its creation and associates
// each key with a time interval.  It can still decrypt EDKs outside the time window
// by reaching out to Vault, in which case the result can be cached.
func NewScheduledKeyProvider(config ProviderConfig) (*scheduledKeyProvider, error) {
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
		client:     config.Client,
		keyName:    config.KeyName,
		keyVersion: config.KeyVersion,
		backend:    config.Backend,
		interval:   config.DailyKeyInterval,
		keys:       make(map[string][]*KeyPair),
		edkMap:     make(map[string]*KeyPair),
	}

	if len(config.Context) > 0 {
		provider.context = base64.StdEncoding.EncodeToString(config.Context)
	}

	if config.CacheSize > 0 {
		provider.cache, err = lru.New(config.CacheSize)
		if err != nil {
			return nil, fmt.Errorf("error initializing cache: %v", err)
		}
	}

	// UTC time, so workloads in different time zones still align
	now := time.Now().UTC()
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
		if len(config.Context) > 0 {
			data["context"] = base64.StdEncoding.EncodeToString(config.Context)
		}

		if config.KeyBits != 0 {
			data["key_bits"] = config.KeyBits
		}

		resp, err := provider.client.Logical().Write(fmt.Sprintf("%s/derivedkeys/plaintext/%s", provider.backend, provider.keyName), data)
		if err != nil {
			return nil, fmt.Errorf("error fetching deriving keys: %v", err)
		}

		if resp == nil {
			return nil, errors.New("got nil response from transit")
		}

		provider.keys[date] = make([]*KeyPair, keysPerDay)
		for k, v := range resp.Data {
			if keyIndex, err := strconv.Atoi(k); err == nil {
				returnedMap, ok := v.(map[string]interface{})
				if !ok {
					return nil, fmt.Errorf("got unexpected type %T from response data", v)
				}

				var version int
				var edk []byte
				var dek []byte
				var edkStr string
				if ct, ok := returnedMap["ciphertext"]; ok {
					edkStr = ct.(string)
					version, edk, err = parseEDKCiphertext(edkStr)
					if err != nil {
						return nil, fmt.Errorf("error parsing returned EDK: %v", err)
					}
				} else {
					return nil, errors.New("response did not include EDK")
				}

				if pt, ok := returnedMap["plaintext"]; ok {
					dek, err = base64.StdEncoding.DecodeString(pt.(string))
					if err != nil {
						return nil, fmt.Errorf("error base64 decoding dek: %v", err)
					}
				} else {
					return nil, errors.New("response did not include DEK")
				}

				kp := KeyPair{
					KeyVersion: version,
					EDK:        edk,
					DEK:        dek,
				}
				provider.keys[date][keyIndex] = &kp
				provider.edkMap[edkStr] = &kp
			}
		}
	}

	return provider, nil
}

// GetKeyPair returns the KeyPair associated with the current time.
// Subsequent calls may return the same key if the calls are made within
// the same time interval.
func (p *scheduledKeyProvider) GetKeyPair() (*KeyPair, error) {
	// UTC time, so workloads in different time zones still align
	now := time.Now().UTC()
	date := now.Format("2006-01-02")
	todayKeys, ok := p.keys[date]
	if !ok {
		return nil, errors.New("no keys configured for the current date")
	}

	timeElapsedInDay := now.Sub(time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()))
	keyIndex := int(timeElapsedInDay / p.interval)

	if keyIndex >= len(todayKeys) {
		return nil, fmt.Errorf("key index %d out of range", keyIndex)
	}

	rv := todayKeys[keyIndex]
	return rv, nil
}

// DecryptDataKey returns the plaintext DEK for the input EDK
func (p *scheduledKeyProvider) DecryptDataKey(edk string) ([]byte, error) {
	// First see if we have it in the windowed keys
	if kp, ok := p.edkMap[edk]; ok {
		return kp.DEK, nil
	}

	// Or, if not, have we seen it before?
	if p.cache != nil {
		if v, ok := p.cache.Get(edk); ok {
			dek, ok := v.([]byte)
			if !ok {
				return nil, fmt.Errorf("got unexpected type %T from cache value", v)
			}
			return dek, nil
		}
	}

	// Otherwise we do need to fetch it
	dek, err := decryptKey(p.backend, p.keyName, edk, p.context, p.client)
	if err != nil {
		return nil, err
	}

	if p.cache != nil {
		p.cache.Add(edk, dek)
	}
	return dek, nil
}

// GetKeyData returns a KeyData struct with the KeyName, KeyVersion,
// MountPath, and Namespace fields from the configured Transit key.
func (p *scheduledKeyProvider) GetKeyData() KeyData {
	namespace := p.client.Namespace()

	return KeyData{
		KeyName:    &p.keyName,
		KeyVersion: uint32(p.keyVersion),
		MountPath:  &p.backend,
		Namespace:  &namespace,
	}
}

// for testing
func (p *scheduledKeyProvider) keyCount() int {
	l := 0
	for _, v := range p.keys {
		l += len(v)
	}
	return l
}
