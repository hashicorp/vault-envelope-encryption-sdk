// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package envelope

import (
	"encoding/base64"
	"errors"
	"fmt"

	lru "github.com/hashicorp/golang-lru"
	"github.com/hashicorp/vault/api"
)

type transitKeyProvider struct {
	client     *api.Client
	cache      *lru.Cache
	keyName    string
	backend    string
	keyBits    int
	keyVersion int
}

func NewTransitKeyProvider(config ProviderConfig) (*transitKeyProvider, error) {
	err := checkCommonConfig(config)
	if err != nil {
		return nil, err
	}

	provider := &transitKeyProvider{
		client:     config.Client,
		keyName:    config.KeyName,
		backend:    config.Backend,
		keyBits:    config.KeyBits,
		keyVersion: config.KeyVersion,
	}

	if config.CacheSize > 0 {
		provider.cache, err = lru.New(config.CacheSize)
		if err != nil {
			return nil, fmt.Errorf("error initializing cache: %v", err)
		}
	}

	return provider, nil
}

func (p *transitKeyProvider) GetKeyPair() (*KeyPair, error) {
	data := map[string]interface{}{
		"key_version": p.keyVersion,
		"count":       1,
	}

	if p.keyBits != 0 {
		data["bits"] = p.keyBits
	}

	resp, err := p.client.Logical().Write(fmt.Sprintf("%s/datakeys/plaintext/%s", p.backend, p.keyName), data)
	if err != nil {
		return nil, err
	}

	if resp == nil {
		return nil, errors.New("got nil response from transit")
	}

	keyPairs, ok := resp.Data["key_pairs"]
	if !ok {
		return nil, errors.New("missing key_pairs in response")
	}

	keyPairList, ok := keyPairs.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected type %T from response data", keyPairs)
	}

	if len(keyPairList) == 0 {
		return nil, errors.New("key_pairs is empty")
	}

	keyPair, ok := keyPairList[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected type %T from response data", keyPair)
	}

	ciphertext, ok := keyPair["ciphertext"]
	if !ok {
		return nil, errors.New("missing ciphertext in response")
	}

	plaintext, ok := keyPair["plaintext"]
	if !ok {
		return nil, errors.New("missing plaintext in response")
	}

	plaintextBytes, err := base64.StdEncoding.DecodeString(plaintext.(string))
	if err != nil {
		return nil, fmt.Errorf("error decoding plaintext: %w", err)
	}

	version, edk, err := parseEDKCiphertext(ciphertext.(string))
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		KeyVersion: version,
		EDK:        edk,
		DEK:        plaintextBytes,
	}, nil
}

func (p *transitKeyProvider) DecryptDataKey(edk string) ([]byte, error) {
	if p.cache != nil {
		if v, ok := p.cache.Get(edk); ok {
			dek, ok := v.([]byte)
			if !ok {
				return nil, fmt.Errorf("got unexpected type %T from cache value", v)
			}

			return dek, nil
		}
	}

	dek, err := decryptKey(p.backend, p.keyName, edk, p.client)
	if err != nil {
		return nil, err
	}

	if p.cache != nil {
		p.cache.Add(edk, dek)
	}
	return dek, nil
}

func (p *transitKeyProvider) GetKeyData() KeyData {
	namespace := p.client.Namespace()

	kd := KeyData{
		KeyName:    &p.keyName,
		KeyVersion: uint32(p.keyVersion),
		MountPath:  &p.backend,
	}
	if namespace != "" {
		kd.Namespace = &namespace
	}
	return kd
}
