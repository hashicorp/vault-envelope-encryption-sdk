// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package envelope

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

const testKeyName = "test-key"

func TestCheckCommonConfig(t *testing.T) {
	t.Parallel()

	client, backend := providerTestSetup(t)

	testCases := map[string]struct {
		config        ProviderConfig
		expectedError string
	}{
		"valid config": {
			config: ProviderConfig{
				Client:    client,
				KeyName:   testKeyName,
				Backend:   backend,
				CacheSize: 1,
			},
		},
		"missing backend": {
			config: ProviderConfig{
				Client:    client,
				KeyName:   testKeyName,
				CacheSize: 1,
			},
			expectedError: "missing backend",
		},
		"missing key name": {
			config: ProviderConfig{
				Client:    client,
				Backend:   backend,
				CacheSize: 1,
			},
			expectedError: "missing key name",
		},
		"invalid key name": {
			config: ProviderConfig{
				Client:    client,
				KeyName:   "bad-key",
				Backend:   backend,
				CacheSize: 1,
			},
			expectedError: "key not found",
		},
		"nil client": {
			config: ProviderConfig{
				KeyName:   "new-key",
				Backend:   backend,
				CacheSize: 1,
			},
			expectedError: "missing client",
		},
		"zero cache size": {
			config: ProviderConfig{
				Client:    client,
				KeyName:   testKeyName,
				Backend:   backend,
				CacheSize: 0,
			},
			expectedError: "cache size must be greater than zero",
		},
		"negative cache size": {
			config: ProviderConfig{
				Client:    client,
				KeyName:   testKeyName,
				Backend:   backend,
				CacheSize: -1,
			},
			expectedError: "cache size must be greater than zero",
		},
		"invalid key version": {
			config: ProviderConfig{
				Client:     client,
				KeyName:    testKeyName,
				Backend:    backend,
				CacheSize:  1,
				KeyVersion: 3,
			},
			expectedError: "invalid key version",
		},
		"invalid key bits": {
			config: ProviderConfig{
				Client:    client,
				KeyName:   testKeyName,
				Backend:   backend,
				CacheSize: 1,
				KeyBits:   3,
			},
			expectedError: "invalid key size: must be 128, 256, or 512",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := checkCommonConfig(tc.config)
			if tc.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectedError)
			} else {
				require.NoError(t, err)

				resp, err := client.Logical().Read(fmt.Sprintf("%s/keys/%s", backend, tc.config.KeyName))
				require.NoError(t, err)
				require.NotNil(t, resp)
			}
		})
	}
}

func TestDecryptKey(t *testing.T) {
	t.Parallel()

	client, backend := providerTestSetup(t)
	_, err := client.Logical().Write(fmt.Sprintf("%s/keys/%s/rotate", backend, testKeyName), map[string]interface{}{})
	require.NoError(t, err)

	resp, err := client.Logical().Write(fmt.Sprintf("%s/datakey/plaintext/%s", backend, testKeyName), map[string]interface{}{"key_version": 1})
	require.NoError(t, err)
	require.NotNil(t, resp.Data)

	v1Ciphertext, ok := resp.Data["ciphertext"].(string)
	require.True(t, ok)

	v1PlaintextEncoded, ok := resp.Data["plaintext"].(string)
	require.True(t, ok)

	v1Plaintext, err := base64.StdEncoding.DecodeString(v1PlaintextEncoded)
	require.NoError(t, err)

	resp, err = client.Logical().Write(fmt.Sprintf("%s/datakey/plaintext/%s", backend, testKeyName), map[string]interface{}{"key_version": 2})
	require.NoError(t, err)
	require.NotNil(t, resp.Data)

	v2Ciphertext, ok := resp.Data["ciphertext"].(string)
	require.True(t, ok)

	v2PlaintextEncoded, ok := resp.Data["plaintext"].(string)
	require.True(t, ok)

	v2Plaintext, err := base64.StdEncoding.DecodeString(v2PlaintextEncoded)
	require.NoError(t, err)

	testCases := map[string]struct {
		backend     string
		keyName     string
		edk         string
		expectedKey []byte
		expectErr   bool
	}{
		"invalid backend": {
			backend:   "trasnit",
			keyName:   testKeyName,
			expectErr: true,
		},
		"invalid key name": {
			backend:   backend,
			keyName:   "bad-key",
			expectErr: true,
		},
		"invalid ciphertext": {
			backend:   backend,
			keyName:   testKeyName,
			edk:       "bad-key",
			expectErr: true,
		},
		"key version 1": {
			backend:     backend,
			keyName:     testKeyName,
			edk:         v1Ciphertext,
			expectedKey: v1Plaintext,
		},
		"key version 2": {
			backend:     backend,
			keyName:     testKeyName,
			edk:         v2Ciphertext,
			expectedKey: v2Plaintext,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dek, err := decryptKey(tc.backend, tc.keyName, tc.edk, client)
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expectedKey, dek)
			}
		})
	}
}

func providerTestSetup(t *testing.T) (*api.Client, string) {
	clientConfig := api.DefaultConfig()

	client, err := api.NewClient(clientConfig)
	require.NoError(t, err)

	require.NoError(t, client.SetAddress("http://localhost:8200"))
	client.SetToken("root")

	id, err := uuid.GenerateUUID()
	require.NoError(t, err)

	backend := fmt.Sprintf("transit-%s", id)

	err = client.Sys().Mount(backend, &api.MountInput{Type: "transit"})
	require.NoError(t, err)

	_, err = client.Logical().Write(fmt.Sprintf("%s/keys/%s", backend, testKeyName), nil)
	require.NoError(t, err)

	return client, backend
}
