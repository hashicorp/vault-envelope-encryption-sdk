// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package envelope

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

const (
	testKeyName        = "test-key"
	testKeyNameDerived = "test-key-derived"
)

var testContext = base64.StdEncoding.EncodeToString([]byte("key context"))

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
		},
		"negative cache size": {
			config: ProviderConfig{
				Client:    client,
				KeyName:   testKeyName,
				Backend:   backend,
				CacheSize: -1,
			},
			expectedError: "cache size must not be negative",
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

	// Determine if we have Vault 2.0
	health, err := client.Sys().Health()
	require.NoError(t, err)
	have20 := strings.HasPrefix(health.Version, "1.22") || strings.HasPrefix(health.Version, "2.") // since we still haven't moved to 2.0 as the version yet

	_, err = client.Logical().Write(fmt.Sprintf("%s/keys/%s/rotate", backend, testKeyName), map[string]interface{}{})
	require.NoError(t, err)

	resp, err := client.Logical().Write(fmt.Sprintf("%s/datakeys/plaintext/%s", backend, testKeyName), map[string]interface{}{"key_version": 1, "count": 1})
	require.NoError(t, err)
	require.NotNil(t, resp.Data)

	keypairsRaw, ok := resp.Data["key_pairs"]
	require.True(t, ok)
	keypairs := keypairsRaw.([]any)
	first := keypairs[0].(map[string]any)
	v1Ciphertext, ok := first["ciphertext"].(string)
	require.True(t, ok)

	v1PlaintextEncoded, ok := first["plaintext"].(string)
	require.True(t, ok)

	v1Plaintext, err := base64.StdEncoding.DecodeString(v1PlaintextEncoded)
	require.NoError(t, err)

	// Test derived success and fail.  Temporarily disabled until we have a Vault release with the API support to test against

	resp, err = client.Logical().Write(fmt.Sprintf("%s/datakeys/plaintext/%s", backend, testKeyName), map[string]interface{}{"key_version": 2, "count": 1})
	require.NoError(t, err)
	require.NotNil(t, resp.Data)

	keypairsRaw, ok = resp.Data["key_pairs"]
	require.True(t, ok)
	keypairs = keypairsRaw.([]any)
	first = keypairs[0].(map[string]any)
	v2Ciphertext, ok := first["ciphertext"].(string)
	require.True(t, ok)

	v2PlaintextEncoded, ok := first["plaintext"].(string)
	require.True(t, ok)

	v2Plaintext, err := base64.StdEncoding.DecodeString(v2PlaintextEncoded)
	require.NoError(t, err)

	type tCase struct {
		backend     string
		keyName     string
		edk         string
		expectedKey []byte
		expectErr   bool
		context     string
		requires20  bool
	}

	testCases := map[string]tCase{
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
	if have20 {
		resp, err = client.Logical().Write(fmt.Sprintf("%s/datakeys/plaintext/%s", backend, testKeyNameDerived), map[string]interface{}{"count": 1})
		require.Error(t, err)
		require.True(t, strings.Contains(err.Error(), "missing 'context'"))

		resp, err = client.Logical().Write(fmt.Sprintf("%s/datakeys/plaintext/%s", backend, testKeyNameDerived), map[string]interface{}{"count": 1, "context": testContext})
		require.NoError(t, err)
		require.NotNil(t, resp.Data)

		keypairsRaw, ok = resp.Data["key_pairs"]
		require.True(t, ok)
		keypairs = keypairsRaw.([]any)
		first = keypairs[0].(map[string]any)
		contextCiphertext, ok := first["ciphertext"].(string)
		require.True(t, ok)

		contextPlaintextEncoded, ok := first["plaintext"].(string)
		require.True(t, ok)

		contextPlaintext, err := base64.StdEncoding.DecodeString(contextPlaintextEncoded)
		require.NoError(t, err)

		testCases["with context"] = tCase{
			backend:     backend,
			keyName:     testKeyNameDerived,
			edk:         contextCiphertext,
			expectedKey: contextPlaintext,
			context:     testContext,
			requires20:  true,
		}
	}

	for name, tc := range testCases {
		if !tc.requires20 || have20 {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				dek, err := decryptKey(tc.backend, tc.keyName, tc.edk, tc.context, client)
				if tc.expectErr {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					require.Equal(t, tc.expectedKey, dek)
				}
			})
		}
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

	data := map[string]any{
		"derived": "true",
	}

	_, err = client.Logical().Write(fmt.Sprintf("%s/keys/%s", backend, testKeyNameDerived), data)
	require.NoError(t, err)

	return client, backend
}
