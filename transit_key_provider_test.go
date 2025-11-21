// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault_envelope_encryption_sdk

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewTransitKeyProvider(t *testing.T) {
	t.Parallel()

	client, backend := providerTestSetup(t)
	provider, err := NewTransitKeyProvider(ProviderConfig{
		Client:     client,
		CacheSize:  2,
		KeyName:    testKeyName,
		Backend:    backend,
		KeyBits:    128,
		KeyVersion: 1,
	})
	require.NoError(t, err)

	transitProvider, ok := provider.(*transitKeyProvider)
	require.True(t, ok)

	require.Equal(t, backend, transitProvider.backend)
	require.Equal(t, testKeyName, transitProvider.keyName)
	require.Equal(t, 128, transitProvider.keyBits)
	require.Equal(t, 1, transitProvider.keyVersion)

	provider, err = NewTransitKeyProvider(ProviderConfig{
		Client:     client,
		CacheSize:  2,
		KeyName:    testKeyName + "-new-key",
		Backend:    backend,
		KeyBits:    128,
		KeyVersion: 1,
		CreateKey:  true,
	})
	require.NoError(t, err)

	transitProvider, ok = provider.(*transitKeyProvider)
	require.True(t, ok)

	require.Equal(t, backend, transitProvider.backend)
	require.Equal(t, testKeyName+"-new-key", transitProvider.keyName)
	require.Equal(t, 128, transitProvider.keyBits)
	require.Equal(t, 1, transitProvider.keyVersion)

	resp, err := client.Logical().Read(fmt.Sprintf("%s/keys/%s%s", backend, testKeyName, "-new-key"))
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestGetKeyPair_transitKeyProvider(t *testing.T) {
	t.Parallel()

	client, backend := providerTestSetup(t)

	_, err := client.Logical().Write(fmt.Sprintf("transit/keys/%s/rotate", testKeyName), map[string]interface{}{})
	require.NoError(t, err)

	testCases := map[string]struct {
		bits          int
		keyVersion    int
		expectedError string
	}{
		"empty config": {},
		"128-bit keys": {
			bits: 128,
		},
		"256-bit keys": {
			bits: 256,
		},
		"512-bit keys": {
			bits: 512,
		},
		"provided key version": {
			keyVersion: 1,
		},
		"zero key version": {
			keyVersion: 0,
		},
		"invalid bits": {
			bits:          24,
			expectedError: "invalid key size",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			provider, err := NewTransitKeyProvider(ProviderConfig{
				Client:     client,
				KeyName:    testKeyName,
				Backend:    backend,
				CacheSize:  1,
				KeyBits:    tc.bits,
				KeyVersion: tc.keyVersion,
			})
			if tc.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectedError)
				return
			}

			require.NoError(t, err)

			keyPair, err := provider.GetKeyPair()
			require.NoError(t, err)
			require.NotNil(t, keyPair)
			require.NotEmpty(t, keyPair.EDK)
			require.NotEmpty(t, keyPair.DEK)

			expectedKeyLength := 32
			if tc.bits != 0 {
				expectedKeyLength = tc.bits / 8
			}
			require.Equal(t, expectedKeyLength, len(keyPair.DEK))
		})
	}
}

func TestDecryptKeyPair_transitKeyProvider(t *testing.T) {
	t.Parallel()

	client, backend := providerTestSetup(t)

	provider, err := NewTransitKeyProvider(ProviderConfig{
		Client:    client,
		KeyName:   testKeyName,
		Backend:   backend,
		CacheSize: 1,
	})
	require.NoError(t, err)

	resp, err := client.Logical().Write(fmt.Sprintf("%s/datakey/plaintext/%s", backend, testKeyName), map[string]interface{}{})
	require.NoError(t, err)
	require.NotNil(t, resp)

	v1Ciphertext := resp.Data["ciphertext"].(string)
	require.NotEmpty(t, v1Ciphertext)

	v1Plaintext := resp.Data["plaintext"].(string)
	require.NotEmpty(t, v1Plaintext)
	v1Key, err := base64.StdEncoding.DecodeString(v1Plaintext)
	require.NoError(t, err)

	_, err = client.Logical().Write(fmt.Sprintf("%s/keys/%s/rotate", backend, testKeyName), map[string]interface{}{})
	require.NoError(t, err)

	resp, err = client.Logical().Write(fmt.Sprintf("%s/datakey/plaintext/%s", backend, testKeyName), map[string]interface{}{})
	require.NoError(t, err)
	require.NotNil(t, resp)

	v2Ciphertext := resp.Data["ciphertext"].(string)
	require.NotEmpty(t, v2Ciphertext)

	v2Plaintext := resp.Data["plaintext"].(string)
	require.NotEmpty(t, v2Plaintext)
	v2Key, err := base64.StdEncoding.DecodeString(v2Plaintext)
	require.NoError(t, err)

	testCases := map[string]struct {
		ciphertext string
		expected   []byte
		expectErr  bool
	}{
		"valid ciphertext": {
			ciphertext: v1Ciphertext,
			expected:   v1Key,
		},
		"key version 2": {
			ciphertext: v2Ciphertext,
			expected:   v2Key,
		},
		"empty ciphertext": {
			expectErr: true,
		},
		"invalid ciphertext": {
			ciphertext: "bad-ciphertext",
			expectErr:  true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			key, err := provider.DecryptKeyPair(tc.ciphertext)
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expected, key)
			}
		})
	}
}
