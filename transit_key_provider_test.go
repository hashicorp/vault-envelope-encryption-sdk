// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package envelope

import (
	"encoding/base64"
	"fmt"
	"strings"
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

	require.Equal(t, backend, provider.backend)
	require.Equal(t, testKeyName, provider.keyName)
	require.Equal(t, 128, provider.keyBits)
	require.Equal(t, 1, provider.keyVersion)
}

func TestGetKeyPair_transitKeyProvider(t *testing.T) {
	t.Parallel()

	client, backend := providerTestSetup(t)

	_, err := client.Logical().Write(fmt.Sprintf("%s/keys/%s/rotate", backend, testKeyName), map[string]interface{}{})
	require.NoError(t, err)

	testCases := map[string]struct {
		bits          int
		keyVersion    int
		cacheSize     int
		expectedError string
	}{
		"empty config": {},
		"128-bit keys": {
			bits:      128,
			cacheSize: 1,
		},
		"256-bit keys": {
			bits:      256,
			cacheSize: 1,
		},
		"512-bit keys": {
			bits:      512,
			cacheSize: 1,
		},
		"provided key version": {
			keyVersion: 1,
			cacheSize:  1,
		},
		"zero key version": {
			keyVersion: 0,
			cacheSize:  1,
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
				CacheSize:  tc.cacheSize,
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

			versionStr := "v2"
			if tc.keyVersion != 0 {
				versionStr = fmt.Sprintf("v%d", tc.keyVersion)
			}

			require.True(t, strings.HasPrefix(keyPair.EDK, "vault:"+versionStr))

			expectedKeyLength := 32
			if tc.bits != 0 {
				expectedKeyLength = tc.bits / 8
			}
			require.Equal(t, expectedKeyLength, len(keyPair.DEK))

			if tc.cacheSize != 0 {
				require.NotNil(t, provider.cache)
			}
		})
	}
}

func TestDecryptKeyPair_transitKeyProvider(t *testing.T) {
	t.Parallel()

	client, backend := providerTestSetup(t)

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
		cacheSize  int
		expected   []byte
		expectErr  bool
	}{
		"valid ciphertext": {
			ciphertext: v1Ciphertext,
			cacheSize:  1,
			expected:   v1Key,
		},
		"key version 2": {
			ciphertext: v2Ciphertext,
			cacheSize:  1,
			expected:   v2Key,
		},
		"no caching": {
			ciphertext: v1Ciphertext,
			expected:   v1Key,
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

			provider, err := NewTransitKeyProvider(ProviderConfig{
				Client:    client,
				KeyName:   testKeyName,
				Backend:   backend,
				CacheSize: tc.cacheSize,
			})
			require.NoError(t, err)

			key, err := provider.DecryptKeyPair(tc.ciphertext)
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expected, key)

				// change the provider so that it can't access the key for decryption
				provider.keyName = "bad-key"

				// when caching is enabled, decrypting this key should still succeed
				if tc.cacheSize != 0 {
					require.NotNil(t, provider.cache)
					require.Equal(t, 1, provider.cache.Len())
					require.True(t, provider.cache.Contains(tc.ciphertext))

					key, err = provider.DecryptKeyPair(tc.ciphertext)
					require.NoError(t, err)
					require.Equal(t, tc.expected, key)
				} else {
					require.Nil(t, provider.cache)

					key, err = provider.DecryptKeyPair(tc.ciphertext)
					require.Error(t, err)
				}
			}
		})
	}
}
