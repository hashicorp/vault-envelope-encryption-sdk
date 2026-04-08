// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package envelope

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewScheduledKeyProvider(t *testing.T) {
	t.Parallel()

	client, backend := providerTestSetup(t)

	testCases := map[string]struct {
		config          ProviderConfig
		expectedNumKeys int
		expectedError   string
	}{
		"single key per day": {
			config: ProviderConfig{
				Client:           client,
				KeyName:          testKeyName,
				Backend:          backend,
				CacheSize:        1,
				DaysPast:         1,
				DaysFuture:       1,
				DailyKeyInterval: 24 * time.Hour,
			},
			expectedNumKeys: 3,
		},
		"missing backend": {
			config: ProviderConfig{
				Client:           client,
				KeyName:          testKeyName,
				CacheSize:        1,
				DaysPast:         1,
				DaysFuture:       1,
				DailyKeyInterval: 24 * time.Hour,
			},
			expectedError: "missing backend",
		},
		"missing key name": {
			config: ProviderConfig{
				Client:           client,
				Backend:          backend,
				CacheSize:        1,
				DaysPast:         1,
				DaysFuture:       1,
				DailyKeyInterval: 24 * time.Hour,
			},
			expectedError: "missing key name",
		},
		"invalid key name": {
			config: ProviderConfig{
				Client:           client,
				KeyName:          "bad-key",
				Backend:          backend,
				CacheSize:        1,
				DaysPast:         1,
				DaysFuture:       1,
				DailyKeyInterval: 24 * time.Hour,
			},
			expectedError: "key not found",
		},
		"nil client": {
			config: ProviderConfig{
				KeyName:          testKeyName,
				Backend:          backend,
				CacheSize:        1,
				DaysPast:         1,
				DaysFuture:       1,
				DailyKeyInterval: 24 * time.Hour,
			},
			expectedError: "missing client",
		},
		"zero cache size": {
			config: ProviderConfig{
				Client:           client,
				KeyName:          testKeyName,
				Backend:          backend,
				CacheSize:        0,
				DaysPast:         1,
				DaysFuture:       1,
				DailyKeyInterval: 24 * time.Hour,
			},
			expectedNumKeys: 3,
		},
		"negative cache size": {
			config: ProviderConfig{
				Client:           client,
				KeyName:          testKeyName,
				Backend:          backend,
				CacheSize:        -1,
				DaysPast:         1,
				DaysFuture:       1,
				DailyKeyInterval: 24 * time.Hour,
			},
			expectedError: "cache size must not be negative",
		},
		"zero key interval": {
			config: ProviderConfig{
				Client:           client,
				KeyName:          testKeyName,
				Backend:          backend,
				CacheSize:        1,
				DaysPast:         1,
				DaysFuture:       1,
				DailyKeyInterval: 0,
			},
			expectedError: "DailyKeyInterval must be positive",
		},
		"negative key interval": {
			config: ProviderConfig{
				Client:           client,
				KeyName:          testKeyName,
				Backend:          backend,
				CacheSize:        1,
				DaysPast:         1,
				DaysFuture:       1,
				DailyKeyInterval: -1,
			},
			expectedError: "DailyKeyInterval must be positive",
		},
		"negative daysPast": {
			config: ProviderConfig{
				Client:           client,
				KeyName:          testKeyName,
				Backend:          backend,
				CacheSize:        1,
				DaysPast:         -1,
				DaysFuture:       1,
				DailyKeyInterval: 24 * time.Hour,
			},
			expectedError: "DaysPast cannot be negative",
		},
		"negative daysFuture": {
			config: ProviderConfig{
				Client:           client,
				KeyName:          testKeyName,
				Backend:          backend,
				CacheSize:        1,
				DaysPast:         1,
				DaysFuture:       -1,
				DailyKeyInterval: 24 * time.Hour,
			},
			expectedError: "DaysFuture cannot be negative",
		},
		"zero daysPast and daysFuture": {
			config: ProviderConfig{
				Client:           client,
				KeyName:          testKeyName,
				Backend:          backend,
				CacheSize:        1,
				DaysPast:         0,
				DaysFuture:       0,
				DailyKeyInterval: 24 * time.Hour,
			},
			expectedNumKeys: 1,
		},
		"multiple keys per day": {
			config: ProviderConfig{
				Client:           client,
				KeyName:          testKeyName,
				Backend:          backend,
				CacheSize:        1,
				DaysPast:         1,
				DaysFuture:       1,
				DailyKeyInterval: time.Hour,
			},
			expectedNumKeys: 72,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			provider, err := NewScheduledKeyProvider(tc.config)
			if tc.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectedError)
			} else {
				require.NoError(t, err)
				require.NotNil(t, provider)

				resp, err := client.Logical().Read(fmt.Sprintf("%s/keys/%s", backend, tc.config.KeyName))
				require.NoError(t, err)
				require.NotNil(t, resp)

				require.Equal(t, tc.config.KeyName, provider.keyName)
				require.Equal(t, tc.config.Backend, provider.backend)
				require.Equal(t, tc.config.DailyKeyInterval, provider.interval)
				require.Equal(t, tc.config.DaysPast+tc.config.DaysFuture+1, len(provider.keys))

				numKeys := 0
				for _, key := range provider.keys {
					numKeys += len(key)
				}

				require.Equal(t, tc.expectedNumKeys, numKeys)
			}
		})
	}
}

func TestGetKeyPair_scheduledKeyProvider(t *testing.T) {
	client, backend := providerTestSetup(t)

	testCases := map[string]struct {
		interval time.Duration
		keyCount int
	}{
		"single key per day": {
			interval: 24 * time.Hour,
			keyCount: 1,
		},
		"key per hour": {
			interval: time.Hour,
			keyCount: 24,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			provider, err := NewScheduledKeyProvider(ProviderConfig{
				DailyKeyInterval: tc.interval,
				Client:           client,
				Backend:          backend,
				KeyName:          testKeyName,
			})
			require.NoError(t, err)

			key, err := provider.GetKeyPair()
			require.NoError(t, err)
			require.NotEmpty(t, key)
			require.Equal(t, 32, len(key.DEK))

			if tc.keyCount > 0 {
				require.Equal(t, tc.keyCount, provider.keyCount())
			} else {
				require.Nil(t, provider.cache)
			}
		})
	}
}

func TestDecryptKeyPair_scheduledKeyProvider(t *testing.T) {
	client, backend := providerTestSetup(t)

	// test with caching
	provider, err := NewScheduledKeyProvider(ProviderConfig{
		DailyKeyInterval: 24 * time.Hour,
		Client:           client,
		Backend:          backend,
		KeyName:          testKeyName,
		CacheSize:        1,
	})
	require.NoError(t, err)

	key, err := provider.GetKeyPair()
	require.NoError(t, err)

	ciphertext := toTransitCiphertext(uint(key.KeyVersion), key.EDK)

	dek, err := provider.DecryptDataKey(ciphertext)
	require.NoError(t, err)
	require.Equal(t, key.DEK, dek)

	require.NotNil(t, provider.cache)
	require.Equal(t, 1, provider.keyCount())
	require.NotNil(t, provider.edkMap[ciphertext])

	// make it impossible for the provider to reach the key
	// to validate that it's loading from the cache
	provider.keyName = "bad-key"

	dek, err = provider.DecryptDataKey(ciphertext)
	require.NoError(t, err)
	require.Equal(t, key.DEK, dek)

	// test without caching
	provider, err = NewScheduledKeyProvider(ProviderConfig{
		DailyKeyInterval: 24 * time.Hour,
		Client:           client,
		Backend:          backend,
		KeyName:          testKeyName,
		CacheSize:        0,
	})
	require.NoError(t, err)

	key, err = provider.GetKeyPair()
	require.NoError(t, err)

	ciphertext = toTransitCiphertext(uint(key.KeyVersion), key.EDK)

	dek, err = provider.DecryptDataKey(ciphertext)
	require.NoError(t, err)
	require.Equal(t, key.DEK, dek)

	require.Nil(t, provider.cache)

	// this should fail without caching
	provider.keyName = "bad-key"
	dek, err = provider.DecryptDataKey(ciphertext[1:])
	require.Error(t, err)

	// error case
	_, err = provider.DecryptDataKey("invalid-ciphertext")
	require.Error(t, err)
}
