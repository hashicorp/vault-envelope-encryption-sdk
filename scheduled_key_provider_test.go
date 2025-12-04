// Copyright (c) HashiCorp, Inc.
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
			expectedError: "cache size must be greater than zero",
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
			expectedError: "cache size must be greater than zero",
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

				scheduledProvider, ok := provider.(*scheduledKeyProvider)
				require.True(t, ok)

				require.Equal(t, tc.config.KeyName, scheduledProvider.keyName)
				require.Equal(t, tc.config.Backend, scheduledProvider.backend)
				require.Equal(t, tc.config.DailyKeyInterval, scheduledProvider.interval)
				require.Equal(t, tc.config.DaysPast+tc.config.DaysFuture+1, len(scheduledProvider.keys))

				numKeys := 0
				for _, key := range scheduledProvider.keys {
					numKeys += len(key)
				}

				require.Equal(t, tc.expectedNumKeys, numKeys)
			}
		})
	}
}

func TestGetKeyPair_scheduledKeyProvider(t *testing.T) {
	client, backend := providerTestSetup(t)

	testCases := map[string]time.Duration{
		"single key per day": 24 * time.Hour,
		"key per hour":       time.Hour,
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			provider, err := NewScheduledKeyProvider(ProviderConfig{
				DailyKeyInterval: tc,
				Client:           client,
				Backend:          backend,
				KeyName:          testKeyName,
				CacheSize:        1,
			})
			require.NoError(t, err)

			key, err := provider.GetKeyPair()
			require.NoError(t, err)
			require.NotEmpty(t, key)
			require.Equal(t, 32, len(key.DEK))
		})
	}
}

func TestDecryptKeyPair_scheduledKeyProvider(t *testing.T) {
	client, backend := providerTestSetup(t)

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

	dek, err := provider.DecryptKeyPair(key.EDK)
	require.NoError(t, err)
	require.Equal(t, key.DEK, dek)

	_, err = provider.DecryptKeyPair("invalid-ciphertext")
	require.Error(t, err)
}
