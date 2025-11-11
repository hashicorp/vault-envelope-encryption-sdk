// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault_envelope_encryption_sdk

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func init() {
	if signed := os.Getenv("VAULT_LICENSE_CI"); signed != "" {
		if err := os.Setenv("VAULT_LICENSE", signed); err != nil {
			panic(err.Error())
		}
	}
}

func TestNewScheduledKeyProvider(t *testing.T) {
	t.Parallel()

	client := providerTestSetup(t)

	testCases := map[string]struct {
		config        ProviderConfig
		expectedError string
	}{
		"create key": {
			config: ProviderConfig{
				Client:           client,
				CreateKey:        true,
				KeyName:          "new-key",
				Backend:          "transit",
				CacheSize:        1,
				DaysPast:         1,
				DaysFuture:       1,
				DailyKeyInterval: 24 * time.Hour,
			},
		},
		"use existing key": {
			config: ProviderConfig{
				Client:           client,
				KeyName:          testKeyName,
				Backend:          "transit",
				CacheSize:        1,
				DaysPast:         1,
				DaysFuture:       1,
				DailyKeyInterval: 24 * time.Hour,
			},
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
				Backend:          "transit",
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
				Backend:          "transit",
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
				Backend:          "transit",
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
				Backend:          "transit",
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
				Backend:          "transit",
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
				Backend:          "transit",
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
				Backend:          "transit",
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
				Backend:          "transit",
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
				Backend:          "transit",
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
				Backend:          "transit",
				CacheSize:        1,
				DaysPast:         0,
				DaysFuture:       0,
				DailyKeyInterval: 24 * time.Hour,
			},
		},
		"multiple keys per day": {
			config: ProviderConfig{
				Client:           client,
				KeyName:          testKeyName,
				Backend:          "transit",
				CacheSize:        1,
				DaysPast:         1,
				DaysFuture:       1,
				DailyKeyInterval: time.Hour,
			},
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

				resp, err := client.Logical().Read("transit/keys/" + tc.config.KeyName)
				require.NoError(t, err)
				require.NotNil(t, resp)
			}
		})
	}
}

func TestGetKeyPair_scheduledKeyProvider(t *testing.T) {
	client := providerTestSetup(t)

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
				Backend:          "transit",
				KeyName:          testKeyName,
				CacheSize:        1,
			})
			require.NoError(t, err)

			key, err := provider.GetKeyPair()
			require.NoError(t, err)
			require.NotEmpty(t, key)
		})
	}
}

func TestDecryptKeyPair_scheduledKeyProvider(t *testing.T) {
	client := providerTestSetup(t)

	provider, err := NewScheduledKeyProvider(ProviderConfig{
		DailyKeyInterval: 24 * time.Hour,
		Client:           client,
		Backend:          "transit",
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
