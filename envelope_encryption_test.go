// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package envelope

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
)

func TestNewEncryptingWriter(t *testing.T) {
	t.Parallel()

	client, backend := providerTestSetup(t)

	dir, err := os.MkdirTemp("", "streamingaead")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	keyName := testKeyName

	provider, err := NewTransitKeyProvider(ProviderConfig{
		Client:    client,
		CacheSize: 1,
		KeyName:   keyName,
		Backend:   backend,
	})
	require.NoError(t, err)

	scheduledProvider, err := NewScheduledKeyProvider(ProviderConfig{
		Client:           client,
		CacheSize:        1,
		KeyName:          keyName,
		Backend:          backend,
		DaysPast:         1,
		DaysFuture:       1,
		DailyKeyInterval: time.Hour * 24,
	})
	require.NoError(t, err)

	ciphertextFile, err := os.Create(filepath.Join(dir, "ciphertext"))
	require.NoError(t, err)

	testCases := map[string]struct {
		provider    KeyProvider
		header      *Header
		writer      io.Writer
		aad         []byte
		expectError bool
	}{
		"nil provider": {
			header: &Header{
				Data: &Header_V1{
					V1: &HeaderV1{
						KeyData: &KeyData{
							MountPath: &backend,
							KeyName:   &keyName,
						},
					},
				},
			},
			writer:      ciphertextFile,
			expectError: true,
		},
		"nil writer": {
			provider: provider,
			header: &Header{
				Data: &Header_V1{
					V1: &HeaderV1{
						KeyData: &KeyData{
							MountPath: &backend,
							KeyName:   &keyName,
						},
					},
				},
			},
			expectError: true,
		},
		"nil header": {
			provider:    provider,
			writer:      ciphertextFile,
			expectError: true,
		},
		"empty aad": {
			provider: provider,
			header: &Header{
				Data: &Header_V1{
					V1: &HeaderV1{
						KeyData: &KeyData{
							MountPath: &backend,
							KeyName:   &keyName,
						},
					},
				},
			},
			writer: ciphertextFile,
		},
		"key provider": {
			provider: provider,
			header: &Header{
				Data: &Header_V1{
					V1: &HeaderV1{
						KeyData: &KeyData{
							MountPath: &backend,
							KeyName:   &keyName,
						},
					},
				},
			},
			writer: ciphertextFile,
			aad:    []byte("test aad"),
		},
		"scheduled key provider": {
			provider: scheduledProvider,
			header: &Header{
				Data: &Header_V1{
					V1: &HeaderV1{
						KeyData: &KeyData{
							MountPath: &backend,
							KeyName:   &keyName,
						},
					},
				},
			},
			writer: ciphertextFile,
			aad:    []byte("test aad"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			w, err := NewEncryptingWriter(tc.provider, tc.writer, tc.header, tc.aad)
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, w)
			}
		})
	}
}

func TestNewDecryptingReader(t *testing.T) {
	t.Parallel()

	client, backend := providerTestSetup(t)

	dir, err := os.MkdirTemp("", "streamingaead")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	keyName := testKeyName

	provider, err := NewTransitKeyProvider(ProviderConfig{
		Client:    client,
		CacheSize: 1,
		KeyName:   keyName,
		Backend:   backend,
	})
	require.NoError(t, err)

	scheduledProvider, err := NewScheduledKeyProvider(ProviderConfig{
		Client:           client,
		CacheSize:        1,
		KeyName:          keyName,
		Backend:          backend,
		DaysPast:         1,
		DaysFuture:       1,
		DailyKeyInterval: time.Hour * 24,
	})
	require.NoError(t, err)

	ciphertextPath := filepath.Join(dir, "ciphertext")

	testCases := map[string]struct {
		provider    KeyProvider
		path        string
		aad         []byte
		expectError bool
	}{
		"empty-aad": {
			provider: provider,
			path:     ciphertextPath,
		},
		"key-provider": {
			provider: provider,
			path:     ciphertextPath,
			aad:      []byte("test aad"),
		},
		"scheduled-key-provider": {
			provider: scheduledProvider,
			path:     ciphertextPath,
			aad:      []byte("test aad"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			key, err := provider.GetKeyPair()
			require.NoError(t, err)

			headerLen := createCiphertext(t, backend, ciphertextPath+name, key)

			ciphertextFile, err := os.Open(ciphertextPath + name)
			require.NoError(t, err)

			defer ciphertextFile.Close()

			headerChannel := make(chan *Header, 1)
			reader, err := NewDecryptingReader(tc.provider, ciphertextFile, tc.aad, &headerLen, headerChannel)
			require.NoError(t, err)
			require.NotNil(t, reader)
		})
	}
}

func TestNewDecryptingReader_errorCases(t *testing.T) {
	t.Parallel()

	client, backend := providerTestSetup(t)

	dir, err := os.MkdirTemp("", "streamingaead")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	keyName := testKeyName

	provider, err := NewTransitKeyProvider(ProviderConfig{
		Client:    client,
		CacheSize: 1,
		KeyName:   keyName,
		Backend:   backend,
	})
	require.NoError(t, err)

	ciphertextFile, err := os.Create(filepath.Join(dir, "ciphertext"))
	require.NoError(t, err)
	defer ciphertextFile.Close()

	header := &Header{
		Data: &Header_V1{
			V1: &HeaderV1{
				KeyData: &KeyData{
					MountPath: &backend,
					KeyName:   &keyName,
				},
			},
		},
	}
	headerBytes, err := proto.Marshal(header)
	require.NoError(t, err)

	headerLen := uint64(len(headerBytes))

	testCases := map[string]struct {
		provider      KeyProvider
		headerChannel chan *Header
		reader        io.Reader
		headerLen     *uint64
		aad           []byte
		expectedError string
	}{
		"nil provider": {
			reader:        ciphertextFile,
			headerChannel: make(chan *Header, 1),
			headerLen:     &headerLen,
			expectedError: "key provider was nil",
		},
		"nil reader": {
			provider:      provider,
			headerChannel: make(chan *Header),
			headerLen:     &headerLen,
			expectedError: "reader was nil",
		},
		"nil channel": {
			provider:      provider,
			reader:        ciphertextFile,
			headerLen:     &headerLen,
			expectedError: "header channel was nil",
		},
		"nil length": {
			provider:      provider,
			reader:        ciphertextFile,
			headerChannel: make(chan *Header),
			expectedError: "length was nil",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := NewDecryptingReader(tc.provider, tc.reader, tc.aad, tc.headerLen, tc.headerChannel)
			require.Error(t, err)
			require.Equal(t, tc.expectedError, err.Error())
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	t.Parallel()

	client, backend := providerTestSetup(t)

	provider, err := NewTransitKeyProvider(ProviderConfig{
		Client:    client,
		CacheSize: 1,
		KeyName:   testKeyName,
		Backend:   backend,
	})
	require.NoError(t, err)

	testEncryptDecryptWithProvider(t, backend, provider)

	scheduledProvider, err := NewScheduledKeyProvider(ProviderConfig{
		Client:           client,
		CacheSize:        1,
		KeyName:          testKeyName,
		Backend:          backend,
		DaysPast:         1,
		DaysFuture:       1,
		DailyKeyInterval: time.Hour * 24,
	})
	require.NoError(t, err)

	testEncryptDecryptWithProvider(t, backend, scheduledProvider)
}

func testEncryptDecryptWithProvider(t *testing.T, backend string, provider KeyProvider) {
	dir, err := os.MkdirTemp("", "streamingaead")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	plaintext := []byte("test plaintext")

	keyName := testKeyName

	aad := []byte("test aad")

	header := &Header{
		Data: &Header_V1{
			V1: &HeaderV1{
				KeyData: &KeyData{
					MountPath: &backend,
					KeyName:   &keyName,
				},
			},
		},
	}

	ciphertextFile, err := os.Create(filepath.Join(dir, "ciphertext"))
	require.NoError(t, err)

	w, err := NewEncryptingWriter(provider, ciphertextFile, header, aad)
	require.NoError(t, err)

	_, err = w.Write(plaintext)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.NoError(t, ciphertextFile.Close())

	require.NotEmpty(t, header.GetV1().KeyData.Edk)

	headerBytes, err := proto.Marshal(header)
	require.NoError(t, err)
	headerLen := uint64(len(headerBytes))

	ciphertextFile, err = os.Open(filepath.Join(dir, "ciphertext"))
	require.NoError(t, err)

	c := make(chan *Header, 1)
	r, err := NewDecryptingReader(provider, ciphertextFile, aad, &headerLen, c)
	require.NoError(t, err)

	var readHeader *Header
	select {
	case readHeader = <-c:
	default:
	}

	require.NotNil(t, readHeader)
	require.Equal(t, keyName, *readHeader.GetV1().KeyData.KeyName)
	require.Equal(t, backend, *readHeader.GetV1().KeyData.MountPath)
	require.Equal(t, header.GetV1().KeyData.Edk, readHeader.GetV1().KeyData.Edk)

	data, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, data, plaintext)

	require.NoError(t, ciphertextFile.Close())
}

func createCiphertext(t *testing.T, backend, fileName string, key *KeyPair) uint64 {
	keyName := testKeyName

	header := &Header{
		Data: &Header_V1{
			V1: &HeaderV1{
				KeyData: &KeyData{
					MountPath: &backend,
					KeyName:   &keyName,
					Edk:       []byte(key.EDK),
				},
			},
		},
	}
	headerBytes, err := proto.Marshal(header)
	require.NoError(t, err)

	headerLen := uint64(len(headerBytes))

	ciphertextFile, err := os.Create(fileName)
	require.NoError(t, err)

	_, err = ciphertextFile.Write(MAGIC)
	require.NoError(t, err)

	_, err = ciphertextFile.Write(headerBytes)
	require.NoError(t, err)

	aead, err := subtle.NewAESGCMHKDF(key.DEK, "SHA256", 32, 1048576, 0)
	require.NoError(t, err)

	w, err := aead.NewEncryptingWriter(ciphertextFile, []byte(""))
	require.NoError(t, err)

	_, err = w.Write([]byte("test-ciphertext"))
	require.NoError(t, err)

	require.NoError(t, ciphertextFile.Close())

	return headerLen
}
