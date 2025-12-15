// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package envelope

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/golang/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
)

var MAGIC = []byte("VEE✉")

const (
	VERSION       = 1
	algorithmName = "OAE2-AES256-GCM96-HKDF"
)

func NewHeader() *Header {
	return &Header{
		Version: VERSION,
		Data: &Header_V1{
			V1: &HeaderV1{
				KeyData: &KeyData{},
			},
		},
	}
}

func NewEncryptingWriter(kp KeyProvider, dest io.Writer, header *Header, aad []byte) (io.WriteCloser, error) {
	if header == nil {
		header = NewHeader()
	}
	if kp == nil {
		return nil, fmt.Errorf("key provider was nil")
	}

	if dest == nil {
		return nil, fmt.Errorf("writer was nil")
	}

	if header == nil {
		return nil, fmt.Errorf("header was nil")
	}

	keyPair, err := kp.GetKeyPair()
	if err != nil {
		return nil, fmt.Errorf("error getting key pair: %v", err)
	}

	keyData := kp.GetKeyData()
	keyData.Edk = keyPair.EDK
	keyData.KeyVersion = uint32(keyPair.KeyVersion)
	header.GetV1().KeyData = &keyData

	headerBytes, err := proto.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("error marshalling header: %v", err)
	}

	_, err = dest.Write(MAGIC)
	if err != nil {
		return nil, fmt.Errorf("error writing magic value: %v", err)
	}

	_, err = dest.Write(headerBytes)
	if err != nil {
		return nil, fmt.Errorf("error writing header: %v", err)
	}

	aead, err := subtle.NewAESGCMHKDF(keyPair.DEK, "SHA256", len(keyPair.DEK), 1048576, 0)
	if err != nil {
		return nil, fmt.Errorf("error creating aead: %v", err)
	}

	w, err := aead.NewEncryptingWriter(dest, aad)
	if err != nil {
		return nil, fmt.Errorf("error creating writer: %v", err)
	}

	return w, nil
}

func NewDecryptingReader(kp KeyProvider, src io.Reader, aad []byte, length *uint64, headerOut chan *Header) (io.Reader, error) {
	if kp == nil {
		return nil, fmt.Errorf("key provider was nil")
	}

	if src == nil {
		return nil, fmt.Errorf("reader was nil")
	}

	if length == nil {
		return nil, fmt.Errorf("length was nil")
	}

	if headerOut == nil {
		return nil, fmt.Errorf("header channel was nil")
	}

	header, err := ReadHeader(src, length)
	if err != nil {
		return nil, err
	}

	select {
	case headerOut <- header:
	default:
	}

	key, err := kp.DecryptKeyPair(fmt.Sprintf("vault:v%d:%s", header.GetV1().KeyData.KeyVersion, base64.StdEncoding.EncodeToString(header.GetV1().KeyData.Edk)))
	if err != nil {
		return nil, fmt.Errorf("error decrypting key: %v", err)
	}

	aead, err := subtle.NewAESGCMHKDF(key, "SHA256", len(key), 1048576, 0)
	if err != nil {
		return nil, fmt.Errorf("error creating aead: %v", err)
	}

	r, err := aead.NewDecryptingReader(src, aad)
	if err != nil {
		return nil, fmt.Errorf("error creating reader: %v", err)
	}

	return r, nil
}

func ReadHeader(src io.Reader, length *uint64) (*Header, error) {
	magicBytes := make([]byte, len(MAGIC))
	_, err := src.Read(magicBytes)
	if err != nil {
		return nil, fmt.Errorf("error reading magic value: %v", err)
	}
	if !bytes.Equal(magicBytes, MAGIC) {
		return nil, fmt.Errorf("invalid envelope encryption magic value")
	}

	headerLen := *length
	headerBytes := make([]byte, headerLen)
	_, err = src.Read(headerBytes)
	if err != nil {
		return nil, fmt.Errorf("error reading header: %v", err)
	}

	header := &Header{}
	err = proto.Unmarshal(headerBytes, header)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling header: %v", err)
	}
	return header, nil
}
