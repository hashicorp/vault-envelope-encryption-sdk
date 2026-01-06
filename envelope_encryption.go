// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package envelope

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
)

var MAGIC = []byte("VEE✉")

const (
	VERSION                      = 1
	algorithmName                = "OAE2-AES256-GCM96-HKDF"
	defaultHkdfAlgo              = "SHA256"
	defaultCiphertextSegmentSize = 1024768
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

func NewEncryptingWriter(kp KeyProvider, dest io.Writer, header *Header, aad []byte, length *int64) (io.WriteCloser, error) {
	if header == nil {
		header = NewHeader()
	}
	if length != nil {
		l := uint64(*length)
		header.GetV1().Length = &l
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

	var buffer bytes.Buffer
	_, err = buffer.Write(MAGIC)
	if err != nil {
		return nil, fmt.Errorf("error writing magic value: %v", err)
	}

	headerLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(headerLen, uint32(len(headerBytes)))
	_, err = buffer.Write(headerLen)
	if err != nil {
		return nil, fmt.Errorf("error writing header length: %v", err)
	}
	_, err = buffer.Write(headerBytes)
	if err != nil {
		return nil, fmt.Errorf("error writing header: %v", err)
	}

	_, err = dest.Write(buffer.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error commiting header: %v", err)
	}

	aead, err := setupAead(header, keyPair.DEK)
	if err != nil {
		return nil, fmt.Errorf("error creating aead: %v", err)
	}

	aad = append(buffer.Bytes(), aad...)
	w, err := aead.NewEncryptingWriter(dest, aad)
	if err != nil {
		return nil, fmt.Errorf("error creating writer: %v", err)
	}

	return w, nil
}

func setupAead(header *Header, dek []byte) (*subtle.AESGCMHKDF, error) {
	var hkdfAlg string
	var ciphertextSegmentSize uint32
	if header.GetV1().AlgoParams == nil {
		hkdfAlg = defaultHkdfAlgo
		ciphertextSegmentSize = defaultCiphertextSegmentSize
	} else {
		hkdfAlg = header.GetV1().AlgoParams.HkdfAlgo
		ciphertextSegmentSize = header.GetV1().AlgoParams.CiphertextSegmentSize
	}
	return subtle.NewAESGCMHKDF(dek, hkdfAlg, len(dek), int(ciphertextSegmentSize), 0)
}

func NewDecryptingReader(kp KeyProvider, src io.Reader, aad []byte, length *int64, headerOut chan *Header) (io.Reader, error) {
	if length != nil {
		src = io.LimitReader(src, *length)
	}
	if kp == nil {
		return nil, fmt.Errorf("key provider was nil")
	}

	if src == nil {
		return nil, fmt.Errorf("reader was nil")
	}

	var buffer bytes.Buffer
	tr := io.TeeReader(src, &buffer)

	magicBytes := make([]byte, len(MAGIC))
	_, err := io.ReadFull(tr, magicBytes)
	if err != nil {
		return nil, fmt.Errorf("error reading magic value: %v", err)
	}
	if !bytes.Equal(magicBytes, MAGIC) {
		return nil, fmt.Errorf("invalid envelope encryption magic value")
	}

	headerLen := make([]byte, 4)
	_, err = io.ReadFull(tr, headerLen)
	if err != nil {
		return nil, err
	}

	headerLength := binary.LittleEndian.Uint32(headerLen)

	header, err := ReadHeader(tr, headerLength)
	if err != nil {
		return nil, err
	}

	if headerOut != nil {
		headerOut <- header
	}

	key, err := kp.DecryptKeyPair(fmt.Sprintf("vault:v%d:%s", header.GetV1().KeyData.KeyVersion, base64.StdEncoding.EncodeToString(header.GetV1().KeyData.Edk)))
	if err != nil {
		return nil, fmt.Errorf("error decrypting key: %v", err)
	}

	aead, err := setupAead(header, key)
	if err != nil {
		return nil, fmt.Errorf("error creating aead: %v", err)
	}

	aad = append(buffer.Bytes(), aad...)
	r, err := aead.NewDecryptingReader(src, aad)
	if err != nil {
		return nil, fmt.Errorf("error creating reader: %v", err)
	}

	return r, nil
}

func ReadHeader(src io.Reader, headerLen uint32) (*Header, error) {
	headerBytes := make([]byte, headerLen)
	n, err := src.Read(headerBytes)
	if err != nil {
		return nil, fmt.Errorf("error reading header: %v", err)
	}
	if uint32(n) != headerLen {
		return nil, errors.New("error reading header: not enough bytes in stream")
	}

	header := &Header{}
	err = proto.Unmarshal(headerBytes, header)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling header: %v", err)
	}
	return header, nil
}

func (h *Header) Map() map[string]any {
	rv := make(map[string]any)

	v1 := h.GetV1()
	if len(v1.Algorithm) > 0 {
		rv["algorithm"] = v1.Algorithm
	}
	if v1.Created != nil {
		rv["created"] = v1.Created.AsTime().Format(time.RFC3339)
	}
	if len(v1.Encoding) > 0 {
		rv["encoding"] = v1.Encoding
	}
	if v1.Length != nil {
		rv["length"] = *v1.Length
	}
	if len(v1.MimeType) > 0 {
		rv["mime_type"] = v1.MimeType
	}
	if v1.Metadata != nil {
		rv["metadata"] = v1.Metadata.AsMap()
	}
	if v1.KeyData != nil {
		kd := make(map[string]any)
		if v1.KeyData.Namespace != nil {
			kd["namespace"] = *v1.KeyData.Namespace
		}
		if v1.KeyData.MountPath != nil {
			kd["mount_path"] = *v1.KeyData.MountPath
		}
		if v1.KeyData.KeyVersion != 0 {
			kd["key_version"] = v1.KeyData.KeyVersion
		}
		if v1.KeyData.KeyName != nil {
			kd["key_name"] = *v1.KeyData.KeyName
		}
		rv["key_data"] = kd
	}

	if v1.AlgoParams != nil {
		rv["hkdf_algorithm"] = v1.AlgoParams.HkdfAlgo
		rv["ciphertext_segment_size"] = v1.AlgoParams.CiphertextSegmentSize
	}

	return rv
}
