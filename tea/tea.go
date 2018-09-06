// Package tea implements the basic Tiny Encryption Angorithm.
// PLEASE DO NOT USE THIS LIBRARY IN PRODUCTION!
// Why?
// 1. Because it was implemented out of curiosity, for learning!
// 2. Encrypt do not use any CBC strategy and just encrypt
//    blocks in sequence padded with NUL bytes when needed.
// You have been warned!
package tea

import (
	"fmt"

	"github.com/madlambda/crypt"
)

const (
	// BlockSize in bytes
	BlockSize = 8

	// KeySize in bytes
	KeySize = 16
)

// encodeBlock encodes a block of 64bits into []byte
func encodeBlock(v0, v1 uint32, dst []byte) {
	dst[0] = byte(v0 >> 24)
	dst[1] = byte(v0 >> 16)
	dst[2] = byte(v0 >> 8)
	dst[3] = byte(v0)
	dst[4] = byte(v1 >> 24)
	dst[5] = byte(v1 >> 16)
	dst[6] = byte(v1 >> 8)
	dst[7] = byte(v1 >> 0)
}

// decodeBlock decodes a []byte into a block
func decodeBlock(src []byte) (b0 uint32, b1 uint32) {
	b0 = uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
	b1 = uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
	return
}

// Pad data to BlockSize
func Pad(data []byte) []byte {
	return crypt.Pad(data, BlockSize)
}

// Encrypt data using key. If data is not block aligned, a padding of
// null bytes are added.
func Encrypt(data []byte, key []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size: %d", len(key))
	}

	data = Pad(data[:])

	dst := make([]byte, len(data))
	for i := 0; i < len(data); i += 8 {
		v0, v1 := decodeBlock(data[i : i+8])
		v0, v1 = cryptBlock(v0, v1, key)

		encodeBlock(v0, v1, dst[i:i+8])
	}
	return dst[:], nil
}

// Decrypt data using key.
func Decrypt(data []byte, key []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size: %d", len(key))
	}

	if len(data)%BlockSize != 0 {
		return nil, fmt.Errorf("crypted data is not block size aligned")
	}

	dst := make([]byte, len(data))
	for i := 0; i < len(data); i += 8 {
		v0, v1 := decodeBlock(data[i : i+8])
		v0, v1 = decryptBlock(v0, v1, key)

		encodeBlock(v0, v1, dst[i:i+8])
	}
	return dst[:], nil
}

func cryptBlock(v0, v1 uint32, key []byte) (uint32, uint32) {
	var (
		y            = uint32(v0)
		z            = uint32(v1)
		delta uint32 = 0x9e3779b9
		sum   uint32
		n     uint32 = 32
	)

	k0, k1 := decodeBlock(key[0:8])
	k2, k3 := decodeBlock(key[8:16])

	for n > 0 {
		sum += delta
		y += ((z << 4) + uint32(k0)) ^ (z + sum) ^ ((z >> 5) + uint32(k1))
		z += ((y << 4) + uint32(k2)) ^ (y + sum) ^ ((y >> 5) + uint32(k3))

		n--
	}

	return y, z
}

func decryptBlock(v0, v1 uint32, key []byte) (uint32, uint32) {
	var (
		y            = uint32(v0)
		z            = uint32(v1)
		delta uint32 = 0x9e3779b9
		sum          = delta << 5
		n     uint32 = 32
	)

	k0, k1 := decodeBlock(key[0:8])
	k2, k3 := decodeBlock(key[8:16])

	for n > 0 {
		z -= ((y << 4) + uint32(k2)) ^ (y + sum) ^ ((y >> 5) + uint32(k3))
		y -= ((z << 4) + uint32(k0)) ^ (z + sum) ^ ((z >> 5) + uint32(k1))
		sum -= delta

		n--
	}

	return y, z
}
