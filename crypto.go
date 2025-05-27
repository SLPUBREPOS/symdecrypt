package main

import (
//	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

func decrypt(algorithm string, cipherText, key []byte) ([]byte, error) {
	switch algorithm {
	case "aes-ctr":
		return aesCTRDecrypt(cipherText, key)
	default:
		return nil, errors.New("unsupported algorithm")
	}
}

func aesCTRDecrypt(cipherText, key []byte) ([]byte, error) {
	if len(cipherText) < aes.BlockSize {
		return nil, errors.New("cipher text too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := cipherText[:aes.BlockSize]
	data := cipherText[aes.BlockSize:]

	stream := cipher.NewCTR(block, iv)
	plain := make([]byte, len(data))
	stream.XORKeyStream(plain, data)

	return plain, nil
}
