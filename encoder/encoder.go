package encoder

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"

	"golang.org/x/crypto/scrypt"
)

const P = 1
const KEYLEN = 32

func Encode(saltBase, saltSeparator, signerKey, password string, rounds uint, memcost int) (string, error) {
	// enc := base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

	saltBaseDecoded, err := base64.StdEncoding.DecodeString(saltBase)
	if err != nil {
		return "", err
	}

	saltSeparatorDecoded, err := base64.StdEncoding.DecodeString(saltSeparator)
	if err != nil {
		return "", err
	}

	salt := append(saltBaseDecoded, saltSeparatorDecoded...)

	signerKeyDecoded, err := base64.StdEncoding.DecodeString(signerKey)
	if err != nil {
		return "", err
	}

	cipherKey, err := scrypt.Key([]byte(password), salt, 1<<rounds, memcost, P, KEYLEN)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return "", err
	}

	cipherText := make([]byte, aes.BlockSize+len(signerKeyDecoded))
	nonces := cipherText[:aes.BlockSize]

	stream := cipher.NewCTR(block, nonces)
	stream.XORKeyStream(cipherText[aes.BlockSize:], signerKeyDecoded)

	result := base64.StdEncoding.EncodeToString(cipherText[aes.BlockSize:])
	return result, nil
}
