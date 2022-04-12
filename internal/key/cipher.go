package key

import (
	"fmt"
	stream "github.com/nknorg/encrypted-stream"
	"golang.org/x/crypto/nacl/box"
)

type BoxCipher struct {
	privateKey *[32]byte
	publicKey  *[32]byte
}

func NewBoxCipher(pr PrivateKey, pu PublicKey) stream.Cipher {
	return &BoxCipher{
		privateKey: &pr.k,
		publicKey:  &pu.k,
	}
}

// Encrypt implements Cipher.
func (c *BoxCipher) Encrypt(ciphertext, plaintext, nonce []byte) ([]byte, error) {
	var n [24]byte
	copy(n[:], nonce[:24])

	encrypted := box.Seal(ciphertext[:0], plaintext, &n, c.publicKey, c.privateKey)

	return ciphertext[:len(encrypted)], nil
}

// Decrypt implements Cipher.
func (c *BoxCipher) Decrypt(plaintext, ciphertext, nonce []byte) ([]byte, error) {
	var n [24]byte
	copy(n[:], nonce[:24])

	plaintext, ok := box.Open(plaintext[:0], ciphertext, &n, c.publicKey, c.privateKey)
	if !ok {
		return nil, fmt.Errorf("decrypt failed")
	}

	return plaintext, nil
}

// MaxOverhead implements Cipher.
func (c *BoxCipher) MaxOverhead() int {
	return box.Overhead
}

// NonceSize implements Cipher.
func (c *BoxCipher) NonceSize() int {
	return 24
}

func parseKey(key string) (*[32]byte, error) {
	k := new([32]byte)
	err := parseHex(k[:], key)
	if err != nil {
		return nil, err
	}
	return k, nil
}
