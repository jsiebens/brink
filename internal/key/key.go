package key

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/kelindar/binary"
	"github.com/klauspost/compress/zstd"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"io"
)

func GeneratePrivateKey() (*PrivateKey, error) {
	_, key, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{k: *key}, nil
}

func ParsePrivateKey(key string) (*PrivateKey, error) {
	k := new([32]byte)
	err := parseHex(k[:], key)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{k: *k}, nil
}

func ParsePublicKey(key string) (*PublicKey, error) {
	k := new([32]byte)
	err := parseHex(k[:], key)
	if err != nil {
		return nil, err
	}
	return &PublicKey{k: *k}, nil
}

func parseHex(out []byte, v string) error {
	in := []byte(v)

	if want := len(out) * 2; len(in) != want {
		return fmt.Errorf("key hex has the wrong size, got %d want %d", len(in), want)
	}

	_, err := hex.Decode(out[:], in)
	if err != nil {
		return err
	}

	return nil
}

type PrivateKey struct {
	k [32]byte
}

type PublicKey struct {
	k [32]byte
}

func (k PrivateKey) Public() PublicKey {
	var ret PublicKey
	curve25519.ScalarBaseMult(&ret.k, &k.k)
	return ret
}

func (k PrivateKey) SealBase58(p PublicKey, v interface{}) (string, error) {
	ciphertext, err := k.Seal(p, v)
	if err != nil {
		return "", err
	}
	return base58.FastBase58Encoding(ciphertext), nil
}

func (k PrivateKey) Seal(p PublicKey, v interface{}) ([]byte, error) {
	b, err := binary.Marshal(v)
	if err != nil {
		return nil, err
	}

	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, err
	}

	encoded := encoder.EncodeAll(b, nil)

	return k.sealTo(p, encoded), nil
}

func (k PrivateKey) sealTo(p PublicKey, cleartext []byte) (ciphertext []byte) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}

	return box.Seal(nonce[:], cleartext, &nonce, &p.k, &k.k)
}

func (k PrivateKey) OpenBase58(p PublicKey, msg string, v interface{}) error {
	ciphertext, err := base58.FastBase58Decoding(msg)
	if err != nil {
		return err
	}

	return k.Open(p, ciphertext, v)
}

func (k PrivateKey) Open(p PublicKey, ciphertext []byte, v interface{}) error {
	decrypted, ok := k.openFrom(p, ciphertext)
	if !ok {
		return fmt.Errorf("decryption error")
	}

	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return err
	}

	decoded, err := decoder.DecodeAll(decrypted, nil)
	if err != nil {
		return err
	}

	if err := binary.Unmarshal(decoded, v); err != nil {
		return err
	}

	return nil
}

func (k PrivateKey) openFrom(p PublicKey, ciphertext []byte) (cleartext []byte, ok bool) {
	if len(ciphertext) < 24 {
		return nil, false
	}
	var nonce [24]byte
	copy(nonce[:], ciphertext)
	return box.Open(nil, ciphertext[len(nonce):], &nonce, &p.k, &k.k)
}

func (k PrivateKey) String() string {
	return hex.EncodeToString(k.k[:])
}

func (k PrivateKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.k)
}

func (k *PrivateKey) UnmarshalJSON(bs []byte) error {
	return json.Unmarshal(bs, &k.k)
}

func (k PublicKey) String() string {
	return hex.EncodeToString(k.k[:])
}

func (k PublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.k)
}

func (k *PublicKey) UnmarshalJSON(bs []byte) error {
	return json.Unmarshal(bs, &k.k)
}
