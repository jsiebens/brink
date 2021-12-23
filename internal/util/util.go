package util

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/klauspost/compress/zstd"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"io"
	"net/url"
)

func NormalizeConnectUrl(input string) (*url.URL, error) {

	normalizeUrl := func(u *url.URL) (*url.URL, error) {
		switch u.Scheme {
		case "http":
			u.Scheme = "ws"
		case "https":
			u.Scheme = "wss"
		case "wss", "ws":
		default:
			u.Scheme = "wss"
		}

		return u, nil
	}

	ok, u := isValidUrl(input)
	if ok {
		return normalizeUrl(u)
	}
	ok, u = isValidUrl("wss://" + input)
	if ok {
		return normalizeUrl(u)
	}

	return nil, fmt.Errorf("invalid target")
}

func NormalizeProxyUrl(input string) (*url.URL, error) {

	normalizeUrl := func(u *url.URL) (*url.URL, error) {
		switch u.Scheme {
		case "ws":
			u.Scheme = "http"
		case "wss":
			u.Scheme = "https"
		case "https", "http":
		default:
			u.Scheme = "https"
		}

		return u, nil
	}

	ok, u := isValidUrl(input)
	if ok {
		return normalizeUrl(u)
	}
	ok, u = isValidUrl("wss://" + input)
	if ok {
		return normalizeUrl(u)
	}

	return nil, fmt.Errorf("invalid target")
}

// isValidUrl tests a string to determine if it is a well-structured url or not.
func isValidUrl(toTest string) (bool, *url.URL) {
	_, err := url.ParseRequestURI(toTest)
	if err != nil {
		return false, nil
	}

	u, err := url.Parse(toTest)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false, nil
	}

	return true, u
}

func ParseOrGenerateKey(key string) (publicKey, privateKey *[32]byte, err error) {
	if key == "" {
		return box.GenerateKey(rand.Reader)
	}

	publicKey = new([32]byte)
	privateKey = new([32]byte)
	_, err = hex.Decode(privateKey[:], []byte(key))
	if err != nil {
		publicKey = nil
		privateKey = nil
		return
	}

	curve25519.ScalarBaseMult(publicKey, privateKey)
	return
}

func GenerateSessionId() string {
	id := new([24]byte)
	_, err := io.ReadFull(rand.Reader, id[:])
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(id[:])
}

func ParseKey(v string) (*[32]byte, error) {
	b, err := hex.DecodeString(v)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("invalid hex key (%q)", v)
	}

	var key = new([32]byte)
	copy(key[:], b)
	return key, nil
}

func Seal(v interface{}, publicKey, privateKey *[32]byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}

	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, err
	}

	encoded := encoder.EncodeAll(b, nil)

	encrypted := box.Seal(nonce[:], encoded, &nonce, publicKey, privateKey)

	return encrypted, nil
}

func Open(encrypted []byte, v interface{}, publicKey, privateKey *[32]byte) error {
	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])

	decrypted, ok := box.Open(nil, encrypted[24:], &decryptNonce, publicKey, privateKey)
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

	if err := json.Unmarshal(decoded, v); err != nil {
		return err
	}

	return nil
}

func SealBase58(v interface{}, publicKey, privateKey *[32]byte) (string, error) {
	encrypted, err := Seal(v, publicKey, privateKey)
	if err != nil {
		return "", err
	}
	return base58.FastBase58Encoding(encrypted), nil
}

func OpenBase58(msg string, v interface{}, publicKey, privateKey *[32]byte) error {
	encrypted, err := base58.FastBase58Decoding(msg)
	if err != nil {
		return err
	}
	return Open(encrypted, v, publicKey, privateKey)
}

func Checksum(v interface{}) (string, error) {
	marshal, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := md5.Sum(marshal)
	return hex.EncodeToString(sum[:]), nil
}
