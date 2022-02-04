package client

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/99designs/keyring"
	"os"
)

func createKeyName(proxy string) string {
	sum := md5.Sum([]byte(proxy))
	x := hex.EncodeToString(sum[:])
	return fmt.Sprintf("brink:%s", x)
}

func LoadAuthToken(proxy string) (string, func(string, string) error, error) {
	ignore := func(x, y string) error { return nil }

	envToken := os.Getenv("BRINK_AUTH_TOKEN")

	if envToken != "" {
		return envToken, ignore, nil
	}

	ring, err := openKeyring()
	if err != nil {
		return "", StoreAuthToken, err
	}

	token, err := ring.Get(createKeyName(proxy))
	if err != nil && !errors.Is(err, keyring.ErrKeyNotFound) {
		return "", StoreAuthToken, err
	}

	return string(token.Data), StoreAuthToken, nil
}

func StoreAuthToken(proxy, token string) error {
	ring, err := openKeyring()
	if err != nil {
		return err
	}

	return ring.Set(keyring.Item{
		Key:  createKeyName(proxy),
		Data: []byte(token),
	})
}

func DeleteAuthToken(proxy string) error {
	ring, err := openKeyring()
	if err != nil {
		return err
	}

	return ring.Remove(createKeyName(proxy))
}

func openKeyring() (keyring.Keyring, error) {
	return keyring.Open(keyring.Config{
		LibSecretCollectionName: "login",
		PassPrefix:              "brink",
		AllowedBackends: []keyring.BackendType{
			keyring.WinCredBackend,
			keyring.KeychainBackend,
			keyring.SecretServiceBackend,
			keyring.KWalletBackend,
			keyring.PassBackend,
		},
	})
}
