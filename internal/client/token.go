package client

import (
	"errors"
	"fmt"
	"github.com/zalando/go-keyring"
)

func LoadAuthToken(proxy string) (string, error) {
	token, err := keyring.Get(fmt.Sprintf("proxiro - %s", proxy), "default")
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return "", err
	}
	return token, nil
}

func StoreAuthToken(proxy, token string) error {
	return keyring.Set(fmt.Sprintf("proxiro - %s", proxy), "default", token)
}

func DeleteAuthToken(proxy string) error {
	return keyring.Delete(fmt.Sprintf("proxiro - %s", proxy), "default")
}
