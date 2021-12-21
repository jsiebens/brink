package client

import (
	"errors"
	"fmt"
	"github.com/zalando/go-keyring"
)

func (c *Client) loadAuthToken(proxy string) (string, error) {
	token, err := keyring.Get(fmt.Sprintf("proxiro - %s", proxy), "default")
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return "", err
	}
	return token, nil
}

func (c *Client) storeAuthToken(proxy, token string) error {
	return keyring.Set(fmt.Sprintf("proxiro - %s", proxy), "default", token)
}
