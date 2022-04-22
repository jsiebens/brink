package util

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
)

func StripScheme(input string) string {
	ok, u := isValidUrl(input)
	if ok {
		return u.Host
	}
	ok, u = isValidUrl("wss://" + input)
	if ok {
		return u.Host
	}

	return ""
}

func NormalizeHttpUrl(input string) (string, error) {

	normalizeUrl := func(u *url.URL) (string, error) {
		switch u.Scheme {
		case "ws":
			u.Scheme = "http"
		case "wss":
			u.Scheme = "https"
		case "https", "http":
		default:
			u.Scheme = "https"
		}

		return u.String(), nil
	}

	ok, u := isValidUrl(input)
	if ok {
		return normalizeUrl(u)
	}
	ok, u = isValidUrl("wss://" + input)
	if ok {
		return normalizeUrl(u)
	}

	return "", fmt.Errorf("invalid url [%s]", input)
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

func GenerateSessionId() string {
	id := new([6]byte)
	_, err := io.ReadFull(rand.Reader, id[:])
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(id[:])
}

func Checksum(v interface{}) (string, error) {
	marshal, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := md5.Sum(marshal)
	return hex.EncodeToString(sum[:]), nil
}
