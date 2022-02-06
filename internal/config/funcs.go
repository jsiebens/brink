package config

import (
	"os"
	"strconv"
	"strings"
)

func getBool(key string, defaultValue bool) bool {
	v := os.Getenv(key)
	if len(v) > 0 {
		return strings.ToLower(v) == "true"
	}
	return defaultValue
}

func getInt(key string, defaultValue int) int {
	v := os.Getenv(key)
	if len(v) > 0 {
		i, err := strconv.Atoi(v)
		if err == nil {
			return i
		}
	}
	return defaultValue
}

func getString(key, defaultValue string) string {
	v := os.Getenv(key)
	if v != "" {
		return v
	}
	return defaultValue
}

func getStringArray(key string, defaultValue []string) []string {
	v := os.Getenv(key)
	if v != "" {
		return strings.Split(v, ";")
	}
	return defaultValue
}
