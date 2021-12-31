package cache

import (
	"encoding/json"
	"github.com/patrickmn/go-cache"
	"time"
)

func NewMemoryCache() Cache {
	return &memoryCache{
		cache: cache.New(DefaultExpiration, 5*time.Minute),
	}
}

type memoryCache struct {
	cache *cache.Cache
}

func (m *memoryCache) Set(id string, v interface{}) error {
	msg, err := json.Marshal(v)
	if err != nil {
		return err
	}
	m.cache.Set(id, msg, cache.DefaultExpiration)
	return nil
}

func (m *memoryCache) Get(id string, v interface{}) (bool, error) {
	msg, b := m.cache.Get(id)

	if !b {
		return b, nil
	}

	return true, json.Unmarshal(msg.([]byte), v)
}

func (m *memoryCache) Delete(id string) error {
	m.cache.Delete(id)
	return nil
}
