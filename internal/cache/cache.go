package cache

import (
	"encoding/json"
	"github.com/patrickmn/go-cache"
	"time"
)

type Cache interface {
	Set(id string, v interface{}) error
	Get(id string, v interface{}) (bool, error)
	Delete(id string) error
}

func NewMemoryCache() Cache {
	return &MemoryCache{
		cache: cache.New(10*time.Minute, 5*time.Minute),
	}
}

type MemoryCache struct {
	cache *cache.Cache
}

func (m *MemoryCache) Set(id string, v interface{}) error {
	msg, err := json.Marshal(v)
	if err != nil {
		return err
	}
	m.cache.Set(id, msg, cache.DefaultExpiration)
	return nil
}

func (m *MemoryCache) Get(id string, v interface{}) (bool, error) {
	msg, b := m.cache.Get(id)

	if !b {
		return b, nil
	}

	return true, json.Unmarshal(msg.([]byte), v)
}

func (m *MemoryCache) Delete(id string) error {
	m.cache.Delete(id)
	return nil
}
