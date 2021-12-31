package cache

import (
	"fmt"
	"github.com/jsiebens/proxiro/internal/config"
	"time"
)

const DefaultExpiration = 10 * time.Minute

type Cache interface {
	Set(id string, v interface{}) error
	Get(id string, v interface{}) (bool, error)
	Delete(id string) error
}

func NewCache(config config.Cache) (Cache, error) {
	switch config.Type {
	case "inmemory":
		return NewMemoryCache(), nil
	case "redis":
		return NewRedisCache(config.RedisAddr, config.RedisPassword, config.RedisDB, 3), nil
	default:
		return nil, fmt.Errorf("invalid cache type [%s]", config.Type)
	}
}

func Prefixed(cache Cache, prefix string) Cache {
	return &prefixedCache{
		prefix: prefix,
		cache:  cache,
	}
}

type prefixedCache struct {
	prefix string
	cache  Cache
}

func (p *prefixedCache) Set(id string, v interface{}) error {
	return p.cache.Set(p.prefix+id, v)
}

func (p *prefixedCache) Get(id string, v interface{}) (bool, error) {
	return p.cache.Get(p.prefix+id, v)
}

func (p *prefixedCache) Delete(id string) error {
	return p.cache.Delete(p.prefix + id)
}
