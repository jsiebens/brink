package cache

import (
	"context"
	"encoding/json"
	rcache "github.com/go-redis/cache/v8"
	"github.com/go-redis/redis/v8"
	"time"
)

func NewRedisCache(address, password string, redisDB, maxRetries int) Cache {
	opts := &redis.Options{
		Addr:       address,
		Password:   password,
		DB:         redisDB,
		MaxRetries: maxRetries,
	}

	client := redis.NewClient(opts)

	return &redisCache{
		client:     client,
		expiration: DefaultExpiration,
		cache:      rcache.New(&rcache.Options{Redis: client}),
	}
}

type redisCache struct {
	expiration time.Duration
	client     *redis.Client
	cache      *rcache.Cache
}

func (r *redisCache) Set(id string, v interface{}) error {
	msg, err := json.Marshal(v)
	if err != nil {
		return err
	}

	return r.cache.Set(&rcache.Item{
		Key:   id,
		Value: msg,
		TTL:   r.expiration,
	})
}

func (r *redisCache) Get(id string, v interface{}) (bool, error) {
	var data []byte
	err := r.cache.Get(context.TODO(), id, &data)

	if err == rcache.ErrCacheMiss {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, json.Unmarshal(data, v)
}

func (r *redisCache) Delete(id string) error {
	return r.cache.Delete(context.TODO(), id)
}
