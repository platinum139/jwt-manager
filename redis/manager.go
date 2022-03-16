package rds

import (
    "context"
    "fmt"
    "github.com/go-redis/redis/v8"
    "log"
    "time"
)

type RedisConfig struct {
    Host     string
    Port     string
    Password string
}

type Manager struct {
    ctx    context.Context
    log    *log.Logger
    client *redis.Client
}

func (manager *Manager) StoreToken(userId, token string, ttl int) error {
    key := fmt.Sprintf("refresh:%s:%s", userId, token)
    return manager.client.Set(manager.ctx, key, 0, time.Duration(ttl)*time.Minute).Err()
}

func (manager *Manager) TokenExists(userId, token string) (bool, error) {
    key := fmt.Sprintf("refresh:%s:%s", userId, token)
    err := manager.client.Get(manager.ctx, key).Err()
    if err == redis.Nil {
        return false, nil
    }
    if err != nil {
        return false, err
    }
    return true, nil
}

func (manager *Manager) DeleteToken(userId, token string) error {
    key := fmt.Sprintf("refresh:%s:%s", userId, token)
    return manager.client.Del(manager.ctx, key).Err()
}

func NewRedisManager(ctx context.Context, log *log.Logger, config *RedisConfig) *Manager {
    log.SetPrefix("[NewRedisManager]")

    redisClient := redis.NewClient(&redis.Options{
        Addr:     config.Host + ":" + config.Port,
        Password: config.Password,
    })
    _, err := redisClient.Ping(ctx).Result()
    if err != nil {
        log.Printf("cannot create redis client: %s\n", err)
    }
    return &Manager{
        ctx:    ctx,
        log:    log,
        client: redisClient,
    }
}
