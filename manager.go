package jwt_manager

import (
    "context"
    "encoding/base64"
    "log"
    "math/rand"
    "strings"
    "time"

    "github.com/golang-jwt/jwt"
    "github.com/platinum139/jwt-manager/redis"
)

type JwtConfig struct {
    SecretKey       string
    AccessTokenMin  int
    RefreshTokenMin int
}

type Config struct {
    Jwt   JwtConfig
    Redis rds.RedisConfig
}

type JwtManager struct {
    ctx         context.Context
    log         *log.Logger
    config      Config
    redisClient *rds.Manager
}

func (manager JwtManager) GenerateAccessToken(userID string) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
        Subject:   userID,
        ExpiresAt: time.Now().Add(time.Duration(manager.config.Jwt.AccessTokenMin) * time.Minute).Unix(),
    })
    return token.SignedString([]byte(manager.config.Jwt.SecretKey))
}

func (manager JwtManager) GenerateRefreshToken() (string, error) {
    buf := make([]byte, 32)
    source := rand.NewSource(time.Now().Unix())
    r := rand.New(source)
    _, err := r.Read(buf)
    token := base64.StdEncoding.EncodeToString(buf)
    return strings.TrimRight(token, "="), err
}

func (manager JwtManager) ValidateAccessToken(tokenString string) (string, error) {
    token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{},
        func(token *jwt.Token) (interface{}, error) {
            return []byte(manager.config.Jwt.SecretKey), nil
        })
    if ve, ok := err.(*jwt.ValidationError); ok {
        if ve.Errors&jwt.ValidationErrorExpired != 0 {
            return "", ExpiredTokenError{}
        }
        if ve.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
            return "", InvalidSignatureError{}
        }
    }
    if token != nil {
        if claims, ok := token.Claims.(*jwt.StandardClaims); ok && token.Valid {
            return claims.Subject, nil
        }
    }
    return "", InvalidTokenError{}
}

func (manager JwtManager) ValidateRefreshToken(userId, token string) (bool, error) {
    return manager.redisClient.TokenExists(userId, token)
}

func (manager JwtManager) SaveRefreshToken(userId, token string) error {
    return manager.redisClient.StoreToken(userId, token, manager.config.Jwt.RefreshTokenMin)
}

func (manager JwtManager) DeleteRefreshToken(userId, token string) error {
    return manager.redisClient.DeleteToken(userId, token)
}

func NewJwtManager(ctx context.Context, log *log.Logger, config Config) *JwtManager {
    redisClient := rds.NewRedisManager(ctx, log, &config.Redis)
    return &JwtManager{
        ctx:         ctx,
        log:         log,
        config:      config,
        redisClient: redisClient,
    }
}
