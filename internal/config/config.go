package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config contains runtime configuration values.
type Config struct {
	Environment          string
	HTTPPort             string
	DatabaseURL          string
	AccessTokenTTL       time.Duration
	RefreshTokenTTL      time.Duration
	RefreshTokenBytes    int
	ServiceName          string
	RateLimitRPM         int
	TelemetryEndpoint    string
	TelemetryInsecure    bool
	CORSAllowedOrigins   []string
	CORSAllowedMethods   []string
	CORSAllowedHeaders   []string
	CORSAllowCredentials bool
}

// Load reads configuration from environment variables with sane defaults.
func Load() (Config, error) {
	cfg := Config{
		Environment:          getEnv("APP_ENV", "development"),
		HTTPPort:             getEnv("HTTP_PORT", "8080"),
		DatabaseURL:          os.Getenv("DATABASE_URL"),
		AccessTokenTTL:       getDuration("ACCESS_TOKEN_TTL", time.Hour),
		RefreshTokenTTL:      getDuration("REFRESH_TOKEN_TTL", 30*24*time.Hour),
		RefreshTokenBytes:    getInt("REFRESH_TOKEN_BYTES", 32),
		ServiceName:          getEnv("SERVICE_NAME", "smallbiznis-auth"),
		RateLimitRPM:         getInt("RATE_LIMIT_RPM", 600),
		TelemetryEndpoint:    os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		TelemetryInsecure:    getBool("OTEL_EXPORTER_OTLP_INSECURE", true),
		CORSAllowedOrigins:   getList("CORS_ALLOWED_ORIGINS", []string{"*"}),
		CORSAllowedMethods:   getList("CORS_ALLOWED_METHODS", []string{"GET", "POST", "OPTIONS"}),
		CORSAllowedHeaders:   getList("CORS_ALLOWED_HEADERS", []string{"Authorization", "Content-Type"}),
		CORSAllowCredentials: getBool("CORS_ALLOW_CREDENTIALS", false),
	}

	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}

	if cfg.RefreshTokenBytes < 32 {
		cfg.RefreshTokenBytes = 32
	}

	return cfg, nil
}

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func getDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return def
}

func getInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
	}
	return def
}

func getBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		switch strings.ToLower(v) {
		case "1", "true", "t", "yes", "y", "on":
			return true
		case "0", "false", "f", "no", "n", "off":
			return false
		}
	}
	return def
}

func getList(key string, def []string) []string {
	if v, ok := os.LookupEnv(key); ok {
		parts := strings.Split(v, ",")
		var cleaned []string
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				cleaned = append(cleaned, trimmed)
			}
		}
		if len(cleaned) > 0 {
			return cleaned
		}
	}
	return def
}
