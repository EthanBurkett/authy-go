package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	AppName     string    `mapstructure:"app_name"`
	Environment string    `mapstructure:"environment"`
	JWT         JWTConfig `mapstructure:"jwt"`
}

type JWTConfig struct {
	Issuer         string        `mapstructure:"issuer"`
	Audience       string        `mapstructure:"audience"`
	ExpiryDuration time.Duration `mapstructure:"expiry_duration"`
}

func Load(configPath string) (*Config, error) {
	viper.SetConfigFile(configPath)

	viper.SetDefault("jwt.expiry_duration", "15m")

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}
