package config

import (
	"gopkg.in/yaml.v3"
	"os"
)

type Config struct {
	LDAP struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"ldap"`

	Audit struct {
		InactiveDays int `yaml:"inactive_days"`
	} `yaml:"audit"`

	Report struct {
		Output string `yaml:"output"`
	} `yaml:"report"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
