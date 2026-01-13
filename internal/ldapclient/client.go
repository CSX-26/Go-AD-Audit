package ldapclient

import (
	"crypto/tls"
	"fmt"

	"github.com/go-ldap/ldap/v3"

)

type Config struct {
	Host     string
	Port     int 
	Username string
	Password string
}

func ClientConnect(cfg Config) (*ldap.Conn, error) {
	address := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // For testing only
	}

	conn, err := ldap.DialTLS("tcp", address, tlsConfig)
	if err != nil {
		return nil, err
	}

	err = conn.Bind(cfg.Username, cfg.Password)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}
