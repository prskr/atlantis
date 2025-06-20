package controllers

import (
	"crypto/cipher"
	"net/http"

	"golang.org/x/crypto/chacha20poly1305"
)

func NewAuthController(cookieSecret []byte) (*AuthController, error) {
	cookieCipher, err := chacha20poly1305.NewX(cookieSecret)
	if err != nil {
		return nil, err
	}

	return &AuthController{
		cookieCipher: cookieCipher,
	}, nil
}

type AuthController struct {
	cookieCipher cipher.AEAD
}

func (ac *AuthController) HandleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	// Implement login logic here
}
