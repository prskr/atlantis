package auth

import (
	"context"
	"crypto/cipher"
	"errors"
	"net/http"
	"net/url"
	"vendor/golang.org/x/crypto/chacha20poly1305"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/runatlantis/atlantis/server/logging"
	"golang.org/x/oauth2"
)

const (
	TokenCookieName = "IDToken"
)

var _ Validator = (*OIDC)(nil)

func NewOIDC(
	ctx context.Context,
	logging logging.SimpleLogging,
	issuerURL, clientID, clientSecret string,
	cookieSecret []byte,
	additionalScopes []string,
) (*OIDC, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, err
	}

	cookieCipher, err := chacha20poly1305.NewX(cookieSecret)
	if err != nil {
		return nil, err
	}

	return &OIDC{
		Logger:           logging,
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		AdditionalScopes: additionalScopes,

		cookieCipher: cookieCipher,
		verifier:     provider.Verifier(&oidc.Config{ClientID: clientID}),
		provider:     provider,
	}, nil
}

type OIDC struct {
	Logger           logging.SimpleLogging
	ClientID         string
	ClientSecret     string
	UsePKCE          bool
	AdditionalScopes []string

	cookieCipher cipher.AEAD
	verifier     *oidc.IDTokenVerifier
	provider     *oidc.Provider
}

// Authenticate implements Validator.
func (o OIDC) Authenticate(writer http.ResponseWriter, req *http.Request) (success bool) {
	cookie, err := req.Cookie(TokenCookieName)
	if err != nil && errors.Is(err, http.ErrNoCookie) {
		o.initiateLogin(writer, req)
		return false
	}

	cookieValueBytes := []byte(cookie.Value)

	openedToken, err := o.cookieCipher.Open(
		nil,
		cookieValueBytes[:chacha20poly1305.NonceSizeX],
		cookieValueBytes[chacha20poly1305.NonceSizeX:],
		nil,
	)
	if err != nil {
		o.Logger.Err("Failed to decrypt token", "error", err)
		return false
	}

	tokenString := string(openedToken)
	_, err = o.verifier.Verify(req.Context(), tokenString)
	if err != nil {
		o.Logger.Err("Failed to verify token", "error", err)
		return false
	}

	return true
}

func (o OIDC) initiateLogin(writer http.ResponseWriter, req *http.Request) {
	// TODO check well known x-forwarded-XYZ headers (scheme, host)
	redirectURL := &url.URL{
		Scheme: req.URL.Scheme,
		Host:   req.URL.Host,
		Path:   "/auth/oidc/callback",
	}

	oauth2Config := &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		RedirectURL:  redirectURL.String(),
		Scopes:       append([]string{oidc.ScopeOpenID}, o.AdditionalScopes...),
		Endpoint:     o.provider.Endpoint(),
	}

	var authOpts []oauth2.AuthCodeOption

	if o.UsePKCE {
		authOpts = append(authOpts, oauth2.S256ChallengeOption(""))
	}

	// TODO: protect original URL in state with XChaCha20Poly1305
	http.Redirect(
		writer,
		req,
		oauth2Config.AuthCodeURL("", authOpts...),
		http.StatusSeeOther,
	)
}
