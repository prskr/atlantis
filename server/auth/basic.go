package auth

import (
	"net/http"

	"github.com/runatlantis/atlantis/server/logging"
)

func NewBasic(
	logging logging.SimpleLogging,
	username, password string,
) Basic {
	return Basic{
		Logger:   logging,
		Username: username,
		Password: password,
	}
}

type Basic struct {
	Logger   logging.SimpleLogging
	Username string
	Password string
}

func (b Basic) Authenticate(writer http.ResponseWriter, req *http.Request) (success bool) {
	user, pass, ok := req.BasicAuth()

	if ok {
		req.SetBasicAuth(user, pass)
		success = user == b.Username && pass == b.Password
	}

	if !success {
		b.Logger.Info("[INVALID] log in attempt: >> url: %s", req.URL.RequestURI())
		writer.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
	} else {
		b.Logger.Debug("[VALID] log in: >> url: %s", req.URL.RequestURI())
	}

	return success
}
