package auth

import "net/http"

type Validator interface {
	Authenticate(writer http.ResponseWriter, req *http.Request) (success bool)
}
