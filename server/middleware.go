// Copyright 2017 HootSuite Media Inc.
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an AS IS BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// Modified hereafter by contributors to runatlantis/atlantis.

package server

import (
	"net/http"
	"strings"

	"github.com/runatlantis/atlantis/server/auth"
	"github.com/runatlantis/atlantis/server/logging"
	"github.com/urfave/negroni/v3"
)

// NewRequestLogger creates a RequestLogger.
func NewRequestLogger(s *Server) *RequestLogger {
	return &RequestLogger{
		logger:            s.Logger,
		WebAuthentication: s.WebAuthentication,
		Validator:         s.AuthValidator,
	}
}

// RequestLogger logs requests and their response codes.
// as well as handle the basicauth on the requests
type RequestLogger struct {
	logger            logging.SimpleLogging
	WebAuthentication bool
	Validator         auth.Validator
}

// ServeHTTP implements the middleware function. It logs all requests at DEBUG level.
func (l *RequestLogger) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	l.logger.Debug("%s %s – from %s", r.Method, r.URL.RequestURI(), r.RemoteAddr)
	allowed := false
	if !l.WebAuthentication ||
		r.URL.Path == "/events" ||
		r.URL.Path == "/healthz" ||
		r.URL.Path == "/status" ||
		strings.HasPrefix(r.URL.Path, "/api/") {
		allowed = true
	} else {
		allowed = l.Validator.Authenticate(rw, r)
	}

	if allowed {
		next(rw, r)
	}

	l.logger.Debug("%s %s – respond HTTP %d", r.Method, r.URL.RequestURI(), rw.(negroni.ResponseWriter).Status())
}
