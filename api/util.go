package api

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/xdire/xlb-poc/entity"
	"github.com/xdire/xlb-poc/storage"
	"github.com/xdire/xlb-poc/tlssec"
	"net/http"
	"strings"
)

func AuthnCredentials(r *http.Request, db storage.IManagerBackend) (*entity.Client, error) {
	id, key, ok := r.BasicAuth()
	if ok {
		client, err := db.GetClient(id)
		if err != nil {
			return nil, err
		}
		if client.Key == key {
			return client, nil
		}
	}
	return nil, fmt.Errorf("no authentication provided")
}

func AuthzToken(r *http.Request, bundle *tlssec.TLSBundle) (string, error) {

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("auth header empty")
	}

	var token string
	// Check if Bearer if present
	if strings.HasPrefix(authHeader, "Bearer ") {
		// Extract the token part after "Bearer "
		token = strings.TrimPrefix(authHeader, "Bearer ")
	}

	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return bundle.PublicKey, nil
	})

	if err != nil {
		return "", fmt.Errorf("invalid authorization token, error: %w", err)
	}

	if !tok.Valid {
		return "", fmt.Errorf("invalid authorization token")
	}

	if subj, err := claims.GetSubject(); err != nil {
		return "", fmt.Errorf("cannot extract subject from")
	} else {
		return subj, nil
	}

}

func WriteOk(writer http.ResponseWriter) {
	WriteResponse(writer, 0, struct{}{})
}

func WriteError(w http.ResponseWriter, code int, body string) {
	WriteResponse(w, code, struct {
		Error string `json:"error"`
	}{
		Error: body,
	})
}

func WriteResponse(w http.ResponseWriter, status int, obj interface{}) {
	var body []byte
	var err error
	// Try to do interface conversion to WKT
	if obj != nil {
		if casted, ok := obj.(string); ok {
			body = []byte(casted)
		} else {
			// Give a try for a json conversion
			body, err = json.Marshal(obj)
			if err != nil {
				status = http.StatusServiceUnavailable
				obj = struct{ error string }{"cannot marshal json"}
				body, _ = json.Marshal(obj)
			}
		}
	} else {
		body = []byte{}
	}
	// See if there is an error
	if status > 0 {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
		return
	}
	// Status was undefined, treat it as OK
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
