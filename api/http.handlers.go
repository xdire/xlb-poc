package api

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/xdire/xlb-poc/entity"
	"github.com/xdire/xlb-poc/jwtsec"
	"github.com/xdire/xlb-poc/storage"
	"github.com/xdire/xlb-poc/tlssec"
	"net/http"
	"os"
)

var log = zerolog.New(os.Stdout).Level(zerolog.ErrorLevel)

type TokenOut struct {
	Token string
}

func HandleClientCreate(w http.ResponseWriter, r *http.Request, db storage.IManagerBackend, tlsBundle *tlssec.TLSBundle) {
	client := &entity.Client{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(client)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "cannot decode json body")
		return
	}
	c, err := db.CreateClient(client.Name)
	if err != nil {
		log.Err(err).Msg("cannot create client")
		WriteError(w, http.StatusLengthRequired, "cannot create client")
		return
	}
	WriteResponse(w, 0, c)
}

func HandleClientToken(w http.ResponseWriter, r *http.Request, db storage.IManagerBackend, tlsBundle *tlssec.TLSBundle) {
	client, err := AuthnCredentials(r, db)
	if err != nil {
		log.Err(err).Msg("cannot authorize basic auth")
		WriteError(w, http.StatusForbidden, "")
		return
	}
	token, err := jwtsec.CreateAccessToken(client, tlsBundle.PrivateKey)
	if err != nil {
		log.Err(err).Msg("cannot create access token")
		WriteError(w, http.StatusInternalServerError, "")
		return
	}
	out := TokenOut{token}
	encOut, err := json.Marshal(out)
	if err != nil {
		log.Err(err).Msg("cannot marshal token")
		WriteError(w, 500, "")
		return
	}
	WriteResponse(w, http.StatusOK, string(encOut))
}

func HandleClientFrontendTLS(w http.ResponseWriter, r *http.Request, db storage.IManagerBackend, tlsBundle *tlssec.TLSBundle) {
	cid, err := AuthzToken(r, tlsBundle)
	if err != nil {
		log.Err(err).Msg("cannot authorize authz token")
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if v, ok := mux.Vars(r)["uuid"]; ok {
		tlsBundle, err := db.CreateFrontendTLS(v, cid)
		if err != nil {
			log.Err(err).Msgf("cannot create frontend credentials %s, %s", v, cid)
			WriteError(w, http.StatusBadRequest, "cannot create frontend credentials")
			return
		}
		WriteResponse(w, http.StatusOK, tlsBundle)
		return
	}
	WriteError(w, http.StatusBadRequest, "")
}

func HandleClientFrontendCreate(w http.ResponseWriter, r *http.Request, db storage.IManagerBackend, tlsBundle *tlssec.TLSBundle) {
	cid, err := AuthzToken(r, tlsBundle)
	if err != nil {
		log.Err(err).Msg("cannot authorize authz token")
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	frontend := &entity.Frontend{}
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(frontend)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "cannot decode json body")
		return
	}
	frontend.ClientId = cid
	newFrontend, err := db.CreateFrontend(frontend)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "cannot decode json body")
		return
	}
	WriteResponse(w, http.StatusOK, newFrontend)
}

func HandleClientFrontendUpdate(w http.ResponseWriter, r *http.Request, db storage.IManagerBackend, tlsBundle *tlssec.TLSBundle) {

}

func HandleClientFrontendList(w http.ResponseWriter, r *http.Request, db storage.IManagerBackend, tlsBundle *tlssec.TLSBundle) {

}

func HandleClientFrontendGet(w http.ResponseWriter, r *http.Request, db storage.IManagerBackend, tlsBundle *tlssec.TLSBundle) {

}
