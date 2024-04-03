package jwtsec

import (
	"crypto"
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v5"
	"github.com/xdire/xlb-poc/entity"
	"time"
)

func CreateAccessToken(client *entity.Client, key crypto.PrivateKey) (string, error) {
	jwtClaim := jwt.MapClaims{
		"iss": "xlb-authority",
		"sub": client.Uuid,
		"foo": 2,
		"exp": time.Now().Add(time.Hour * 1).Unix(),
	}
	tokenWithClaims := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaim)
	return tokenWithClaims.SignedString(key)
}

func VerifyAccessToken(token string, key *rsa.PrivateKey) {

}
