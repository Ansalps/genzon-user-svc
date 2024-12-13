package utils

import (
	"errors"
	"fmt"
	"time"

	"github.com/Ansalps/genzon-user-svc/pkg/models"
	"github.com/golang-jwt/jwt"
)

type JwtWrapper struct {
	SecretKey       string
	Issuer          string
	ExpirationHours int64
}
type jwtClaims struct {
	jwt.StandardClaims
	Id    int64
	Email string
	Role  string
}

func (w *JwtWrapper) GenerateToken(user models.User, role string) (signedToken string, err error) {
	claims := &jwtClaims{
		Id:    int64(user.ID),
		Email: user.Email,
		Role:  role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(w.ExpirationHours)).Unix(),
			Issuer:    w.Issuer,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err = token.SignedString([]byte(w.SecretKey))
	if err != nil {
		return "", err
	}
	return signedToken, nil
}
func (w *JwtWrapper) ValidateToken(signedToken string) (claims *jwtClaims, err error) {
	fmt.Println("is it reaching in validate token of user-svc")
	token, err := jwt.ParseWithClaims(
		signedToken,
		&jwtClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(w.SecretKey), nil
		},
	)
	if err != nil {
		return
	}
	claims, ok := token.Claims.(*jwtClaims)
	if !ok {
		return nil, errors.New("couldn't parse claims")
	}
	if claims.ExpiresAt < time.Now().Local().Unix() {
		return nil, errors.New("JWT is expired")
	}
	fmt.Println(claims.Role)
	if claims.Role!="user"{
		return nil,errors.New("permission denied")
	}
	return claims, nil
}
