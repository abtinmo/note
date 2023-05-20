package jwtauth

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func getKey() []byte {
	var str = os.Getenv("SECRET_KEY")
	key := []byte(str)
	return key
}

func dayToNanoSec(day int) int {
	return day * 8.64e+13
}

func GenerateToken(user_id string) (string, error) {
	now_time := time.Now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp":     now_time.Add(time.Duration(dayToNanoSec(180))).Unix(),
		"iss":     now_time.Add(10000).Unix(),
		"user_id": user_id,
	})
	return token.SignedString(getKey())
}

func ValidateTokenMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth_token := c.Request.Header.Get("authorization")
		if auth_token == "" {
			c.JSON(400, gin.H{"message": "An authorization header is required."})
			return
		}
		bearerToken := strings.Split(auth_token, " ")
		if len(bearerToken) != 2 {
			c.JSON(400, gin.H{"message": "Invalid authorization token."})
			return
		}
		token, error := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
			if _, err := token.Method.(*jwt.SigningMethodHMAC); !err {
				log.Fatalf("Error while parrsing token %v", err)
				return nil, fmt.Errorf("There was an error.")
			}
			return getKey(), nil
		})
		if error != nil {
			c.JSON(400, gin.H{"message": error.Error()})
			return
		}
		if !token.Valid {
			c.JSON(400, gin.H{"message": "Invalid authorization token."})
			return
		}
		c.Set("claims", token.Claims)
		c.Next()
	}
}
