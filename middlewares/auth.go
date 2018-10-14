package middlewares

import (
	"fmt"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func AuthHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Request.Header.Get("Authorization")
		fmt.Println(token)
		// Check if toke in correct format
		// ie Bearer: xx03xllasx
		b := "Bearer "
		if !strings.Contains(token, b) {
			c.JSON(403, gin.H{"message": "Your request is not authorized"})
			c.Abort()
			return
		}
		t := strings.Split(token, b)
		if len(t) < 2 {
			c.JSON(403, gin.H{"message": "An authorization token was not supplied"})
			c.Abort()
			return
		}
		// Validate token
		valid, err := ValidateToken(t[1], SigningKey)
		if err != nil {
			c.JSON(403, gin.H{"message": "Invalid authorization token"})
			c.Abort()
			return
		}

		// set userId Variable
		c.Set("userId", valid.Claims.(jwt.MapClaims)["user_id"])
		c.Next()
	}
}
