package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	jwt "github.com/appleboy/gin-jwt/v2"
)

type login struct {
	UserName string `form:"user" json:"user" binding:"required"`
	Password string `form:"pass" json:"pass" binding:"required"`
}

type User struct {
	UserName  string
	FirstName string
	LastName  string
}

var identityKey = "id"

func helloHandler(c *gin.Context) {
	var claims = jwt.ExtractClaims(c)
	var user, _ = c.Get(identityKey)
	c.JSON(http.StatusOK, gin.H{
		"userID":   claims[identityKey],
		"userName": user.(*User).UserName,
		"text":     "Hello World",
	})
}

func main() {
	var authMiddleware, err = jwt.New(&jwt.GinJWTMiddleware{
		Realm:       "test zone",
		Key:         []byte("secret key"),
		Timeout:     time.Hour,
		MaxRefresh:  time.Hour,
		IdentityKey: identityKey,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(*User); ok {
				return jwt.MapClaims{
					identityKey: v.UserName,
				}
			}

			return jwt.MapClaims{}
		},
		IdentityHandler: func(c *gin.Context) interface{} {
			var claims = jwt.ExtractClaims(c)

			return &User{
				UserName: claims[identityKey].(string),
			}
		},
		Authenticator: func(c *gin.Context) (interface{}, error) {
			var loginVals login
			if err := c.ShouldBind(&loginVals); err != nil {
				return "", jwt.ErrMissingLoginValues
			}

			var userID = loginVals.UserName
			var password = loginVals.Password

			if (userID == "admin" && password == "admin") || (userID == "test" && password == "test") {
				return &User{
					UserName:  userID,
					LastName:  "last_name",
					FirstName: "first_name",
				}, nil
			}

			return nil, jwt.ErrFailedAuthentication
		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			if v, ok := data.(*User); ok && v.UserName == "admin" {
				return true
			}

			return false
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		},

		TokenLookup: "header: Authorization, query: token, cookie: jwt",

		TokenHeadName: "Bearer",

		TimeFunc: time.Now,

		// SendCookie:     true,
		// CookieHTTPOnly: true,
	})

	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	var errInit = authMiddleware.MiddlewareInit()
	if errInit != nil {
		log.Fatal("authMiddleware.MiddlewareInit() Error:" + errInit.Error())
	}

	var router = gin.Default()

	router.LoadHTMLGlob("/go/src/jwt_auth/templates/*.html")

	router.GET("/signin", func(c *gin.Context) {
		c.HTML(http.StatusOK, "signin.html", gin.H{})
	})

	router.POST("/signin", authMiddleware.LoginHandler)

	router.NoRoute(authMiddleware.MiddlewareFunc(), func(c *gin.Context) {
		var claims = jwt.ExtractClaims(c)
		log.Printf("NoRoute claims: %#v\n", claims)
		c.JSON(404, gin.H{"code": "PAGE_NOT_FOUND", "message": "Page not found"})
	})

	var auth = router.Group("/auth")

	auth.GET("/refresh_token", authMiddleware.RefreshHandler)
	auth.Use(authMiddleware.MiddlewareFunc())
	{
		auth.GET("/hello", helloHandler)
	}

	router.Run()
}
