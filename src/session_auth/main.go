package main

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

const AUTH_USER_NAME = "foo"
const AUTH_PASSWORD = "bar"

type LoginRequest struct {
	UserName string `form:"user"`
	Password string `form:"pass"`
}

func main() {
	var router = gin.Default()
	var store = cookie.NewStore([]byte("secret"))
	router.Use(sessions.Sessions("mysession", store))
	router.LoadHTMLGlob("/go/src/session_auth/templates/*.html")

	router.GET("/signin", func(c *gin.Context) {
		c.HTML(http.StatusOK, "signin.html", gin.H{})
	})

	router.POST("/signin", func(c *gin.Context) {
		var loginRequest LoginRequest
		if c.Bind(&loginRequest) != nil {
			c.HTML(http.StatusInternalServerError, "signin.html", gin.H{
				"message": "request bind error.",
			})
			return
		}

		if loginRequest.UserName != AUTH_USER_NAME || loginRequest.Password != AUTH_PASSWORD {
			c.HTML(http.StatusBadRequest, "signin.html", gin.H{
				"message": "sign in error.",
			})
		} else {
			var session = sessions.Default(c)
			session.Options(sessions.Options{
				Path:     "/",
				HttpOnly: true,
			})

			session.Set("userName", loginRequest.UserName)
			session.Save()

			c.Redirect(http.StatusFound, "/session_auth/mypage")
		}
	})

	router.GET("/mypage", func(c *gin.Context) {
		var session = sessions.Default(c)

		var userName = session.Get("userName")
		if userName == nil {
			c.Redirect(http.StatusFound, "/session_auth/signin")
		} else {
			c.HTML(http.StatusOK, "mypage.html", gin.H{})
		}
	})

	router.POST("/logout", func(c *gin.Context) {
		var session = sessions.Default(c)
		session.Clear()
		session.Options(sessions.Options{Path: "/", MaxAge: -1})
		session.Save()

		c.Redirect(http.StatusFound, "/session_auth/signin")
	})

	router.Run()
}
