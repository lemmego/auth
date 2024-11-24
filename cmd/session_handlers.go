//go:build ignore

package handlers

import (
	"encoding/gob"
	"github.com/lemmego/api/app"
	"github.com/lemmego/api/db"
	//inject:res_import
	"github.com/lemmego/api/session"
	"github.com/lemmego/api/shared"
	"github.com/lemmego/auth"
	"github.com/lemmego/lemmego/internal/inputs"
	"github.com/lemmego/lemmego/internal/models"
	//inject:templates_import
	"log/slog"
)

func init() {
	gob.Register(&models.User{})
}

func SessionIndexHandler(c *app.Context) error {
	//inject:templ_login
	//inject:react_login
}

func SessionStoreHandler(c *app.Context) error {
	// Initialize credential errors for reusability
	credErrors := shared.ValidationErrors{
		"password": []string{"Invalid credentials"},
		"email":    []string{"Invalid credentials"},
	}

	// Validate input
	body := &inputs.LoginInput{}
	if err := c.Validate(body); err != nil {
		return err
	}

	// Check if the user with the provided email exists
	user := &models.User{}

	attrs := map[string]interface{}{
		"email": body.Email,
	}

	//inject:org_login

	if err := db.Get().DB().Where(attrs).First(user).Error; err != nil {
		slog.Error(err.Error())
		return credErrors
	}

	if user.ID == 0 {
		return credErrors
	}

	if body.RememberMe {
		token := session.Get().Token(c.RequestContext())
		db.Get().DB().Model(user).Update("remember_token", token)
		session.Get().RememberMe(c.RequestContext(), true)
	}

	// Check if given email and password matches
	if _, err := auth.Get().Login(
		c.Request().Context(),
		user,
		body.Email,
		body.Password,
	); err != nil {
		slog.Error(err.Error())
		return credErrors
	}

	return c.Redirect("/home")
}

func SessionDeleteHandler(c *app.Context) error {
	if err := session.Get().Destroy(c.RequestContext()); err != nil {
		return err
	}
	return c.Redirect("/home")
}
