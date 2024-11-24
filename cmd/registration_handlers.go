//go:build ignore

package handlers

import (
	//inject:required_import_fmt
	//inject:required_import_models
	"github.com/lemmego/api/app"
	"github.com/lemmego/api/db"
	//inject:res_import
	//inject:shared_import
	"github.com/lemmego/api/utils"
	"github.com/lemmego/lemmego/internal/inputs"
	//inject:templates_import
)

func RegistrationIndexHandler(c *app.Context) error {
	//inject:templ_register
	//inject:react_register
}

func RegistrationStoreHandler(c *app.Context) error {
	body := &inputs.RegistrationInput{}
	if err := c.Validate(body); err != nil {
		return err
	}

	password, err := utils.Bcrypt(body.Password)

	if err != nil {
		return err
	}

	//inject:org_model
	//inject:user_model
	//inject:org_logo
	//inject:avatar
	//inject:org_create

	if err := db.Get().DB().Create(user).Error; err != nil {
		return err
	}

	return c.With("message", "Registration Successful. Please Log In.").Redirect("/login")
}
