//go:build ignore

package routes

import (
	"github.com/lemmego/api/app"
	"github.com/lemmego/auth"
	"github.com/lemmego/lemmego/internal/handlers"
	"github.com/lemmego/lemmego/internal/models"
	"github.com/lemmego/lemmego/templates"
)

func authRoutes(r app.Router) {
	r.Get("/login",
		auth.Get().Guest,
		handlers.SessionIndexHandler,
	)

	r.Post("/login",
		auth.Get().Guest,
		auth.Get().Tenant,
		handlers.SessionStoreHandler,
	)

	r.Delete("/logout",
		auth.Get().Guard,
		handlers.SessionDeleteHandler,
	)

	r.Get("/register",
		auth.Get().Guest,
		handlers.RegistrationIndexHandler,
	)

	r.Post(
		"/register",
		auth.Get().Guest,
		handlers.RegistrationStoreHandler,
	)

	r.Get("/home", auth.Get().Guard, func(c *app.Context) error {
		user := c.GetSession("user").(*models.User)
		return c.Templ(templates.BaseLayout(templates.Home(user)))
	})
}
