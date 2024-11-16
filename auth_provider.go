package auth

import (
	_ "embed"
	"encoding/gob"
	"github.com/lemmego/api/app"
	"github.com/lemmego/api/db"
	"github.com/lemmego/api/session"
	"github.com/lemmego/auth/cmd"
	"github.com/spf13/cobra"
)

func init() {
	gob.Register(&AuthUser{})
	app.RegisterService(func(a app.App) error {
		dm := &db.DatabaseManager{}
		sess := &session.Session{}

		if err := a.Service(dm); err != nil {
			panic(err)
		}

		if err := a.Service(sess); err != nil {
			panic(err)
		}

		dbc, err := dm.Get()
		if err != nil {
			panic(err)
		}

		Set(func(opts *Options) {
			opts.HomeRoute = "/home"
			opts.Router = a.Router()
			opts.DB = dbc
			opts.Session = sess
		})

		a.AddService(Get())

		return nil
	})

	app.BootService(func(a app.App) error {
		auth := &Auth{}
		if err := a.Service(auth); err != nil {
			panic(err)
		}

		a.AddCommands([]app.Command{
			func(a app.App) *cobra.Command {
				return cmd.Command()
			},
		})
		return nil
	})
}
