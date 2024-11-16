package cmd

import (
	"bytes"
	"fmt"
	"github.com/lemmego/cli"
	"github.com/lemmego/fsys"
	"log"
	"os"
	"runtime/debug"

	_ "embed"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
)

//go:embed session_handlers.go
var sessionHandlers []byte

//go:embed registration_handlers.go
var registrationHandlers []byte

//go:embed routes.go
var routes []byte

//go:embed home.templ
var homeTempl []byte

var formFieldTypes = []string{"text", "textarea", "integer", "decimal", "boolean", "radio", "checkbox", "dropdown", "date", "time", "datetime", "file"}

var userFields = []string{"first_name", "last_name", "username", "bio", "phone", "avatar"}
var requiredUserFields = []string{"email", "password"}
var orgFields = []string{"org_name", "org_email", "org_logo"}
var requiredOrgFields = []string{"org_username"}
var wd, _ = os.Getwd()

type Field struct {
	Name     string
	Type     string
	Required bool
	Unique   bool
}

var uf = []*Field{
	{Name: "email", Type: "string", Required: true, Unique: true},
	{Name: "password", Type: "string", Required: true, Unique: false},
	{Name: "username", Type: "string", Required: true, Unique: false},
	{Name: "first_name", Type: "string", Required: true, Unique: false},
	{Name: "last_name", Type: "string", Required: true, Unique: false},
	{Name: "bio", Type: "string", Required: true, Unique: false},
	{Name: "phone", Type: "string", Required: true, Unique: false},
	{Name: "avatar", Type: "string", Required: true, Unique: false},
}

var of = []*Field{
	{Name: "avatar", Type: "string", Required: true, Unique: false},
}

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Generate auth related files",
	Long:  `Generate auth related files`,

	Run: func(cmd *cobra.Command, args []string) {
		selectedFrontend := ""
		// username, password := "email", "password"
		hasOrg := false

		selectedUserFields := []string{}
		selectedOrgFields := []string{}

		orgForm := huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().
					Title("Which frontend scaffolding should be generated?").
					Options(huh.NewOptions("templ", "react")...).
					Value(&selectedFrontend),
				huh.NewConfirm().
					Title("Should your users belong to an org? (useful for multitenant apps)").
					Value(&hasOrg),
			),
		)

		err := orgForm.Run()
		if err != nil {
			fmt.Println("Error:", err.Error())
			return
		}

		userFieldSelectionForm := huh.NewForm(
			huh.NewGroup(
				huh.NewMultiSelect[string]().
					Title("Select the fields for the user entity").
					Options(huh.NewOptions(userFields...)...).
					Value(&selectedUserFields),
			),
		)

		err = userFieldSelectionForm.Run()
		if err != nil {
			fmt.Println("Error:", err.Error())
			return
		}

		if hasOrg {
			orgFieldSelectionForm := huh.NewForm(
				huh.NewGroup(
					huh.NewMultiSelect[string]().
						Title("Select the fields for the org entity").
						Options(huh.NewOptions(orgFields...)...).
						Value(&selectedOrgFields),
				),
			)

			err = orgFieldSelectionForm.Run()
			if err != nil {
				fmt.Println("Error:", err.Error())
				return
			}
		}

		createMigrationFiles(selectedUserFields, selectedOrgFields)
		createModelFiles(selectedUserFields, selectedOrgFields)
		createInputFiles(selectedUserFields, selectedOrgFields)
		createFormFiles(selectedFrontend, selectedUserFields, selectedOrgFields)
		createHandlerFiles(selectedFrontend, selectedUserFields, selectedOrgFields)
		createTemplateFiles(selectedFrontend, selectedUserFields, selectedOrgFields)
		createRoutesFiles(selectedUserFields, selectedOrgFields)
	},
}

func generateOrgMigration(oFields []*cli.MigrationField) {
	om := cli.NewMigrationGenerator(&cli.MigrationConfig{
		TableName:  "orgs",
		Fields:     oFields,
		Timestamps: true,
	})
	om.Generate()
}

func generateUserMigration(userFields []*cli.MigrationField, hasOrg bool) {
	config := &cli.MigrationConfig{
		TableName:  "users",
		Fields:     userFields,
		Timestamps: true,
	}
	if hasOrg {
		config.PrimaryColumns = []string{"id", "org_id"}
	} else {
		config.PrimaryColumns = []string{"id"}
	}
	um := cli.NewMigrationGenerator(config)
	um.BumpVersion().Generate()
}

func createMigrationFiles(userFields []string, orgFields []string) {
	hasOrg := len(orgFields) > 0
	uFields := []*cli.MigrationField{
		{Name: "id", Type: "bigIncrements"},
		{Name: "email", Type: "string", Unique: true},
		{Name: "password", Type: "text"},
		{Name: "remember_token", Type: "string", Nullable: true},
	}

	for _, f := range userFields {
		field := &cli.MigrationField{Name: f, Type: "string"}
		if f == "username" || f == "email" {
			field.Unique = true
		}
		if f == "bio" {
			field.Nullable = true
			field.Type = "text"
		}
		uFields = append(uFields, field)
	}

	if hasOrg {
		oFields := []*cli.MigrationField{
			{Name: "id", Type: "bigIncrements", Primary: true},
			{Name: "org_username", Type: "string", Unique: true},
		}

		for _, f := range orgFields {
			field := &cli.MigrationField{Name: f, Type: "string"}
			if f == "username" || f == "email" {
				field.Unique = true
			}
			if f == "bio" {
				field.Nullable = true
				field.Type = "text"
			}
			oFields = append(oFields, field)
		}
		generateOrgMigration(oFields)

		uFields = append(uFields, &cli.MigrationField{
			Name:               "org_id",
			Type:               "bigIncrements",
			ForeignConstrained: true,
		})
	}

	generateUserMigration(uFields, hasOrg)
}

func generateOrgModel(orgFields []*cli.ModelField) {
	om := cli.NewModelGenerator(&cli.ModelConfig{
		Name:   "org",
		Fields: orgFields,
	})
	om.Generate()
}

func generateUserModel(userFields []*cli.ModelField) {
	um := cli.NewModelGenerator(&cli.ModelConfig{
		Name:   "user",
		Fields: userFields,
	})

	appendable := []byte(`
func (u *User) Id() interface{} {
	return u.ID
}

func (u *User) GetUsername() string {
	return u.Email
}

func (u *User) GetPassword() string {
	return u.Password
}
`)

	um.Generate(appendable)
}

func createModelFiles(userFields []string, orgFields []string) {
	createModelDir()
	uFields := []*cli.ModelField{
		{Name: "email", Type: "string", Unique: true},
		{Name: "password", Type: "string"},
		{Name: "remember_token", Type: "string"},
	}

	if len(orgFields) > 0 {
		oFields := []*cli.ModelField{
			{Name: "org_username", Type: "string", Unique: true},
		}
		for _, f := range orgFields {
			field := &cli.ModelField{Name: f, Type: "string"}
			if f == "org_email" {
				field.Unique = true
			}
			field.Required = true
			oFields = append(oFields, field)
		}

		uFields = append(uFields, &cli.ModelField{
			Name: "org_id", Type: "uint", Required: true,
		})
		generateOrgModel(oFields)
	}

	for _, f := range userFields {
		field := &cli.ModelField{Name: f, Type: "string"}
		if f == "username" || f == "email" {
			field.Required = true
			field.Unique = true
		}
		uFields = append(uFields, field)
	}
	generateUserModel(uFields)
}

func createInputFiles(userFields []string, orgFields []string) {
	createInputDir()
	loginFields := []*cli.InputField{
		{Name: "email", Type: "string", Required: true},
		{Name: "password", Type: "string", Required: true},
		{Name: "remember_me", Type: "bool"},
	}

	registrationFields := []*cli.InputField{
		{Name: "email", Type: "string", Required: true, Unique: true, Table: "users"},
		{Name: "password", Type: "string", Required: true},
		{Name: "password_confirmation", Type: "string", Required: true},
	}

	for _, f := range userFields {
		typ := "string"
		if f == "avatar" {
			typ = "file"
		}
		registrationFields = append(registrationFields, &cli.InputField{
			Name:     f,
			Type:     typ,
			Required: true,
		})
	}

	if len(orgFields) > 0 {
		for _, f := range orgFields {
			field := &cli.InputField{
				Name:     f,
				Type:     "string",
				Required: true,
			}

			if f == "org_email" {
				field.Unique = true
				field.Table = "orgs"
			}

			if f == "org_logo" {
				field.Type = "file"
			}

			registrationFields = append(registrationFields, field)
		}

		orgUsernameFieldLogin := &cli.InputField{
			Name:     "org_username",
			Type:     "string",
			Required: true,
			Table:    "orgs",
			Unique:   false,
		}

		loginFields = append(loginFields, orgUsernameFieldLogin)

		orgUsernameFieldRegister := &cli.InputField{
			Name:     "org_username",
			Type:     "string",
			Required: true,
			Table:    "orgs",
			Unique:   true,
		}
		registrationFields = append(registrationFields, orgUsernameFieldRegister)
	}

	loginGen := cli.NewInputGenerator(&cli.InputConfig{
		Name:   "login",
		Fields: loginFields,
	})
	loginGen.Generate()

	registrationGen := cli.NewInputGenerator(&cli.InputConfig{
		Name:   "registration",
		Fields: registrationFields,
	})
	registrationGen.Generate()
}

func createFormFiles(flavor string, userFields []string, orgFields []string) {
	createFormDir(flavor)
	loginFields := []*cli.FormField{
		{Name: "email", Type: "text"},
		{Name: "password", Type: "text"},
		{Name: "remember_me", Type: "boolean", Choices: []string{"Remember Me"}},
	}
	registrationFields := []*cli.FormField{}

	for _, f := range userFields {
		field := &cli.FormField{Name: f, Type: "text"}
		if f == "avatar" {
			field.Type = "file"
		}
		if f == "bio" {
			field.Type = "textarea"
		}
		registrationFields = append(registrationFields, field)
	}

	registrationFields = append(registrationFields, []*cli.FormField{
		{Name: "email", Type: "text"},
		{Name: "password", Type: "text"},
		{Name: "password_confirmation", Type: "text"},
	}...)

	if len(orgFields) > 0 {
		loginFields = append([]*cli.FormField{{Name: "org_username", Type: "text"}}, loginFields...)
		registrationFields = append(registrationFields, &cli.FormField{Name: "org_username", Type: "text"})
		for _, f := range orgFields {
			field := &cli.FormField{Name: f, Type: "text"}
			if f == "org_logo" {
				field.Type = "file"
			}
			registrationFields = append(registrationFields, field)
		}
	}

	loginForm := cli.NewFormGenerator(&cli.FormConfig{
		Name:   "login",
		Flavor: flavor,
		Fields: loginFields,
		Route:  "/login",
	})

	loginForm.Generate()

	regForm := cli.NewFormGenerator(&cli.FormConfig{
		Name:   "register",
		Flavor: flavor,
		Fields: registrationFields,
		Route:  "/register",
	})

	regForm.Generate()
}

func createHandlerFiles(flavor string, userFields []string, orgFields []string) {
	info, _ := debug.ReadBuildInfo()

	sessionHandlers = bytes.Replace(sessionHandlers, buildTagBlock, []byte(``), 1)
	registrationHandlers = bytes.Replace(registrationHandlers, buildTagBlock, []byte(``), 1)

	if flavor == "react" {
		sessionHandlers = bytes.Replace(sessionHandlers, loginTemplFlavorBlock, []byte(``), 1)
		sessionHandlers = bytes.Replace(sessionHandlers, templImportResBlock, []byte(``), 1)
		sessionHandlers = bytes.Replace(sessionHandlers, templImportTemplatesBlock, []byte(``), 1)

		registrationHandlers = bytes.Replace(registrationHandlers, registrationTemplFlavorBlock, []byte(``), 1)
		registrationHandlers = bytes.Replace(registrationHandlers, templImportResBlock, []byte(``), 1)
		registrationHandlers = bytes.Replace(registrationHandlers, templImportSharedBlock, []byte(``), 1)
		registrationHandlers = bytes.Replace(registrationHandlers, templImportTemplatesBlock, []byte(``), 1)
	}

	if flavor == "templ" {
		sessionHandlers = bytes.Replace(sessionHandlers, loginReactFlavorBlock, []byte(``), 1)
		registrationHandlers = bytes.Replace(registrationHandlers, registrationReactFlavorBlock, []byte(``), 1)
	}

	// Remove tenant/org-specific code-blocks from the handlers
	if len(orgFields) == 0 {
		sessionHandlers = bytes.Replace(sessionHandlers, loginHandlersOrgBlock, []byte(``), 1)

		registrationHandlers = bytes.Replace(registrationHandlers, registrationHandlersOrgModelBlock, []byte(``), 1)
		registrationHandlers = bytes.Replace(registrationHandlers, registrationHandlersOrgLogoBlock, []byte(``), 1)
		registrationHandlers = bytes.Replace(registrationHandlers, registrationHandlersOrgCreateBlock, []byte(``), 1)
	}

	sessionHandlers = bytes.ReplaceAll(sessionHandlers, defaultModuleName, []byte(info.Main.Path))
	registrationHandlers = bytes.ReplaceAll(registrationHandlers, defaultModuleName, []byte(info.Main.Path))
	fs := fsys.NewLocalStorage("")
	err := fs.Write(
		"./internal/handlers/session_handlers.go",
		sessionHandlers,
	)
	if err != nil {
		log.Fatal(err)
	}
	err = fs.Write(
		"./internal/handlers/registration_handlers.go",
		registrationHandlers,
	)
	if err != nil {
		log.Fatal(err)
	}
}

func createTemplateFiles(flavor string, userFields []string, orgFields []string) {
	info, _ := debug.ReadBuildInfo()
	fs := fsys.NewLocalStorage("")

	if flavor == "templ" {
		homeTempl = bytes.ReplaceAll(homeTempl, defaultModuleName, []byte(info.Main.Path))
		err := fs.Write("./templates/home.templ", homeTempl)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func createRoutesFiles(userFields []string, orgFields []string) {
	info, _ := debug.ReadBuildInfo()
	routes = bytes.Replace(routes, buildTagBlock, []byte(``), 1)
	fs := fsys.NewLocalStorage("")

	// Remove tenant/org-specific code-blocks
	if len(orgFields) == 0 {
		routes = bytes.Replace(routes, routesTenantBlock, []byte(``), 1)
	}
	routes = bytes.ReplaceAll(routes, defaultModuleName, []byte(info.Main.Path))

	err := fs.Write("./internal/routes/auth.go", routes)
	if err != nil {
		log.Fatal(err)
	}
}

func createInputDir() {
	fs := fsys.NewLocalStorage("")
	err := fs.CreateDirectory("./internal/inputs")
	if err != nil {
		fmt.Println("Error creating inputs directory:", err.Error())
		return
	}
}

func createFormDir(flavor string) {
	if flavor == "react" {
		fs := fsys.NewLocalStorage("")
		err := fs.CreateDirectory("./resources/js/Pages/Forms")
		if err != nil {
			fmt.Println("Error creating forms directory:", err.Error())
			return
		}
	}

	if flavor == "templ" {
		fs := fsys.NewLocalStorage("")
		err := fs.CreateDirectory("./templates")
		if err != nil {
			fmt.Println("Error creating forms directory:", err.Error())
			return
		}
	}
}

func createModelDir() {
	fs := fsys.NewLocalStorage("")
	err := fs.CreateDirectory("./internal/models")
	if err != nil {
		fmt.Println("Error creating models directory:", err.Error())
		return
	}
}

func Command() *cobra.Command {
	return authCmd
}
