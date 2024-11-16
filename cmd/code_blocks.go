package cmd

var defaultModuleName = []byte(`github.com/lemmego/lemmego`)

var buildTagBlock = []byte(`//go:build ignore

`)

var loginHandlersOrgBlock = []byte(`

	if orgId := c.Get("org_id").(uint); orgId != 0 {
		attrs["org_id"] = orgId
	}
`)

var registrationHandlersOrgModelBlock = []byte(`

	org := &models.Org{
		OrgUsername: body.OrgUsername,
		OrgName:     body.OrgName,
		OrgEmail:    body.OrgEmail,
	}
`)

var registrationHandlersOrgLogoBlock = []byte(`

	if c.HasFile("org_logo") {
		_, err := c.Upload("org_logo", "images/orgs")

		if err != nil {
			return fmt.Errorf("could not upload org_logo: %w", err)
		}
		org.OrgLogo = "images/orgs/" + body.OrgLogo.Filename()
	}
`)

var registrationHandlersOrgCreateBlock = []byte(`

	if err := conn.DB().Create(org).Error; err != nil {
		return err
	} else {
		user.OrgId = org.ID
	}
`)

var routesTenantBlock = []byte(`		authn.Tenant,
`)

var loginTemplFlavorBlock = []byte(`
	data := res.TemplateData{}
	if val, ok := c.PopSession("errors").(shared.ValidationErrors); ok {
		data.ValidationErrors = val
	}

	return c.Templ(templates.BaseLayout(templates.Login(data)))
`)

var registrationTemplFlavorBlock = []byte(`
	data := res.TemplateData{}
	if val, ok := c.PopSession("errors").(shared.ValidationErrors); ok {
		data.ValidationErrors = val
	}

	return c.Templ(templates.BaseLayout(templates.Register(data)))
`)

var loginReactFlavorBlock = []byte(`
	props := map[string]any{}
	message := c.PopSessionString("message")
	if message != "" {
		props["message"] = message
	}
	return c.Inertia("Forms/Login", props)
`)

var registrationReactFlavorBlock = []byte(`	return c.Inertia("Forms/Register", nil)
`)

var templImportResBlock = []byte(`"github.com/lemmego/api/res"`)

var templImportSharedBlock = []byte(`"github.com/lemmego/api/shared"`)

var templImportTemplatesBlock = []byte(`"github.com/lemmego/lemmego/templates"`)
