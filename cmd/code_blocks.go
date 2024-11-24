package cmd

import (
	"bytes"
	"github.com/iancoleman/strcase"
)

var defaultModuleName = []byte(`github.com/lemmego/lemmego`)

var regHandlerFmtImportBlock = []byte(`
	"fmt"`)

var regHandlerModelsImportBlock = []byte(`
	"github.com/lemmego/lemmego/internal/models"`)

var buildTagBlock = []byte(`//go:build ignore

`)

var tsNocheckBlock = []byte(`//@ts-nocheck

`)

var loginHandlersOrgBlock = []byte(`
	if orgId := c.Get("org_id").(uint); orgId != 0 {
		attrs["org_id"] = orgId
	}`)

var registrationHandlersOrgModelBlock = []byte(`

	org := &models.Org{
		OrgUsername: body.OrgUsername,
		OrgName:     body.OrgName,
		OrgEmail:    body.OrgEmail,
	}`)

var registrationHandlersOrgLogoBlock = []byte(`
	if c.HasFile("org_logo") {
		_, err := c.Upload("org_logo", "images/orgs")

		if err != nil {
			return fmt.Errorf("could not upload org_logo: %w", err)
		}
		org.OrgLogo = "images/orgs/" + body.OrgLogo.Filename()
	}`)

var registrationHandlersAvatarBlock = []byte(`
	if c.HasFile("avatar") {
		_, err := c.Upload("avatar", "images/avatars")

		if err != nil {
			return fmt.Errorf("could not upload avatar: %w", err)
		}
		user.Avatar = "images/avatars/" + body.Avatar.Filename()
	}`)

var registrationHandlersOrgCreateBlock = []byte(`
	if err := db.Get().DB().Create(org).Error; err != nil {
		return err
	} else {
		user.OrgId = org.ID
	}`)

var routesTenantBlock = []byte(`		auth.Get().Tenant,
`)

var loginTemplFlavorBlock = []byte(`
	data := res.TemplateData{}
	if val, ok := c.PopSession("errors").(shared.ValidationErrors); ok {
		data.ValidationErrors = val
	}

	return c.Templ(templates.BaseLayout(templates.Login(data)))`)

var registrationTemplFlavorBlock = []byte(`
	data := res.TemplateData{}
	if val, ok := c.PopSession("errors").(shared.ValidationErrors); ok {
		data.ValidationErrors = val
	}

	return c.Templ(templates.BaseLayout(templates.Register(data)))`)

var loginReactFlavorBlock = []byte(`
	props := map[string]any{}
	message := c.PopSessionString("message")
	if message != "" {
		props["message"] = message
	}
	return c.Inertia("Forms/Login", props)`)

var registrationReactFlavorBlock = []byte(`
	return c.Inertia("Forms/Register", nil)`)

var templImportResBlock = []byte(`"github.com/lemmego/api/res"`)

var templImportSharedBlock = []byte(`"github.com/lemmego/api/shared"`)

var templImportTemplatesBlock = []byte(`"github.com/lemmego/lemmego/templates"`)

var templHomeViewBlock = []byte(`
		return c.Templ(templates.BaseLayout(templates.Home(user)))`)

var reactHomeViewBlock = []byte(`
		return c.Inertia("Home", map[string]any{"user": user})`)

func orgModelBytes(orgFields []string) []byte {
	var buf bytes.Buffer

	buf.WriteString("org := &models.Org{\n")
	for _, orgField := range orgFields {
		if orgField != "org_logo" {
			buf.WriteString("\t\t" + strcase.ToCamel(orgField) + ":" + " body." + strcase.ToCamel(orgField) + ",\n")
		}
	}
	buf.WriteString("\t\tOrgUsername" + ": body.OrgUsername,\n")
	buf.WriteString("\t}")

	return buf.Bytes()
}

func userModelBytes(userFields []string) []byte {
	var buf bytes.Buffer

	buf.WriteString("user := &models.User{\n")
	for _, userField := range userFields {
		if userField != "avatar" {
			buf.WriteString("\t\t" + strcase.ToCamel(userField) + ":" + " body." + strcase.ToCamel(userField) + ",\n")
		}
	}
	buf.WriteString("\t\tEmail" + ": body.Email,\n")
	buf.WriteString("\t\tPassword" + ": password,\n")
	buf.WriteString("\t}")

	return buf.Bytes()
}

func RemoveMarker(content []byte, marker []byte) []byte {
	return bytes.Replace(content, marker, []byte(""), 1)
}
