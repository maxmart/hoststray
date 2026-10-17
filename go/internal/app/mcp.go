package app

import (
	"context"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Agents may switch existing hosts groups and the proxy on or off, and read
// the configuration. Adding hostnames or routes and trusting the CA stay
// human-only: pointing a real domain at localhost behind a trusted CA would
// let a prompt-injected agent intercept that site's traffic.
const mcpInstructions = `Hosts Tray manages hosts-file groups and a local HTTPS reverse proxy for developing against real domain names.

- get_status shows the hosts groups (each a named block of hosts entries pointing domains at local addresses), the proxy state and its routes.
- set_hosts_group switches an existing group on or off. If the user hasn't allowed password-free changes, they will be asked for their password.
- set_proxy starts or stops the HTTPS proxy, which serves every hostname with a certificate from a local CA and forwards to the routes in proxy.conf.

New hostnames, groups and routes can only be added by the user in the Hosts Tray editors.`

type noInput struct{}

type setGroupInput struct {
	Name    string `json:"name" jsonschema:"exact name of an existing hosts group, as listed by get_status"`
	Enabled bool   `json:"enabled" jsonschema:"true to switch the group's entries on, false to comment them out"`
}

type setGroupOutput struct {
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	Elevated bool   `json:"elevated" jsonschema:"whether the user had to approve the change with their password"`
}

type setProxyInput struct {
	Enabled bool `json:"enabled" jsonschema:"true to start the HTTPS proxy, false to stop it"`
}

func (a *App) mcpServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "hoststray", Title: "Hosts Tray", Version: a.cfg.Version},
		&mcp.ServerOptions{Instructions: mcpInstructions})
	f := false

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_status",
		Description: "List hosts groups with their entries and on/off state, plus the HTTPS proxy's state, port, CA trust and routes.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &f},
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ noInput) (*mcp.CallToolResult, Status, error) {
		st, err := a.Status()
		return nil, st, err
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "set_hosts_group",
		Description: "Switch an existing hosts group on (entries active) or off (entries commented out).",
		Annotations: &mcp.ToolAnnotations{IdempotentHint: true, DestructiveHint: &f, OpenWorldHint: &f},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in setGroupInput) (*mcp.CallToolResult, setGroupOutput, error) {
		res, err := a.SetGroup(in.Name, in.Enabled)
		if err != nil {
			return nil, setGroupOutput{}, err
		}
		return nil, setGroupOutput{Name: in.Name, Enabled: in.Enabled, Elevated: res.Elevated}, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "set_proxy",
		Description: "Start or stop the local HTTPS proxy.",
		Annotations: &mcp.ToolAnnotations{IdempotentHint: true, DestructiveHint: &f, OpenWorldHint: &f},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in setProxyInput) (*mcp.CallToolResult, ProxyStatus, error) {
		if err := a.SetProxy(in.Enabled); err != nil {
			return nil, ProxyStatus{}, err
		}
		st, err := a.Status()
		return nil, st.Proxy, err
	})
	return s
}

func (a *App) mcpHandler() http.Handler {
	s := a.mcpServer()
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, nil)
}
