package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

type mcpClient struct {
	httpClient httpDoer
	url        string
	region     string
	service    string
	creds      aws.Credentials
	sessionID  string
	verbose    bool
	stderr     io.Writer
}

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc,omitempty"`
	ID      any             `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int             `json:"code,omitempty"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

var errUpstream = errors.New("upstream tool failure")

type authError struct{ error }

func isAuthErr(err error) bool {
	var ae authError
	return errors.As(err, &ae)
}

func errorName(err error) string {
	if isAuthErr(err) {
		return "auth_failure"
	}
	if errors.Is(err, errUpstream) {
		return "upstream_tool_failure"
	}
	return "failure"
}

func (a *app) syncTools(ctx context.Context, cfg effectiveConfig) (*toolCache, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.SyncTimeout)
	defer cancel()
	fmt.Fprintln(a.stderr, "Syncing tools...")
	client, err := a.newMCPClient(ctx, cfg, cfg.SyncTimeout)
	if err != nil {
		return nil, err
	}
	server, err := client.initialize(ctx)
	if err != nil {
		return nil, err
	}
	tools, err := client.listTools(ctx)
	if err != nil {
		return nil, err
	}
	for i := range tools {
		tools[i].SchemaHash = schemaHash(tools[i].InputSchema)
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	cache := &toolCache{Version: 1, URL: cfg.URL, LastSync: a.now().UTC(), Server: server, Tools: tools}
	if err := writeCache(cfg.ToolsPath, cache); err != nil {
		return nil, err
	}
	return cache, nil
}

func (a *app) callTool(ctx context.Context, cfg effectiveConfig, name string, input map[string]any) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.CallTimeout)
	defer cancel()
	client, err := a.newMCPClient(ctx, cfg, cfg.CallTimeout)
	if err != nil {
		return nil, err
	}
	if _, err := client.initialize(ctx); err != nil {
		return nil, err
	}
	return client.callTool(ctx, name, input)
}

func (a *app) newMCPClient(ctx context.Context, cfg effectiveConfig, timeout time.Duration) (*mcpClient, error) {
	creds, sdkRegion, err := a.loadCredentials(ctx, cfg)
	if err != nil {
		return nil, err
	}
	region := firstNonEmpty(cfg.Region, sdkRegion)
	if region == "" {
		return nil, errors.New("AWS region could not be inferred; set --region, BMCP_REGION, or an AWS profile/default region")
	}
	doer := a.httpClient
	if doer == nil {
		doer = &http.Client{Timeout: timeout}
	}
	return &mcpClient{
		httpClient: doer,
		url:        cfg.URL, region: region, service: cfg.Service, creds: creds,
		verbose: cfg.NonInteractive, stderr: a.stderr,
	}, nil
}

func (c *mcpClient) initialize(ctx context.Context) (serverInfo, error) {
	params := json.RawMessage(`{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"bmcp","version":"0.1.0"}}`)
	body, err := c.rpc(ctx, jsonRPCRequest{JSONRPC: "2.0", ID: 1, Method: "initialize", Params: params}, true)
	if err != nil {
		return serverInfo{}, err
	}
	var result struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
		Instructions string `json:"instructions"`
	}
	_ = json.Unmarshal(body, &result)
	_, _ = c.rpc(ctx, jsonRPCRequest{JSONRPC: "2.0", Method: "notifications/initialized"}, false)
	return serverInfo{Name: result.ServerInfo.Name, ProtocolVersion: result.ProtocolVersion, Instructions: result.Instructions}, nil
}

func (c *mcpClient) listTools(ctx context.Context) ([]tool, error) {
	body, err := c.rpc(ctx, jsonRPCRequest{JSONRPC: "2.0", ID: 2, Method: "tools/list"}, true)
	if err != nil {
		return nil, err
	}
	var result struct {
		Tools []struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			InputSchema json.RawMessage `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	tools := make([]tool, 0, len(result.Tools))
	for _, t := range result.Tools {
		tools = append(tools, tool{Name: t.Name, Description: t.Description, InputSchema: nonEmptySchema(t.InputSchema)})
	}
	return tools, nil
}

func (c *mcpClient) callTool(ctx context.Context, name string, input map[string]any) ([]byte, error) {
	params, _ := json.Marshal(map[string]any{"name": name, "arguments": input})
	body, err := c.rpc(ctx, jsonRPCRequest{JSONRPC: "2.0", ID: 3, Method: "tools/call", Params: params}, true)
	if err != nil {
		return nil, err
	}
	var maybe struct {
		IsError bool `json:"isError"`
	}
	if json.Unmarshal(body, &maybe) == nil && maybe.IsError {
		return nil, fmt.Errorf("%w: %s", errUpstream, string(body))
	}
	return body, nil
}

func (c *mcpClient) rpc(ctx context.Context, rpcReq jsonRPCRequest, expectResponse bool) (json.RawMessage, error) {
	body, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, body)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	if err := v4.NewSigner().SignHTTP(ctx, c.creds, req, hex.EncodeToString(sum[:]), c.service, c.region, time.Now().UTC()); err != nil {
		return nil, authError{err}
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.sessionID = sid
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("remote MCP HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if !expectResponse {
		return nil, nil
	}
	payload := normalizeMCPResponse(resp.Header.Get("Content-Type"), respBody)
	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(payload, &rpcResp); err != nil {
		return nil, fmt.Errorf("invalid MCP response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("MCP error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	return rpcResp.Result, nil
}

func (c *mcpClient) newRequest(ctx context.Context, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	if c.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", c.sessionID)
	}
	return req, nil
}

func normalizeMCPResponse(contentType string, body []byte) []byte {
	if !strings.Contains(strings.ToLower(contentType), "text/event-stream") {
		return body
	}
	var last []byte
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "data:") {
			last = []byte(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	if len(last) == 0 {
		return body
	}
	return last
}

func unwrapMCPTextEnvelope(raw []byte) []byte {
	var envelope struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return raw
	}
	for _, item := range envelope.Content {
		if item.Type == "text" && item.Text != "" {
			return []byte(item.Text)
		}
	}
	return raw
}
