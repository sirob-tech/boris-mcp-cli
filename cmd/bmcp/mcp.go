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
	"net/url"
	"os"
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

// sameServer reports whether two configured URLs address the same MCP endpoint,
// ignoring differences that cannot change which server answers: a trailing
// slash, and the case of the scheme and host. Anything it cannot parse falls
// back to exact comparison.
//
// This is deliberately narrow. It exists so the empty-catalog guard is not
// disarmed by a cosmetic spelling, not to decide cache validity in general —
// cacheForCatalog still treats any string difference as a reason to re-sync,
// which costs a round trip and never loses data.
func sameServer(a, b string) bool {
	if a == b {
		return true
	}
	ua, erra := url.Parse(a)
	ub, errb := url.Parse(b)
	if erra != nil || errb != nil {
		return false
	}
	norm := func(u *url.URL) string {
		scheme := strings.ToLower(u.Scheme)
		host := strings.ToLower(u.Hostname())
		// Brackets come back for IPv6: Hostname() strips them, and without them
		// `[::1]:8787` and a host literally named `::1` would collide.
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		// A default port spelled out is the same origin as one left off, and this
		// is the direction that matters: a false negative here disarms the guard
		// and destroys the catalog, where a false positive only preserves it.
		if port := u.Port(); port != "" && !(scheme == "https" && port == "443") && !(scheme == "http" && port == "80") {
			host += ":" + port
		}
		// EscapedPath, not Path: Path is percent-decoded, so `/a%2Fb` and `/a/b`
		// would compare equal despite being different request targets.
		//
		// TrimRight, not TrimSuffix: `/mcp//` has to collapse to `/mcp` too, or the
		// guard is disarmed by one extra keystroke.
		return scheme + "://" + host + strings.TrimRight(u.EscapedPath(), "/") + "?" + u.RawQuery
	}
	return norm(ua) == norm(ub)
}

func pluralize(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// errEmptyCatalog reports a tools/list that succeeded at the transport level and
// returned nothing, while a non-empty cache already existed. It is a refusal to
// write, not a transport failure: the cache on disk is untouched and still the
// last known-good catalog, which is why cacheForCatalog can serve from it.
// The wording is deliberately about refusing the write rather than about
// keeping a usable cache: on the unreadable-cache branch below there is nothing
// left to serve from, and cacheForCatalog will not pretend otherwise.
var errEmptyCatalog = errors.New("the server returned no tools; refusing to overwrite the existing catalog")

// existingCatalogDetail describes the catalog an empty tools/list would destroy,
// or "" when there is nothing worth protecting and the empty result may be
// written as the truth.
//
// The precondition is "no prior catalog", not "I could read a prior catalog".
// Those came apart when the cache was unparseable: readCache failed, the guard
// read that as a first sync, and an empty catalog was written over a file that
// had held the real one. Any tools.json with bytes in it is treated as a
// catalog, so a damaged one fails closed.
//
// A damaged file cannot say which server it came from, so the URL check below
// cannot run and a `--url`/BMCP_URL override pointed at a genuinely empty server
// is refused too. Deleting the file clears it, which is what the caller's error
// says to do. (`bmcp init --url <other>` cannot reach this at all: cmdInit
// already removes tools.json when the URL changes.)
func existingCatalogDetail(path, url string) string {
	old, err := readCache(path)
	if err == nil {
		if len(old.Tools) == 0 {
			return ""
		}
		// A cache from a different server is not a catalog worth protecting:
		// after `bmcp init --url <other>` an empty result from the new server is
		// the truth about it. Compared normalized because this check fails
		// *open* — a cosmetic difference that still addresses the same server,
		// such as a trailing slash from `--url`, would otherwise disarm the
		// guard and destroy the catalog it exists to protect.
		if !sameServer(old.URL, url) {
			return ""
		}
		return fmt.Sprintf("%d %s, synced %s", len(old.Tools), pluralize(len(old.Tools), "tool"),
			old.LastSync.UTC().Format(time.RFC3339))
	}
	// Size is deliberately not considered. A zero-byte tools.json is not an
	// empty catalog, it is the signature of an in-place write killed after
	// O_TRUNC and before its first byte — exactly what the old writer could
	// leave, and exactly the machine that most needs the guard when it upgrades.
	if _, statErr := os.Stat(path); statErr == nil {
		return "existing cache is unreadable, so its contents cannot be ruled out"
	}
	return ""
}

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
	if errors.Is(err, errEmptyCatalog) {
		return "empty_catalog"
	}
	return "failure"
}

func (a *app) syncTools(ctx context.Context, cfg effectiveConfig) (*toolCache, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.SyncTimeout)
	defer cancel()
	fmt.Fprintln(a.prose(), "Syncing tools...")
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
	// A tools/list that succeeds and returns nothing — a partial upstream outage,
	// a gateway misconfiguration, an auth scope resolving to no tools — must not
	// replace a good catalog with an empty one stamped LastSync: now. That write
	// is unrecoverable without the server coming back, and it propagates: `sync`
	// then rewrites every installed instruction file with the "no tools
	// available" placeholder, spending a backup generation each time it runs.
	//
	// Only a catalog that already had tools is protected. A first sync against a
	// genuinely empty server still writes, because there is nothing to lose.
	//
	// Leaving the cache untouched also leaves LastSync stale, so the next command
	// retries rather than waiting out the TTL — one round trip per command during
	// the outage, and recovery the moment upstream returns.
	//
	// existingCatalogDetail decides what counts as a catalog worth protecting.
	if len(tools) == 0 {
		if detail := existingCatalogDetail(cfg.ToolsPath, cfg.URL); detail != "" {
			return nil, fmt.Errorf("%w (%s).\nIf the catalog really is empty now, delete %s and sync again",
				errEmptyCatalog, detail, cfg.ToolsPath)
		}
	}
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
	params := json.RawMessage(fmt.Sprintf(`{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"bmcp","version":%q}}`, version))
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

// maxToolPages bounds the cursor loop below. SyncTimeout already bounds
// wall-clock, but a server that returns a fresh cursor forever would otherwise
// spend all of it accumulating pages.
//
// Set high enough that it is a runaway backstop rather than a catalog limit: a
// server free to choose its own page size is free to choose one, and refusing
// its 51st tool would be this client's bug, not the server's.
const maxToolPages = 1000

// listTools follows tools/list pagination to the end of the catalog.
//
// tools/list is a paginated MCP method: a server may answer with a page plus a
// nextCursor, and a compliant client keeps asking until the cursor is gone.
// BORIS returns everything in one page today, so this is latent — it stops
// being latent the moment the catalog crosses whatever page size the server
// picks, and nothing on the client side would say so. A short catalog is
// written to tools.json stamped LastSync: now, rendered into every installed
// instruction file, and then reads to an agent as "that tool does not exist"
// rather than "the catalog is truncated".
//
// The empty-catalog guard in syncTools does not cover this: it refuses a
// catalog with zero tools, and 1 of 13 is not zero. So anything short of a
// complete catalog has to fail here rather than be returned as the truth.
func (c *mcpClient) listTools(ctx context.Context) ([]tool, error) {
	// Non-nil so a genuinely empty catalog marshals to `"tools": []` rather than
	// `"tools": null` — tools.json is a documented file that people read with jq,
	// and iterating null is an error there.
	tools := []tool{}
	cursor := ""
	for page := 0; page < maxToolPages; page++ {
		req := jsonRPCRequest{JSONRPC: "2.0", ID: 2 + page, Method: "tools/list"}
		if cursor != "" {
			params, err := json.Marshal(map[string]string{"cursor": cursor})
			if err != nil {
				return nil, err
			}
			req.Params = params
		}
		body, err := c.rpc(ctx, req, true)
		if err != nil {
			return nil, err
		}
		// Tools is a pointer so a page that omits it, or sends null, is told
		// apart from one that sends []. Decoding into a plain slice made both
		// look like an empty final page: the accumulated tools from earlier
		// pages were then returned as a complete catalog, and being non-empty
		// they sailed past the empty-catalog guard and overwrote the real one.
		// ListToolsResult requires the array, so anything else is a broken page,
		// not an empty one.
		var result struct {
			Tools *[]struct {
				Name        string          `json:"name"`
				Description string          `json:"description"`
				InputSchema json.RawMessage `json:"inputSchema"`
			} `json:"tools"`
			NextCursor string `json:"nextCursor"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, err
		}
		if result.Tools == nil {
			return nil, fmt.Errorf("remote MCP returned a tools/list page with no tools array; refusing a possibly truncated catalog of %d %s",
				len(tools), pluralize(len(tools), "tool"))
		}
		for _, t := range *result.Tools {
			tools = append(tools, tool{Name: t.Name, Description: t.Description, InputSchema: nonEmptySchema(t.InputSchema)})
		}
		if result.NextCursor == "" {
			return tools, nil
		}
		// A cursor that does not advance is a server bug that would otherwise
		// look like a slow sync, then stop at the page cap with a misleading
		// error about catalog size.
		if result.NextCursor == cursor {
			return nil, fmt.Errorf("remote MCP repeated the same tools/list cursor; refusing a possibly truncated catalog of %d %s",
				len(tools), pluralize(len(tools), "tool"))
		}
		cursor = result.NextCursor
	}
	return nil, fmt.Errorf("remote MCP returned more than %d pages of tools/list; refusing a possibly truncated catalog of %d %s",
		maxToolPages, len(tools), pluralize(len(tools), "tool"))
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
	// The response has to be the answer to the request that was just sent. This
	// was academic while every session issued one request per id; paging makes a
	// session send several, so a server that echoes a stale id would have its
	// earlier page counted twice and the catalog silently reshaped.
	if id, ok := rpcResp.ID.(float64); ok && int(id) != rpcReq.ID {
		return nil, fmt.Errorf("remote MCP answered request %d with a response for %d", rpcReq.ID, int(id))
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
