package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pagpeter/trackme/pkg/types"
	"github.com/pagpeter/trackme/pkg/utils"
)

// RouteHandler is the function signature for route handlers
type RouteHandler func(types.Response, url.Values) ([]byte, string, error)

// Result is one response produced by the router.
//
// Status carries the frontend's own status code so that a proxied 204 or 304
// reaches the client as a 204 or 304. Collapsing everything to 200 breaks any
// client that distinguishes them -- an updater polling for "is there a new
// version" reads 204 as "no", and a 200 with an empty body as a parse error.
type Result struct {
	Status      int
	Body        []byte
	ContentType string
}

// StatusOrDefault returns the status to send, defaulting to 200 for handlers
// that do not set one.
func (r Result) StatusOrDefault() int {
	if r.Status == 0 {
		return http.StatusOK
	}
	return r.Status
}

var (
	ErrTLSNotAvailable = errors.New("TLS details not available")

	// No overall client timeout: it would also cap the body transfer, so a
	// large download over a slow link dies partway through for no good reason.
	// ResponseHeaderTimeout keeps the actual protection -- a frontend that
	// never answers still fails fast.
	frontendClient = &http.Client{
		Transport: &http.Transport{ResponseHeaderTimeout: 10 * time.Second},
	}
)

// defaultMaximumFrontendResponseBytes caps what we buffer from the frontend.
//
// The response is read fully into memory before it is written back, because
// the HTTP/1, HTTP/2 and HTTP/3 writers all take a []byte. 8 MiB used to be
// enough for a page, but the frontend now also serves desktop installers, and
// the cap turned that into a confusing `frontend response exceeds ...` error.
// Override with `frontend_max_bytes` when the frontend serves anything bigger.
const defaultMaximumFrontendResponseBytes = 64 * 1024 * 1024

// portalPublicHeader marks a request as arriving from the public internet.
//
// The frontend and the backend behind it use it to withhold private content.
// It is set unconditionally here: everything reaching this process came in over
// the public listener, so there is no such thing as a trusted caller on this
// path. A client-supplied value must never survive, or withholding is opt-out.
const portalPublicHeader = "X-Portal-Public"

func staticFile(file string) RouteHandler {
	return func(types.Response, url.Values) ([]byte, string, error) {
		b, err := utils.ReadFile(file)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read file %s: %w", file, err)
		}
		return b, "text/html", nil
	}
}

func apiAll(res types.Response, _ url.Values) ([]byte, string, error) {
	return []byte(res.ToJson()), "application/json", nil
}

func apiTLS(res types.Response, _ url.Values) ([]byte, string, error) {
	return []byte(types.Response{
		TLS: res.TLS,
	}.ToJson()), "application/json", nil
}

func apiClean(res types.Response, _ url.Values) ([]byte, string, error) {
	akamai := "-"
	hash := "-"
	if res.HTTPVersion == "h2" && res.Http2 != nil {
		akamai = res.Http2.AkamaiFingerprint
		hash = utils.GetMD5Hash(res.Http2.AkamaiFingerprint)
	} else if res.HTTPVersion == "h3" && res.Http3 != nil {
		akamai = res.Http3.AkamaiFingerprint
		hash = res.Http3.AkamaiFingerprintHash
	}

	smallRes := types.SmallResponse{
		Akamai:      akamai,
		AkamaiHash:  hash,
		HTTPVersion: res.HTTPVersion,
	}

	if res.TLS != nil {
		smallRes.JA3 = res.TLS.JA3
		smallRes.JA3Hash = res.TLS.JA3Hash
		smallRes.JA4 = res.TLS.JA4
		smallRes.JA4_r = res.TLS.JA4_r
		smallRes.PeetPrint = res.TLS.PeetPrint
		smallRes.PeetPrintHash = res.TLS.PeetPrintHash
	}

	return []byte(smallRes.ToJson()), "application/json", nil
}

func apiRaw(res types.Response, _ url.Values) ([]byte, string, error) {
	if res.TLS == nil {
		return nil, "", ErrTLSNotAvailable
	}
	return []byte(fmt.Sprintf(`{"raw": "%s", "raw_b64": "%s"}`, res.TLS.RawBytes, res.TLS.RawB64)), "application/json", nil
}

func proxyFrontend(frontendURL string, method string, requestURL *url.URL, maxBytes int64) (Result, error) {
	if method != http.MethodGet && method != http.MethodHead {
		return Result{}, fmt.Errorf("frontend method %s is not supported", method)
	}

	if maxBytes <= 0 {
		maxBytes = defaultMaximumFrontendResponseBytes
	}

	target := strings.TrimRight(frontendURL, "/") + requestURL.EscapedPath()
	if requestURL.RawQuery != "" {
		target += "?" + requestURL.RawQuery
	}
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		return Result{}, fmt.Errorf("failed to create frontend request: %w", err)
	}
	req.Header.Set(portalPublicHeader, "1")
	resp, err := frontendClient.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("frontend request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return Result{}, fmt.Errorf("failed to read frontend response: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return Result{}, fmt.Errorf("frontend response exceeds %d bytes", maxBytes)
	}

	// The status is passed through rather than turned into an error. A proxy
	// that answers 200 to everything hides 204, 304, 403 and 404 from the
	// client, and each of those means something the client needs to act on.
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" && len(body) > 0 {
		contentType = http.DetectContentType(body)
	}
	return Result{Status: resp.StatusCode, Body: body, ContentType: contentType}, nil
}

func index(r types.Response, v url.Values) ([]byte, string, error) {
	res, ct, err := staticFile("static/index.html")(r, v)
	if err != nil {
		return nil, "", err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal response: %w", err)
	}
	return []byte(strings.ReplaceAll(string(res), "/*DATA*/", string(data))), ct, nil
}

func getAllPaths() map[string]RouteHandler {
	return map[string]RouteHandler{
		"/":          index,
		"/explore":   staticFile("static/explore.html"),
		"/api/all":   apiAll,
		"/api/tls":   apiTLS,
		"/api/clean": apiClean,
		"/api/raw":   apiRaw,
	}
}
