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

var (
	ErrTLSNotAvailable = errors.New("TLS details not available")
	frontendClient     = &http.Client{Timeout: 10 * time.Second}
)

const maximumFrontendResponseBytes = 8 * 1024 * 1024

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

func proxyFrontend(frontendURL string, method string, requestURL *url.URL) ([]byte, string, error) {
	if method != http.MethodGet && method != http.MethodHead {
		return nil, "", fmt.Errorf("frontend method %s is not supported", method)
	}

	target := strings.TrimRight(frontendURL, "/") + requestURL.EscapedPath()
	if requestURL.RawQuery != "" {
		target += "?" + requestURL.RawQuery
	}
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create frontend request: %w", err)
	}
	resp, err := frontendClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("frontend request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maximumFrontendResponseBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("failed to read frontend response: %w", err)
	}
	if len(body) > maximumFrontendResponseBytes {
		return nil, "", fmt.Errorf("frontend response exceeds %d bytes", maximumFrontendResponseBytes)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, "", fmt.Errorf("frontend returned %s", resp.Status)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = http.DetectContentType(body)
	}
	return body, contentType, nil
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
