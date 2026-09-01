package server

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pagpeter/trackme/pkg/tls"
	"github.com/pagpeter/trackme/pkg/types"
	"github.com/pagpeter/trackme/pkg/utils"
)

func Log(msg string) {
	t := time.Now()
	formatted := t.Format("2006-01-02 15:04:05")
	fmt.Printf("[%v] %v\n", formatted, msg)
}

func cleanIP(ip string) string {
	return strings.Replace(strings.Replace(ip, "]", "", -1), "[", "", -1)
}

// Router returns the response that should be sent to the client.
func Router(path string, res types.Response, srv *Server) (Result, error) {
	if v, ok := srv.GetTCPFingerprints().Load(res.IP); ok {
		res.TCPIP = v.(types.TCPIPDetails)
	}
	if syn, p0f, ok := srv.TakeTCPSyn(res.IP); ok {
		res.TCPIP.TCPSyn = &syn
		res.TCPIP.P0F = p0f
	}
	res.Donate = "Please consider donating to keep this API running. Visit https://tls.peet.ws"
	if res.TLS != nil {
		// Use QUIC JA4 for HTTP/3 connections
		if res.HTTPVersion == "h3" {
			res.TLS.JA4 = tls.CalculateJa4QUIC(res.TLS)
			res.TLS.JA4_r = tls.CalculateJa4QUIC_r(res.TLS)
		} else {
			res.TLS.JA4 = tls.CalculateJa4(res.TLS)
			res.TLS.JA4_r = tls.CalculateJa4_r(res.TLS)
		}
		Log(fmt.Sprintf("%v %v %v %v %v", cleanIP(res.IP), res.Method, res.HTTPVersion, res.Path, res.TLS.JA3Hash))
	} else {
		Log(fmt.Sprintf("%v %v %v %v %v", cleanIP(res.IP), res.Method, res.HTTPVersion, res.Path, "-"))
	}

	srv.LogParquet(res)

	u, err := url.Parse("https://tls.peet.ws" + path)
	var m map[string][]string
	if err != nil || u == nil {
		m = make(map[string][]string)
	} else {
		m, err = url.ParseQuery(u.RawQuery)
		if err != nil {
			m = make(map[string][]string)
		}
	}

	paths := getAllPaths()
	if u != nil {
		if val, ok := paths[u.Path]; ok && u.Path == "/api/all" {
			return handle(val, res, m)
		}
		if cfg := srv.GetConfig(); cfg.FrontendURL != "" {
			return proxyFrontend(cfg.FrontendURL, res.Method, u, cfg.FrontendMaxBytes)
		}
		if val, ok := paths[u.Path]; ok {
			return handle(val, res, m)
		}
	}
	// 404
	b, err := utils.ReadFile("static/404.html")
	if err != nil {
		return Result{Body: []byte(`{"error": "page not found"}`), ContentType: "application/json"}, nil
	}
	return Result{Body: []byte(b), ContentType: "text/html"}, nil
}

// handle adapts a RouteHandler, which has no notion of a status code, to the
// Result the writers now expect. These handlers always mean 200.
func handle(h RouteHandler, res types.Response, m url.Values) (Result, error) {
	b, ctype, err := h(res, m)
	if err != nil {
		return Result{}, err
	}
	return Result{Body: b, ContentType: ctype}, nil
}
