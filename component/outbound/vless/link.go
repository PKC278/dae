package vless

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/transport/meek"

	mo "github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/transport/xhttp"
)

// NewVless builds a VLESS dialer from a share link, following the Xray
// VLESS/VMessAEAD share-link standard:
// https://github.com/XTLS/Xray-core/discussions/716
//
// The parameter mapping mirrors mihomo's own converter so that a link that
// works in mihomo works here.
func NewVless(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, nil, err
	}
	if u.Scheme != "vless" {
		return nil, nil, dialer.InvalidParameterErr
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, nil, fmt.Errorf("invalid port %q: %w", u.Port(), err)
	}

	q := u.Query()
	opt := mo.VlessOption{
		Name:   u.Fragment,
		Server: u.Hostname(),
		Port:   port,
		UUID:   u.User.Username(),
		UDP:    true,
		Flow:   strings.ToLower(q.Get("flow")),
	}

	if enc := q.Get("encryption"); enc != "none" {
		opt.Encryption = enc
	}

	// Note: "none" (the original single-destination UDP tunnel) is not
	// reachable here. mihomo's adapter forces XUDP whenever packet-addr is off,
	// so a link asking for "none" transparently gets XUDP instead.
	switch q.Get("packetEncoding") {
	case "packet", "packetaddr":
		opt.PacketAddr = true
	default:
		opt.XUDP = true
	}

	base, err := buildBaseDialer(nextDialer, &opt, q, option)
	if err != nil {
		return nil, nil, err
	}

	d, err := NewDialer(base, opt)
	if err != nil {
		return nil, nil, err
	}
	return d, &dialer.Property{
		Name:     opt.Name,
		Address:  net.JoinHostPort(opt.Server, strconv.Itoa(opt.Port)),
		Protocol: "vless",
		Link:     link,
	}, nil
}

// buildBaseDialer composes the layers dae still owns below the VLESS protocol
// onto nextDialer, which is what mihomo ends up dialing through. It also
// settles opt.Network for the transports mihomo does not implement.
func buildBaseDialer(nextDialer netproxy.Dialer, opt *mo.VlessOption, q url.Values, extra *dialer.ExtraOption) (netproxy.Dialer, error) {
	base := nextDialer
	// Fragmentation goes first, so it also splits the ClientHello of a
	// transport stacked above it, such as meek's.
	if extra.TlsFragment {
		fragmented, err := newFragmentDialer(base, extra.TlsFragmentLength, extra.TlsFragmentInterval)
		if err != nil {
			return nil, err
		}
		base = fragmented
	}

	if strings.EqualFold(q.Get("type"), "meek") {
		// mihomo has no meek, so dae keeps its own. meek carries its own HTTPS,
		// and VLESS rides the resulting stream as plain TCP.
		meekDialer, err := newMeekDialer(base, q, extra, opt.Server, opt.Port)
		if err != nil {
			return nil, err
		}
		opt.Network = "tcp"
		return meekDialer, nil
	}

	applySecurity(opt, q, extra)
	if err := applyTransport(opt, q); err != nil {
		return nil, err
	}
	return base, nil
}

// applySecurity fills in the TLS layer and whichever camouflage sits on top of
// it. REALITY, ECH, JLS, Restls and ShadowTLS are mutually exclusive; mihomo
// rejects any combination of them at construction time.
func applySecurity(opt *mo.VlessOption, q url.Values, extra *dialer.ExtraOption) {
	security := strings.ToLower(q.Get("security"))
	opt.TLS = strings.HasSuffix(security, "tls") || security == "reality"
	opt.SkipCertVerify = extra.AllowInsecure || boolParam(q, "allowInsecure")

	if sni := q.Get("sni"); sni != "" {
		opt.ServerName = sni
	} else if peer := q.Get("peer"); peer != "" {
		opt.ServerName = peer
	}
	if alpn := q.Get("alpn"); alpn != "" {
		opt.ALPN = strings.Split(alpn, ",")
	}
	// "pcs" pins the server certificate; distinct from "fp", which selects the
	// uTLS ClientHello to imitate.
	if pcs := q.Get("pcs"); pcs != "" {
		opt.Fingerprint = pcs
	}
	if opt.TLS {
		if fp := q.Get("fp"); fp != "" {
			opt.ClientFingerprint = fp
		} else if extra.UtlsImitate != "" && extra.TlsImplementation == "utls" {
			opt.ClientFingerprint = extra.UtlsImitate
		} else {
			opt.ClientFingerprint = "chrome"
		}
	}

	if pbk := q.Get("pbk"); pbk != "" {
		opt.RealityOpts = mo.RealityOptions{
			PublicKey:             pbk,
			ShortID:               q.Get("sid"),
			SupportX25519MLKEM768: boolParam(q, "mldsa65Verify") || boolParam(q, "pqv"),
		}
	}
	if boolParam(q, "ech") || q.Get("echCfg") != "" {
		opt.ECHOpts = mo.ECHOptions{
			Enable: true,
			Config: q.Get("echCfg"),
		}
	}
}

func applyTransport(opt *mo.VlessOption, q url.Values) error {
	network := strings.ToLower(q.Get("type"))
	if network == "" {
		network = "tcp"
	}
	// A "tcp" node with an HTTP header disguise is a distinct transport in
	// mihomo, and "http" in a share link means HTTP/2.
	headerType := strings.ToLower(q.Get("headerType"))
	if network == "tcp" && headerType == "http" {
		network = "http"
	} else if network == "http" {
		network = "h2"
	}
	opt.Network = network

	switch network {
	case "tcp":
	case "http":
		httpOpts := mo.HTTPOptions{Path: []string{"/"}}
		if path := q.Get("path"); path != "" {
			httpOpts.Path = []string{path}
		}
		if method := q.Get("method"); method != "" {
			httpOpts.Method = method
		}
		if host := q.Get("host"); host != "" {
			httpOpts.Headers = map[string][]string{"Host": {host}}
		}
		opt.HTTPOpts = httpOpts
	case "h2":
		h2Opts := mo.HTTP2Options{Path: "/"}
		if path := q.Get("path"); path != "" {
			h2Opts.Path = path
		}
		if host := q.Get("host"); host != "" {
			h2Opts.Host = []string{host}
		}
		opt.HTTP2Opts = h2Opts
	case "ws", "httpupgrade":
		wsOpts := mo.WSOptions{
			Path:    q.Get("path"),
			Headers: map[string]string{},
		}
		if host := q.Get("host"); host != "" {
			wsOpts.Headers["Host"] = host
		}
		if ed := q.Get("ed"); ed != "" {
			maxEarlyData, err := strconv.Atoi(ed)
			if err != nil {
				return fmt.Errorf("bad WebSocket max early data size %q: %w", ed, err)
			}
			switch network {
			case "ws":
				wsOpts.MaxEarlyData = maxEarlyData
				wsOpts.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
			case "httpupgrade":
				wsOpts.V2rayHttpUpgradeFastOpen = true
			}
		}
		if eh := q.Get("eh"); eh != "" {
			wsOpts.EarlyDataHeaderName = eh
		}
		if network == "httpupgrade" {
			// mihomo models HTTPUpgrade as a WebSocket variant.
			opt.Network = "ws"
			wsOpts.V2rayHttpUpgrade = true
		}
		opt.WSOpts = wsOpts
	case "grpc":
		opt.GrpcOpts = mo.GrpcOptions{
			GrpcServiceName: q.Get("serviceName"),
			GrpcUserAgent:   q.Get("userAgent"),
		}
	case "xhttp":
		xhttpOpts := mo.XHTTPOptions{
			Path: q.Get("path"),
			Host: q.Get("host"),
			Mode: q.Get("mode"),
		}
		// Xray packs the advanced knobs into a JSON blob under "extra".
		if extra := q.Get("extra"); extra != "" {
			var raw map[string]any
			if err := json.Unmarshal([]byte(extra), &raw); err != nil {
				return fmt.Errorf("bad xhttp extra: %w", err)
			}
			applyXHTTPExtra(&xhttpOpts, raw)
		}
		// mihomo only parses the padding range lazily, when a request is built,
		// so a typo would surface as a runtime failure long after the config
		// was loaded. dae validates node links up front, so check it here.
		if xhttpOpts.XPaddingBytes != "" {
			if _, err := xhttp.ParseRange(xhttpOpts.XPaddingBytes, ""); err != nil {
				return fmt.Errorf("bad xhttp x-padding-bytes %q: %w", xhttpOpts.XPaddingBytes, err)
			}
		}
		opt.XHTTPOpts = xhttpOpts
	default:
		return fmt.Errorf("%w: network: %v", dialer.UnexpectedFieldErr, network)
	}
	return nil
}

// applyXHTTPExtra maps the xray-core "extra" object onto mihomo's xhttp-opts.
func applyXHTTPExtra(opts *mo.XHTTPOptions, extra map[string]any) {
	str := func(key string) string {
		switch v := extra[key].(type) {
		case string:
			return v
		case float64:
			return strconv.FormatInt(int64(v), 10)
		}
		return ""
	}
	if v, ok := extra["noGRPCHeader"].(bool); ok {
		opts.NoGRPCHeader = v
	}
	if v, ok := extra["xPaddingObfsMode"].(bool); ok {
		opts.XPaddingObfsMode = v
	}
	for key, dst := range map[string]*string{
		"xPaddingBytes":        &opts.XPaddingBytes,
		"xPaddingKey":          &opts.XPaddingKey,
		"xPaddingHeader":       &opts.XPaddingHeader,
		"xPaddingPlacement":    &opts.XPaddingPlacement,
		"xPaddingMethod":       &opts.XPaddingMethod,
		"uplinkHTTPMethod":     &opts.UplinkHTTPMethod,
		"sessionPlacement":     &opts.SessionPlacement,
		"sessionKey":           &opts.SessionKey,
		"sessionTable":         &opts.SessionTable,
		"sessionLength":        &opts.SessionLength,
		"seqPlacement":         &opts.SeqPlacement,
		"seqKey":               &opts.SeqKey,
		"uplinkDataPlacement":  &opts.UplinkDataPlacement,
		"uplinkDataKey":        &opts.UplinkDataKey,
		"uplinkChunkSize":      &opts.UplinkChunkSize,
		"scMaxEachPostBytes":   &opts.ScMaxEachPostBytes,
		"scMinPostsIntervalMs": &opts.ScMinPostsIntervalMs,
	} {
		if v := str(key); v != "" {
			*dst = v
		}
	}
	if xmux, ok := extra["xmux"].(map[string]any); ok {
		reuse := &mo.XHTTPReuseSettings{}
		for key, dst := range map[string]*string{
			"maxConnections":   &reuse.MaxConnections,
			"maxConcurrency":   &reuse.MaxConcurrency,
			"cMaxReuseTimes":   &reuse.CMaxReuseTimes,
			"hMaxRequestTimes": &reuse.HMaxRequestTimes,
			"hMaxReusableSecs": &reuse.HMaxReusableSecs,
		} {
			switch v := xmux[key].(type) {
			case string:
				*dst = v
			case float64:
				*dst = strconv.FormatInt(int64(v), 10)
			}
		}
		if v, ok := xmux["hKeepAlivePeriod"].(float64); ok {
			reuse.HKeepAlivePeriod = int(v)
		}
		opts.ReuseSettings = reuse
	}
}

func boolParam(q url.Values, key string) bool {
	v, _ := strconv.ParseBool(q.Get(key))
	return v
}

// newMeekDialer builds dae's meek transport for a VLESS link. meek is an
// HTTP-polling transport with domain fronting: the TLS handshake advertises
// serverName while the requests target the "url" endpoint, which may live on a
// different host behind the same CDN.
func newMeekDialer(next netproxy.Dialer, q url.Values, extra *dialer.ExtraOption, server string, port int) (netproxy.Dialer, error) {
	target := q.Get("url")
	if target == "" {
		return nil, fmt.Errorf("%w: meek requires a url parameter", dialer.InvalidParameterErr)
	}
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	u := url.URL{
		Scheme: "meek",
		Host:   net.JoinHostPort(server, strconv.Itoa(port)),
		RawQuery: url.Values{
			"url":           []string{target},
			"alpn":          []string{q.Get("alpn")},
			"serverName":    []string{sni},
			"allowInsecure": []string{strconv.FormatBool(extra.AllowInsecure || boolParam(q, "allowInsecure"))},
		}.Encode(),
	}
	return meek.NewDialer(u.String(), next)
}
