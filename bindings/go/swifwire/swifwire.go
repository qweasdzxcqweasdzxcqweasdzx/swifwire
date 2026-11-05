// Package swifwire — Go embed helpers for 3x-ui style panels.
//
// Integration model (same idea as MTProto sidecar in 3x-ui):
//  1. Panel stores SwifWire inbound JSON in DB.
//  2. Supervisor starts `swif-edge` with EdgeArgv(inbound).
//  3. Optional: Xray socks outbound → edge egress bridge.
//  4. Subscription exports ShareURI for clients.
//
// Build native lib: `cargo build -p swif-ffi --release`
// Then either cgo-link the DLL, or call the pure-Go helpers below (JSON only).
package swifwire

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

const Protocol = "swifwire"

type OutboundSettings struct {
	Address           string  `json:"address"`
	Port              int     `json:"port"`
	ServerPubHex      string  `json:"server_pub_hex"`
	Mask              string  `json:"mask"`
	SNI               string  `json:"sni,omitempty"`
	SocksListen       string  `json:"socks_listen"`
	PackURL           string  `json:"pack_url,omitempty"`
	PackTrustPubHex   string  `json:"pack_trust_pub_hex,omitempty"`
}

type Outbound struct {
	Protocol string           `json:"protocol"`
	Tag      string           `json:"tag,omitempty"`
	Settings OutboundSettings `json:"settings"`
}

type InboundSettings struct {
	StaticKeyPath string `json:"static_key_path"`
	PubOutPath    string `json:"pub_out_path"`
	Mask          string `json:"mask"`
	SNI           string `json:"sni,omitempty"`
	Cover         string `json:"cover,omitempty"`
	Egress        string `json:"egress"`
}

type Inbound struct {
	Protocol string          `json:"protocol"`
	Listen   string          `json:"listen"`
	Port     int             `json:"port"`
	Tag      string          `json:"tag,omitempty"`
	Remark   string          `json:"remark,omitempty"`
	Settings InboundSettings `json:"settings"`
}

// EdgeArgv builds argv for swif-edge sidecar (without binary path).
func EdgeArgv(in Inbound) []string {
	if in.Listen == "" {
		in.Listen = "0.0.0.0"
	}
	if in.Settings.PubOutPath == "" {
		in.Settings.PubOutPath = "server.pub"
	}
	if in.Settings.Mask == "" {
		in.Settings.Mask = "tls13_stable"
	}
	args := []string{
		"--listen", fmt.Sprintf("%s:%d", in.Listen, in.Port),
		"--key", in.Settings.StaticKeyPath,
		"--pub-out", in.Settings.PubOutPath,
		"--mask", in.Settings.Mask,
	}
	if in.Settings.SNI != "" {
		args = append(args, "--sni", in.Settings.SNI)
	}
	if in.Settings.Cover != "" {
		args = append(args, "--cover", in.Settings.Cover)
	}
	return args
}

// ShareURI builds swif:// link for subscription.
func ShareURI(publicHost string, port int, serverPubHex, mask, sni string) string {
	if mask == "" {
		mask = "tls13_stable"
	}
	u := fmt.Sprintf("swif://%s:%d?pub=%s&mask=%s", publicHost, port, serverPubHex, mask)
	if sni != "" {
		u += "&sni=" + sni
	}
	return u
}

// Supervisor runs one swif-edge child for an inbound (3x-ui sidecar pattern).
type Supervisor struct {
	EdgeBin string
	WorkDir string
	cmd     *exec.Cmd
}

func (s *Supervisor) Start(in Inbound) error {
	_ = s.Stop()
	bin := s.EdgeBin
	if bin == "" {
		bin = "swif-edge"
	}
	args := EdgeArgv(in)
	s.cmd = exec.Command(bin, args...)
	if s.WorkDir != "" {
		s.cmd.Dir = s.WorkDir
	}
	s.cmd.Stdout = os.Stdout
	s.cmd.Stderr = os.Stderr
	return s.cmd.Start()
}

func (s *Supervisor) Stop() error {
	if s.cmd == nil || s.cmd.Process == nil {
		return nil
	}
	err := s.cmd.Process.Kill()
	s.cmd = nil
	return err
}

// XraySocksBridgeSnippet returns a minimal Xray outbound JSON fragment
// that sends traffic into a local SOCKS (when edge egress is bridged the other way,
// panel usually adds socks inbound for edge→xray; this is for client-style chaining).
func XraySocksBridgeSnippet(tag, listen string) json.RawMessage {
	// listen "127.0.0.1:11080"
	host := "127.0.0.1"
	port := 11080
	if h, p, ok := splitHostPort(listen); ok {
		host, port = h, p
	}
	raw, _ := json.Marshal(map[string]any{
		"tag":      tag,
		"protocol": "socks",
		"settings": map[string]any{
			"servers": []map[string]any{{
				"address": host,
				"port":    port,
			}},
		},
	})
	return raw
}

func splitHostPort(s string) (string, int, bool) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			p, err := strconv.Atoi(s[i+1:])
			if err != nil {
				return "", 0, false
			}
			return s[:i], p, true
		}
	}
	return "", 0, false
}

// ExampleInbound for docs/tests.
func ExampleInbound(port int, keyPath string) Inbound {
	return Inbound{
		Protocol: Protocol,
		Listen:   "0.0.0.0",
		Port:     port,
		Tag:      "swif-in",
		Remark:   "SwifWire",
		Settings: InboundSettings{
			StaticKeyPath: keyPath,
			PubOutPath:    filepath.Join(filepath.Dir(keyPath), "server.pub"),
			Mask:          "tls13_stable",
			SNI:           "cover.local",
			Egress:        "direct",
		},
	}
}
