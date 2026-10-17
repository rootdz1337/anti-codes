package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ============================================================================
// Anti-Network Module
//
// Network provenance and monitoring detection. Complements NetworkEvasion by
// answering the *defensive* questions:
//
//   1. What network is this host on (adapter, gateway, DNS, proxies, VPN)?
//   2. Who sees my traffic (proxy, VPN, TLS interceptor, DNS resolver)?
//   3. What is my public egress IP and how does it differ from my local IP?
//   4. Is DNS leaking outside a VPN/proxy tunnel?
//   5. Is there a TLS-inspecting middlebox on the path?
//   6. What local services are listening (C2 detection surface)?
//   7. Are firewall rules unusually tight (EDR/AV network blocking)?
//
// All operations are read-only. No connections are made except read-only
// probes (TLS handshake to a public endpoint, one DNS query to a canary).
// ============================================================================

// NetSignal enumerates what a network finding implies.
type NetSignal string

const (
	SigAdapter         NetSignal = "adapter"
	SigGateway         NetSignal = "gateway"
	SigDNS             NetSignal = "dns-resolver"
	SigProxy           NetSignal = "proxy"
	SigVPN             NetSignal = "vpn"
	SigPublicIP        NetSignal = "public-ip"
	SigDNSLeak         NetSignal = "dns-leak"
	SigTLSIntercept    NetSignal = "tls-intercept"
	SigLocalListener   NetSignal = "local-listener"
	SigFirewall        NetSignal = "firewall"
	SigRoutes          NetSignal = "routes"
	SigPAC             NetSignal = "pac"
	SigProxyAuth       NetSignal = "proxy-auth"
)

// NetFinding is one piece of evidence.
type NetFinding struct {
	Signal   NetSignal
	Key      string
	Value    string
	Detail   string
	Severity PatchSeverity
}

// AdapterInfo describes one network interface.
type AdapterInfo struct {
	Name        string
	MAC         string
	IPs         []net.IP
	Gateway     net.IP
	DNS         []net.IP
	IsLoopback  bool
	IsVirtual   bool  // TAP/TUN/WSL/Docker/Hyper-V
	IsVPN       bool  // WireGuard/OpenVPN/IPSec tunnel
	MTU         int
	Up          bool
}

// TLSInterceptReport captures TLS middlebox detection.
type TLSInterceptReport struct {
	Intercepted  bool
	Issuer       string
	Subject      string
	NotAfter     time.Time
	SerialValid  bool
	Reason       string
	Severity     PatchSeverity
}

// NetReport is the module's output.
type NetReport struct {
	Adapters     []AdapterInfo
	DNSResolvers []net.IP
	Proxies      *ProxyConfig
	Gateway      net.IP
	PublicIP     net.IP
	LocalIP      net.IP
	VPN          bool
	TLSIntercept *TLSInterceptReport
	DNSLeak      bool
	LocalPorts   []LocalListener
	Firewall     *FirewallPosture
	Findings     []NetFinding
	Notes        string
}

// ProxyConfig captures system proxy settings.
type ProxyConfig struct {
	Enabled  bool
	HTTP     string
	HTTPS    string
	PAC      string
	Bypass   string
	AuthReq  bool
	Source   string // "registry", "env", "winhttp"
}

// LocalListener describes a listening socket.
type LocalListener struct {
	Addr    string
	Port    int
	Process string
	PID     uint32
	Public  bool // 0.0.0.0 or [::] vs 127.0.0.1
}

// FirewallPosture captures high-level firewall state.
type FirewallPosture struct {
	DomainEnabled  bool
	PrivateEnabled bool
	PublicEnabled  bool
	BlockAllInbound bool
	BlockAllOutbound bool
	Profile        string
}

// AntiNet is the scanner.
type AntiNet struct {
	// CanaryHosts are queried to detect DNS leaks and TLS interception.
	// One HTTPS handshake, one DNS query per canary. Never sends data.
	CanaryHosts []string

	// PublicIPProbes are HTTP endpoints returning the client's public IP.
	// Empty disables egress probing.
	PublicIPProbes []string

	// TLSProbeTimeout bounds the canary handshake.
	TLSProbeTimeout time.Duration

	// MaxLocalPorts caps the listener enumeration.
	MaxLocalPorts int

	mu sync.Mutex
}

// DefaultAntiNet returns the standard configuration.
func DefaultAntiNet() *AntiNet {
	return &AntiNet{
		CanaryHosts: []string{
			// Cloudflare-hosted, widely reachable
			"cloudflare.com",
			// Microsoft, commonly allowlisted
			"www.microsoft.com",
		},
		PublicIPProbes: []string{
			"https://api.ipify.org",
			"https://ifconfig.me/ip",
		},
		TLSProbeTimeout: 5 * time.Second,
		MaxLocalPorts:   512,
	}
}

// ---------------------------------------------------------------------------
// Adapter enumeration
// ---------------------------------------------------------------------------

// scanAdapters enumerates network interfaces and classifies each one.
func (an *AntiNet) scanAdapters() []AdapterInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []AdapterInfo
	for _, iface := range ifaces {
		info := AdapterInfo{
			Name:       iface.Name,
			MAC:        iface.HardwareAddr.String(),
			MTU:        iface.MTU,
			IsLoopback: iface.Flags&net.FlagLoopback != 0,
			Up:         iface.Flags&net.FlagUp != 0,
		}
		if iface.Flags&net.FlagLoopback == 0 {
			addrs, _ := iface.Addrs()
			for _, a := range addrs {
				ip, _, err := net.ParseCIDR(a.String())
				if err != nil {
					continue
				}
				info.IPs = append(info.IPs, ip)
				if ip.To4() != nil && !ip.IsLoopback() && info.IPs[0].IsLoopback() {
					info.IPs[0] = ip
				}
			}
		}
		// Classify by name — heuristic but portable.
		nameLower := strings.ToLower(iface.Name)
		switch {
		case strings.Contains(nameLower, "wsl") ||
			strings.Contains(nameLower, "docker") ||
			strings.Contains(nameLower, "veth") ||
			strings.Contains(nameLower, "vmnet") ||
			strings.Contains(nameLower, "hyper-v") ||
			strings.Contains(nameLower, "vmware") ||
			strings.Contains(nameLower, "virtualbox"):
			info.IsVirtual = true
		case strings.Contains(nameLower, "tap") ||
			strings.Contains(nameLower, "tun") ||
			strings.Contains(nameLower, "wg") ||
			strings.Contains(nameLower, "wireguard") ||
			strings.Contains(nameLower, "openvpn") ||
			strings.Contains(nameLower, "ppp") ||
			strings.Contains(nameLower, "ipsec") ||
			strings.Contains(nameLower, "ipvanish") ||
			strings.Contains(nameLower, "nordlynx"):
			info.IsVPN = true
		}
		out = append(out, info)
	}
	return out
}

// findGateway returns the default gateway IP for the given adapter. On
// Windows this is read from the routing table; on Linux from /proc/net/route.
func (an *AntiNet) findGateway(ifaceName string) net.IP {
	if runtime.GOOS == "windows" {
		return gatewayFromRoutePrint(ifaceName)
	}
	if runtime.GOOS == "linux" {
		return gatewayFromProcRoute()
	}
	return nil
}

// gatewayFromRoutePrint parses `route print -4 0.0.0.0` output for the
// default route's gateway. Uses cmd shell-out because it's the simplest
// portable path.
func gatewayFromRoutePrint(ifaceName string) net.IP {
	out, err := runExternal("route", "print", "-4", "0.0.0.0")
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// Default route has destination 0.0.0.0 and mask 0.0.0.0
		if fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			gw := net.ParseIP(fields[2])
			if gw != nil {
				return gw
			}
		}
	}
	return nil
}

// gatewayFromProcRoute reads /proc/net/route for the default gateway.
func gatewayFromProcRoute() net.IP {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if fields[1] != "00000000" {
			continue
		}
		// Gateway is little-endian hex.
		hexStr := fields[2]
		if len(hexStr) != 8 {
			continue
		}
		var b [4]byte
		for i := 0; i < 4; i++ {
			var v uint32
			fmt.Sscanf(hexStr[i*2:i*2+2], "%02x", &v)
			b[3-i] = byte(v)
		}
		return net.IP(b[:])
	}
	return nil
}

// ---------------------------------------------------------------------------
// DNS resolver detection
// ---------------------------------------------------------------------------

// scanDNSResolvers returns the configured DNS servers.
func (an *AntiNet) scanDNSResolvers() []net.IP {
	if runtime.GOOS == "windows" {
		return dnsFromIpconfig()
	}
	if runtime.GOOS == "linux" {
		return dnsFromResolvConf()
	}
	return nil
}

// dnsFromIpconfig shells out to `ipconfig /all` and parses DNS Servers lines.
func dnsFromIpconfig() []net.IP {
	out, err := runExternal("ipconfig", "/all")
	if err != nil {
		return nil
	}
	var ips []net.IP
	var inDNS bool
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "DNS Servers") {
			inDNS = true
			if idx := strings.Index(line, ":"); idx >= 0 {
				if ip := net.ParseIP(strings.TrimSpace(line[idx+1:])); ip != nil {
					ips = append(ips, ip)
				}
			}
			continue
		}
		if inDNS {
			// Continuation lines are indented and contain a bare IP.
			if ip := net.ParseIP(line); ip != nil {
				ips = append(ips, ip)
				continue
			}
			inDNS = false
		}
	}
	return ips
}

// dnsFromResolvConf parses /etc/resolv.conf.
func dnsFromResolvConf() []net.IP {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var ips []net.IP
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if ip := net.ParseIP(parts[1]); ip != nil {
					ips = append(ips, ip)
				}
			}
		}
	}
	return ips
}

// ---------------------------------------------------------------------------
// Proxy configuration
// ---------------------------------------------------------------------------

// scanProxies reads the system proxy configuration from env first (works
// everywhere), then from the Windows registry / WinHTTP if empty.
func (an *AntiNet) scanProxies() *ProxyConfig {
	cfg := &ProxyConfig{}

	// 1. Environment variables.
	if v := os.Getenv("HTTPS_PROXY"); v != "" {
		cfg.HTTPS = v
		cfg.Enabled = true
		cfg.Source = "env"
	}
	if v := os.Getenv("HTTP_PROXY"); v != "" {
		cfg.HTTP = v
		cfg.Enabled = true
		cfg.Source = "env"
	}
	if v := os.Getenv("ALL_PROXY"); v != "" {
		if cfg.HTTP == "" {
			cfg.HTTP = v
		}
		if cfg.HTTPS == "" {
			cfg.HTTPS = v
		}
		cfg.Enabled = true
		cfg.Source = "env"
	}
	if v := os.Getenv("NO_PROXY"); v != "" {
		cfg.Bypass = v
	}

	// 2. Windows registry.
	if runtime.GOOS == "windows" && !cfg.Enabled {
		reg := readProxyReg()
		if reg != nil {
			*cfg = *reg
		}
	}

	return cfg
}

// readProxyReg reads HKCU\Software\Microsoft\Windows\CurrentVersion\
// Internet Settings for ProxyEnable / ProxyServer / AutoConfigURL.
func readProxyReg() *ProxyConfig {
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	regOpenKeyEx := advapi32.NewProc("RegOpenKeyExW")
	regQueryValueEx := advapi32.NewProc("RegQueryValueExW")
	regCloseKey := advapi32.NewProc("RegCloseKey")

	keyPath, _ := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Internet Settings`)
	var hKey syscall.Handle
	// HKCU = 0x80000001, KEY_READ = 0x20019
	ret, _, _ := regOpenKeyEx.Call(
		0x80000001,
		uintptr(unsafe.Pointer(keyPath)),
		0,
		0x20019,
		uintptr(unsafe.Pointer(&hKey)),
	)
	if ret != 0 {
		return nil
	}
	defer regCloseKey.Call(uintptr(hKey))

	readString := func(name string) string {
		ptr, _ := syscall.UTF16PtrFromString(name)
		var buf [2048]uint16
		size := uint32(len(buf) * 2)
		var valType uint32
		ret, _, _ := regQueryValueEx.Call(
			uintptr(hKey),
			uintptr(unsafe.Pointer(ptr)),
			0,
			uintptr(unsafe.Pointer(&valType)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
		)
		if ret != 0 {
			return ""
		}
		// REG_SZ=1, REG_EXPAND_SZ=2
		if valType == 1 || valType == 2 {
			return syscall.UTF16ToString(buf[:size/2])
		}
		return ""
	}

	cfg := &ProxyConfig{Source: "registry"}

	// ProxyEnable — REG_DWORD.
	ptr, _ := syscall.UTF16PtrFromString("ProxyEnable")
	var dword [4]byte
	size := uint32(4)
	var valType uint32
	ret, _, _ = regQueryValueEx.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(ptr)),
		0,
		uintptr(unsafe.Pointer(&valType)),
		uintptr(unsafe.Pointer(&dword[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 && valType == 4 {
		cfg.Enabled = binary.LittleEndian.Uint32(dword[:]) != 0
	}

	cfg.HTTP = readString("ProxyServer")
	if cfg.HTTP == "" {
		cfg.HTTPS = cfg.HTTP
	} else if strings.Contains(cfg.HTTP, "://") {
		// "http=...;https=..." format
		for _, part := range strings.Split(cfg.HTTP, ";") {
			if strings.HasPrefix(part, "http=") {
				cfg.HTTP = strings.TrimPrefix(part, "http=")
			}
			if strings.HasPrefix(part, "https=") {
				cfg.HTTPS = strings.TrimPrefix(part, "https=")
			}
		}
	}
	cfg.PAC = readString("AutoConfigURL")
	cfg.Bypass = readString("ProxyOverride")
	if cfg.PAC != "" {
		cfg.Enabled = true
	}
	if cfg.HTTP == "" && cfg.HTTPS == "" && cfg.PAC == "" {
		return nil
	}
	return cfg
}

// ---------------------------------------------------------------------------
// Public egress IP probe
// ---------------------------------------------------------------------------

// probePublicIP hits configured public-IP endpoints to discover our egress
// IP. One request per endpoint; no payload. Returns the first successful.
func (an *AntiNet) probePublicIP() net.IP {
	for _, url := range an.PublicIPProbes {
		ip := httpGetIP(url, 5*time.Second)
		if ip != nil {
			return ip
		}
	}
	return nil
}

// httpGetIP fetches a URL and parses the body as an IP address.
func httpGetIP(url string, timeout time.Duration) net.IP {
	// Use the stdlib HTTP client.
	client := newHTTPClientTimeout(timeout)
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	buf := make([]byte, 128)
	n, _ := resp.Body.Read(buf)
	return net.ParseIP(strings.TrimSpace(string(buf[:n])))
}

// ---------------------------------------------------------------------------
// TLS interception detection
// ---------------------------------------------------------------------------

// detectTLSIntercept completes a TLS handshake to a canary host and inspects
// the leaf certificate. Interception is suspected if:
//   - The issuer is not a well-known public CA.
//   - The issuer CN names an enterprise firewall (Zscaler, Palo Alto, etc.).
//   - The certificate chain is unusually short (self-signed middlebox).
func (an *AntiNet) detectTLSIntercept(host string) *TLSInterceptReport {
	addr := host
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}
	dialer := &net.Dialer{Timeout: an.TLSProbeTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // inspection only
	})
	if err != nil {
		return &TLSInterceptReport{Reason: "handshake failed: " + err.Error(), Severity: SevInfo}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return &TLSInterceptReport{Reason: "no peer certificate", Severity: SevSuspicious}
	}
	leaf := state.PeerCertificates[0]
	rep := &TLSInterceptReport{
		Issuer:   leaf.Issuer.CommonName,
		Subject:  leaf.Subject.CommonName,
		NotAfter: leaf.NotAfter,
	}
	issuerLower := strings.ToLower(leaf.Issuer.CommonName + " " + leaf.Issuer.Organization[0])

	// Known public CAs.
	publicCAs := []string{
		"digicert", "let's encrypt", "globalsign", "sectigo",
		"entrust", "godaddy", "amazon", "google trust services",
		"cloudflare", "microsoft", "comodo", "certum", "geotrust",
		"thawte", "verisign", "usertrust",
	}
	// Known TLS-inspecting middleboxes.
	inspectors := []string{
		"zscaler", "netskope", "palo alto", "fortinet", "fortigate",
		"check point", "cisco umbrella", "bluecoat", "symantec proxy",
		"sophos", "squid", "mitmproxy", "burp", "charles",
		"contentkeeper", "barracuda", "forcepoint", "mcafee web gateway",
	}
	for _, ca := range publicCAs {
		if strings.Contains(issuerLower, ca) {
			return nil // not intercepted
		}
	}
	for _, insp := range inspectors {
		if strings.Contains(issuerLower, insp) {
			rep.Intercepted = true
			rep.Reason = "issuer matches known TLS-inspecting middlebox: " + insp
			rep.Severity = SevCritical
			return rep
		}
	}
	// Unknown issuer, but short chain suggests a middlebox.
	if len(state.PeerCertificates) <= 2 {
		rep.Intercepted = true
		rep.Reason = "short chain with non-public issuer: " + rep.Issuer
		rep.Severity = SevSuspicious
		return rep
	}
	rep.Reason = "issuer: " + rep.Issuer
	rep.Severity = SevInfo
	return rep
}

// ---------------------------------------------------------------------------
// DNS leak detection
// ---------------------------------------------------------------------------

// detectDNSLeak checks whether the configured DNS resolver is reachable
// outside the VPN/proxy tunnel. If a VPN is active but the DNS server is on
// the same subnet as the VPN gateway's DNS, it's likely leaking.
//
// This is a *heuristic* — it does not query external DNS-leak services
// (which would be itself a privacy leak). It only checks resolver topology.
func (an *AntiNet) detectDNSLeak(adapters []AdapterInfo, resolvers []net.IP, vpn bool) bool {
	if !vpn || len(resolvers) == 0 {
		return false
	}
	for _, r := range resolvers {
		// Loopback DNS = stub resolver (systemd-resolved, dnsmasq) — not a leak.
		if r.IsLoopback() {
			continue
		}
		// Check if the resolver sits on the VPN adapter's subnet.
		onVPN := false
		for _, a := range adapters {
			if !a.IsVPN {
				continue
			}
			for _, ip := range a.IPs {
				mask := net.CIDRMask(24, 32)
				if r.To4() != nil && ip.To4() != nil {
					if r.Mask(mask).Equal(ip.Mask(mask)) {
						onVPN = true
						break
					}
				}
			}
		}
		// Resolver not on VPN subnet = likely leak.
		if !onVPN {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Local listener enumeration
// ---------------------------------------------------------------------------

// scanLocalListeners walks listening sockets and (where possible) resolves
// the owning process. Public listeners are flagged as potential C2.
func (an *AntiNet) scanLocalListeners() []LocalListener {
	var out []LocalListener
	if runtime.GOOS == "windows" {
		out = windowsListeners()
	} else if runtime.GOOS == "linux" {
		out = linuxListeners()
	}
	if len(out) > an.MaxLocalPorts {
		out = out[:an.MaxLocalPorts]
	}
	return out
}

// windowsListeners shells out to `netstat -ano -p TCP` and parses LISTENING.
func windowsListeners() []LocalListener {
	out, err := runExternal("netstat", "-ano", "-p", "TCP")
	if err != nil {
		return nil
	}
	pidToName := make(map[string]string)
	if procs, err := listProcesses(); err == nil {
		for _, p := range procs {
			pidToName[fmt.Sprintf("%d", p.PID)] = p.Name
		}
	}
	var listeners []LocalListener
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || !strings.EqualFold(fields[3], "LISTENING") {
			continue
		}
		local := fields[1]
		host, portStr, err := net.SplitHostPort(local)
		if err != nil {
			continue
		}
		var port int
		fmt.Sscanf(portStr, "%d", &port)
		ip := net.ParseIP(host)
		isPublic := !ip.IsLoopback()
		pid := fields[4]
		listeners = append(listeners, LocalListener{
			Addr:    local,
			Port:    port,
			Process: pidToName[pid],
			PID:     parseUint(pid),
			Public:  isPublic,
		})
	}
	return listeners
}

// linuxListeners parses /proc/net/tcp{,6} for LISTEN sockets.
func linuxListeners() []LocalListener {
	var out []LocalListener
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != "0A" { // 0A = LISTEN
				continue
			}
			local := fields[1]
			parts := strings.Split(local, ":")
			if len(parts) != 2 {
				continue
			}
			var port int
			fmt.Sscanf(parts[1], "%X", &port)
			isPublic := parts[0] != "0100007F" && parts[0] != "00000000"
			out = append(out, LocalListener{
				Addr:   fmt.Sprintf(":%d", port),
				Port:   port,
				Public: isPublic,
			})
		}
	}
	return out
}

// parseUint converts a string to uint32, returning 0 on failure.
func parseUint(s string) uint32 {
	var v uint32
	fmt.Sscanf(s, "%d", &v)
	return v
}

// ---------------------------------------------------------------------------
// Firewall posture
// ---------------------------------------------------------------------------

// scanFirewall reads the firewall profile state.
func (an *AntiNet) scanFirewall() *FirewallPosture {
	if runtime.GOOS == "windows" {
		return windowsFirewall()
	}
	return nil
}

// windowsFirewall uses Netsh to read profile state.
func windowsFirewall() *FirewallPosture {
	out, err := runExternal("netsh", "advfirewall", "show", "allprofiles", "state")
	if err != nil {
		return nil
	}
	state := &FirewallPosture{}
	var current string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Domain Profile") {
			current = "domain"
		} else if strings.HasPrefix(line, "Private Profile") {
			current = "private"
		} else if strings.HasPrefix(line, "Public Profile") {
			current = "public"
		}
		if strings.Contains(line, "State") && strings.Contains(line, "ON") {
			switch current {
			case "domain":
				state.DomainEnabled = true
			case "private":
				state.PrivateEnabled = true
			case "public":
				state.PublicEnabled = true
			}
		}
		if strings.Contains(line, "Outbound") && strings.Contains(line, "Block") {
			state.BlockAllOutbound = true
		}
		if strings.Contains(line, "Inbound") && strings.Contains(line, "Block") {
			state.BlockAllInbound = true
		}
	}
	if state.DomainEnabled && state.PrivateEnabled && state.PublicEnabled {
		state.Profile = "all"
	} else if state.PublicEnabled {
		state.Profile = "public"
	}
	return state
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

// Scan runs the full anti-network pipeline.
func (an *AntiNet) Scan() *NetReport {
	an.mu.Lock()
	defer an.mu.Unlock()

	rep := &NetReport{}

	rep.Adapters = an.scanAdapters()
	for _, a := range rep.Adapters {
		if a.IsVPN {
			rep.VPN = true
		}
		if !a.IsLoopback && a.Up && len(a.IPs) > 0 && !a.IsVirtual {
			if rep.LocalIP == nil {
				rep.LocalIP = a.IPs[0]
			}
			if a.Gateway == nil && an.Gateway == nil {
				a.Gateway = an.findGateway(a.Name)
				if a.Gateway != nil {
					rep.Gateway = a.Gateway
				}
			}
		}
		rep.Findings = append(rep.Findings, NetFinding{
			Signal:   SigAdapter,
			Key:      a.Name,
			Value:    a.MAC,
			Detail:   adapterDetail(a),
			Severity: adapterSeverity(a),
		})
	}

	rep.DNSResolvers = an.scanDNSResolvers()
	for _, r := range rep.DNSResolvers {
		rep.Findings = append(rep.Findings, NetFinding{
			Signal:   SigDNS,
			Key:      r.String(),
			Severity: SevInfo,
		})
	}

	rep.Proxies = an.scanProxies()
	if rep.Proxies != nil && rep.Proxies.Enabled {
		rep.Findings = append(rep.Findings, NetFinding{
			Signal:   SigProxy,
			Key:      rep.Proxies.Source,
			Value:    rep.Proxies.HTTP + "|" + rep.Proxies.HTTPS + "|" + rep.Proxies.PAC,
			Detail:   "system proxy configured",
			Severity: SevSuspicious,
		})
	}

	rep.PublicIP = an.probePublicIP()
	if rep.PublicIP != nil && rep.LocalIP != nil && !rep.PublicIP.Equal(rep.LocalIP) {
		rep.Findings = append(rep.Findings, NetFinding{
			Signal:   SigPublicIP,
			Key:      rep.PublicIP.String(),
			Value:    rep.LocalIP.String(),
			Detail:   "egress IP differs from local — NAT, VPN, or proxy in path",
			Severity: SevInfo,
		})
	}

	if len(an.CanaryHosts) > 0 {
		rep.TLSIntercept = an.detectTLSIntercept(an.CanaryHosts[0])
		if rep.TLSIntercept.Intercepted {
			rep.Findings = append(rep.Findings, NetFinding{
				Signal:   SigTLSIntercept,
				Key:      rep.TLSIntercept.Issuer,
				Detail:   rep.TLSIntercept.Reason,
				Severity: rep.TLSIntercept.Severity,
			})
		}
	}

	rep.DNSLeak = an.detectDNSLeak(rep.Adapters, rep.DNSResolvers, rep.VPN)
	if rep.DNSLeak {
		rep.Findings = append(rep.Findings, NetFinding{
			Signal:   SigDNSLeak,
			Detail:   "DNS resolvers are outside the VPN tunnel",
			Severity: SevCritical,
		})
	}

	rep.LocalPorts = an.scanLocalListeners()
	for _, l := range rep.LocalPorts {
		if l.Public {
			rep.Findings = append(rep.Findings, NetFinding{
				Signal:   SigLocalListener,
				Key:      l.Addr,
				Value:    l.Process,
				Detail:   fmt.Sprintf("public listener on %s (%s)", l.Addr, l.Process),
				Severity: SevSuspicious,
			})
		}
	}

	rep.Firewall = an.scanFirewall()
	if rep.Firewall != nil {
		if rep.Firewall.BlockAllOutbound {
			rep.Findings = append(rep.Findings, NetFinding{
				Signal:   SigFirewall,
				Detail:   "firewall blocks all outbound connections",
				Severity: SevCritical,
			})
		}
	}

	// Compose notes.
	var notes []string
	if rep.VPN {
		notes = append(notes, "VPN active")
	}
	if rep.TLSIntercept != nil && rep.TLSIntercept.Intercepted {
		notes = append(notes, "TLS interception detected")
	}
	if rep.DNSLeak {
		notes = append(notes, "DNS leak")
	}
	if rep.Proxies != nil && rep.Proxies.Enabled {
		notes = append(notes, "system proxy")
	}
	if rep.Firewall != nil && rep.Firewall.BlockAllOutbound {
		notes = append(notes, "outbound firewall block")
	}
	rep.Notes = strings.Join(notes, "; ")
	return rep
}

// adapterDetail returns a human-readable summary of one adapter.
func adapterDetail(a AdapterInfo) string {
	parts := []string{}
	if len(a.IPs) > 0 {
		parts = append(parts, "ip="+a.IPs[0].String())
	}
	if a.Gateway != nil {
		parts = append(parts, "gw="+a.Gateway.String())
	}
	if a.IsVPN {
		parts = append(parts, "vpn")
	}
	if a.IsVirtual {
		parts = append(parts, "virtual")
	}
	return strings.Join(parts, " ")
}

// adapterSeverity classifies how interesting an adapter is.
func adapterSeverity(a AdapterInfo) PatchSeverity {
	if a.IsVPN {
		return SevSuspicious
	}
	if a.IsVirtual {
		return SevInfo
	}
	return SevInfo
}

// ---------------------------------------------------------------------------
// Reporting helpers
// ---------------------------------------------------------------------------

// Summary returns a compact one-line status.
func (r *NetReport) Summary() string {
	if r == nil {
		return "no network analysis"
	}
	parts := []string{}
	if r.PublicIP != nil {
		parts = append(parts, "public="+r.PublicIP.String())
	}
	if r.VPN {
		parts = append(parts, "vpn")
	}
	if r.Proxies != nil && r.Proxies.Enabled {
		parts = append(parts, "proxy")
	}
	if r.TLSIntercept != nil && r.TLSIntercept.Intercepted {
		parts = append(parts, "tls-intercept")
	}
	if r.DNSLeak {
		parts = append(parts, "dns-leak")
	}
	if len(parts) == 0 {
		return "clean"
	}
	return strings.Join(parts, " ")
}

// CriticalFindings returns only SevCritical findings.
func (r *NetReport) CriticalFindings() []NetFinding {
	if r == nil {
		return nil
	}
	var out []NetFinding
	for _, f := range r.Findings {
		if f.Severity == SevCritical {
			out = append(out, f)
		}
	}
	return out
}

// IsConstrained returns true if the host is likely unable to egress freely.
func (r *NetReport) IsConstrained() bool {
	if r == nil {
		return false
	}
	if r.Firewall != nil && r.Firewall.BlockAllOutbound {
		return true
	}
	return false
}

// CrossReference joins anti-network findings with the sibling modules.
func (an *AntiNet) CrossReference(net *NetReport, graph *GraphReport, pomp *POMPReport, hooks *HookMap, patches []PatchReport) string {
	var parts []string
	if net != nil {
		if net.VPN {
			parts = append(parts, "vpn")
		}
		if net.Proxies != nil && net.Proxies.Enabled {
			parts = append(parts, "proxy")
		}
		if net.TLSIntercept != nil && net.TLSIntercept.Intercepted {
			parts = append(parts, "tls-intercept")
		}
		if net.DNSLeak {
			parts = append(parts, "dns-leak")
		}
		if net.IsConstrained() {
			parts = append(parts, "egress-blocked")
		}
	}
	if graph != nil && graph.OutlierScore > 0 {
		parts = append(parts, fmt.Sprintf("outlier=%d", graph.OutlierScore))
	}
	if pomp != nil && pomp.State != CertUnknown {
		parts = append(parts, fmt.Sprintf("pomp=%s", pomp.State))
	}
	if hooks != nil {
		if n := hooks.CriticalCount(); n > 0 {
			parts = append(parts, fmt.Sprintf("hooks=%d", n))
		}
	}
	if patches != nil {
		crit := 0
		for _, p := range patches {
			if p.Severity == SevCritical {
				crit++
			}
		}
		if crit > 0 {
			parts = append(parts, fmt.Sprintf("patches=%d", crit))
		}
	}
	if len(parts) == 0 {
		return "clean"
	}
	return strings.Join(parts, " ")
}

// ---------------------------------------------------------------------------
// Helpers — shared package primitives (stubbed here for compile isolation)
// ---------------------------------------------------------------------------

// runExternal is expected to be wired by the package owner (see antipatch.go).
var _ = runExternal

// newHTTPClientTimeout returns an HTTP client with the given timeout.
var newHTTPClientTimeout = func(timeout time.Duration) interface {
	Get(url string) (interface {
		Body interface {
			Read([]byte) (int, error)
			Close() error
		}
	}, error)
} {
	panic("newHTTPClientTimeout not wired")
}

// time referenced to avoid unused-import if built alone.
var _ = time.Now
var _ = tls.Config{}
var _ = x509.Certificate{}
var _ = filepath.Join
