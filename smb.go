package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cloudsoda/go-smb2"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"golang.org/x/net/proxy"
)

// ProxyConfig holds SOCKS proxy settings.
type ProxyConfig struct {
	Type      string // "socks4", "socks5", or ""
	Host      string
	Port      string
	Username  string
	Password  string
	DNSServer string // custom DNS server IP (e.g. "10.0.0.2" or "10.0.0.2:53")
}

// DirEntry represents a file or directory entry from an SMB share.
type DirEntry struct {
	Name      string
	IsDir     bool
	Size      int64
	LastWrite time.Time
}

// AuthMode distinguishes NTLM pass-the-hash from Kerberos ccache authentication.
type AuthMode int

const (
	AuthNTLM     AuthMode = iota // NTLM pass-the-hash
	AuthKerberos                 // Kerberos TGT from ccache
)

// SMBClient wraps go-smb2 for pass-the-hash and Kerberos SMB browsing.
type SMBClient struct {
	AuthMode AuthMode
	Domain   string
	Username string
	NTHash   []byte // raw 16-byte NT hash (NTLM mode)
	Target   string
	Port     int
	Proxy    *ProxyConfig

	// Kerberos fields
	ccachePath string
	krbClient  *client.Client
	krbSPN     string       // SPN from a pre-cached service ticket (TGS); empty = build from target
	kdcProxy   net.Listener // local proxy that forwards KDC traffic through SOCKS

	session    *smb2.Session
	conn       net.Conn
	mountCache map[string]*smb2.Share
	logFunc    func(string)
}

// NewSMBClient creates a new SMBClient for NTLM pass-the-hash. ntlmHash can be "LM:NT" or just "NT" hex string.
func NewSMBClient(domain, username, ntlmHash, target string, port int, proxyConf *ProxyConfig, logFunc func(string)) (*SMBClient, error) {
	target = strings.TrimSpace(target)
	target = strings.Trim(target, ":")
	if target == "" {
		return nil, fmt.Errorf("target address is empty")
	}
	if port == 0 {
		port = 445
	}

	// Parse NTLM hash - extract NT hash portion
	hashStr := ntlmHash
	if strings.Contains(ntlmHash, ":") {
		parts := strings.SplitN(ntlmHash, ":", 2)
		hashStr = parts[1] // Use the NT hash part
	}
	hashStr = strings.TrimSpace(hashStr)
	ntBytes, err := hex.DecodeString(hashStr)
	if err != nil {
		return nil, fmt.Errorf("invalid NTLM hash hex: %w", err)
	}
	if len(ntBytes) != 16 {
		return nil, fmt.Errorf("NT hash must be 16 bytes (32 hex chars), got %d bytes", len(ntBytes))
	}

	return &SMBClient{
		AuthMode:   AuthNTLM,
		Domain:     domain,
		Username:   username,
		NTHash:     ntBytes,
		Target:     target,
		Port:       port,
		Proxy:      proxyConf,
		mountCache: make(map[string]*smb2.Share),
		logFunc:    logFunc,
	}, nil
}

// NewSMBClientKerberos creates a new SMBClient that authenticates using a
// Kerberos ticket file.  Both .ccache (MIT ccache) and .kirbi (KRB_CRED /
// Mimikatz / Rubeus) formats are accepted.
func NewSMBClientKerberos(ticketPath, target, kdcHostOverride string, port int, proxyConf *ProxyConfig, logFunc func(string)) (*SMBClient, error) {
	target = strings.TrimSpace(target)
	target = strings.Trim(target, ":")
	if target == "" {
		return nil, fmt.Errorf("target address is empty")
	}
	if port == 0 {
		port = 445
	}
	if ticketPath == "" {
		return nil, fmt.Errorf("ticket file path is empty")
	}

	log := func(msg string) {
		if logFunc != nil {
			logFunc(msg)
		}
	}

	// Load the ticket file — detect format by extension.
	var ccache *credentials.CCache
	var err error
	ext := strings.ToLower(filepath.Ext(ticketPath))
	switch ext {
	case ".kirbi":
		ccache, err = loadKirbiAsCCache(ticketPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load kirbi file: %w", err)
		}
	default: // .ccache or any other extension
		ccache, err = credentials.LoadCCache(ticketPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load ccache file: %w", err)
		}
	}

	realm := ccache.DefaultPrincipal.Realm
	if realm == "" {
		return nil, fmt.Errorf("ccache has no default realm")
	}
	username := ccache.DefaultPrincipal.PrincipalName.PrincipalNameString()
	log(fmt.Sprintf("[INFO] Loaded ticket: principal=%s, realm=%s", username, realm))

	// Detect whether we have a service ticket (TGS) or a TGT.
	// If the ccache only contains a service ticket, we can use it directly
	// without contacting the KDC — the SPN is extracted from the ticket.
	var serviceSPN string
	for _, cred := range ccache.Credentials {
		sname := cred.Server.PrincipalName.PrincipalNameString()
		if !strings.HasPrefix(strings.ToLower(sname), "krbtgt/") {
			serviceSPN = sname
			log(fmt.Sprintf("[INFO] Found service ticket (TGS): SPN=%s", serviceSPN))
			break
		}
	}

	var kdcProxyLn net.Listener
	kdcAddr := "127.0.0.1:88" // placeholder for TGS-only tickets (KDC won't be contacted)

	// Only set up KDC resolution/proxy when we actually need the KDC
	// (i.e. we have a TGT and need to request a service ticket).
	if serviceSPN == "" {
		// Determine the KDC address for krb5.conf.
		// gokrb5 uses net.DialTimeout directly, so:
		//  1) We must give it an IP (not hostname) to avoid DNS resolution failures.
		//  2) If a SOCKS proxy is configured, we start a local TCP proxy that
		//     forwards KDC traffic through the SOCKS tunnel.
		//
		// If the caller provided an explicit KDC host, use that instead of target.
		kdcHost := target
		if kdcHostOverride != "" {
			kdcHost = kdcHostOverride
			log(fmt.Sprintf("[INFO] Using explicit KDC host: %s", kdcHost))
		}

		// Pre-resolve hostname → IP using custom DNS if configured.
		if proxyConf != nil && proxyConf.DNSServer != "" && net.ParseIP(kdcHost) == nil {
			resolved, err := resolveHostname(kdcHost, proxyConf)
			if err != nil {
				log(fmt.Sprintf("[WARN] Custom DNS resolution for KDC failed: %v", err))
			} else {
				log(fmt.Sprintf("[INFO] Resolved KDC %s → %s via DNS %s", kdcHost, resolved, proxyConf.DNSServer))
				kdcHost = resolved
			}
		}

		// If SOCKS proxy is configured, start a local port-forward for KDC traffic
		// because gokrb5 dials the KDC directly and doesn't know about our proxy.
		kdcAddr = net.JoinHostPort(kdcHost, "88")
		if proxyConf != nil && proxyConf.Host != "" && proxyConf.Port != "" {
			ln, localAddr, err := startKDCLocalProxy(kdcAddr, proxyConf, log)
			if err != nil {
				return nil, fmt.Errorf("failed to start KDC proxy: %w", err)
			}
			log(fmt.Sprintf("[INFO] KDC proxy: %s → (SOCKS) → %s", localAddr, kdcAddr))
			kdcAddr = localAddr
			kdcProxyLn = ln
		}
	} else {
		log("[INFO] Using pre-cached service ticket — KDC contact not required")
	}

	// Build krb5.conf with the (possibly proxied) KDC address.
	// dns_lookup_kdc = false:  we resolved the KDC ourselves.
	// udp_preference_limit = 1: force TCP (required for SOCKS tunnelling).
	krbConfStr := fmt.Sprintf(`[libdefaults]
  default_realm = %s
  dns_lookup_realm = false
  dns_lookup_kdc = false
  udp_preference_limit = 1

[realms]
  %s = {
    kdc = %s
  }
`, realm, realm, kdcAddr)

	cfg, err := config.NewFromString(krbConfStr)
	if err != nil {
		if kdcProxyLn != nil {
			kdcProxyLn.Close()
		}
		return nil, fmt.Errorf("failed to build krb5 config: %w", err)
	}

	krbClient, err := client.NewFromCCache(ccache, cfg)
	if err != nil {
		if kdcProxyLn != nil {
			kdcProxyLn.Close()
		}
		return nil, fmt.Errorf("failed to create Kerberos client from ccache: %w", err)
	}

	return &SMBClient{
		AuthMode:   AuthKerberos,
		Domain:     realm,
		Username:   username,
		Target:     target,
		Port:       port,
		Proxy:      proxyConf,
		ccachePath: ticketPath,
		krbClient:  krbClient,
		krbSPN:     serviceSPN,
		kdcProxy:   kdcProxyLn,
		mountCache: make(map[string]*smb2.Share),
		logFunc:    logFunc,
	}, nil
}

func (c *SMBClient) log(msg string) {
	if c.logFunc != nil {
		c.logFunc(msg)
	}
}

// Connect establishes the SMB session using NTLM or Kerberos, via SOCKS proxy if configured.
func (c *SMBClient) Connect() error {
	// If the target is a hostname (not an IP) and a custom DNS server is
	// configured, resolve it first via TCP DNS.  We keep the original
	// hostname in c.Target so the Kerberos SPN stays correct.
	connHost := c.Target
	if c.Proxy != nil && c.Proxy.DNSServer != "" && net.ParseIP(c.Target) == nil {
		resolved, err := c.resolveTarget(c.Target)
		if err != nil {
			c.log(fmt.Sprintf("[WARN] Custom DNS resolution failed: %v — falling back to system resolver", err))
		} else {
			c.log(fmt.Sprintf("[INFO] Resolved %s → %s via custom DNS (%s)", c.Target, resolved, c.Proxy.DNSServer))
			connHost = resolved
		}
	}

	addr := net.JoinHostPort(connHost, fmt.Sprintf("%d", c.Port))
	c.log(fmt.Sprintf("[INFO] Connecting to %s ...", addr))

	var conn net.Conn
	var err error

	if c.Proxy != nil && c.Proxy.Host != "" && c.Proxy.Port != "" {
		proxyAddr := net.JoinHostPort(c.Proxy.Host, c.Proxy.Port)
		c.log(fmt.Sprintf("[INFO] SOCKS proxy ENABLED — dialing %s via %s proxy at %s", addr, c.Proxy.Type, proxyAddr))
		conn, err = c.dialViaProxy(addr)
	} else {
		if c.Proxy == nil {
			c.log("[INFO] SOCKS proxy DISABLED — connecting directly")
		} else {
			c.log("[INFO] SOCKS proxy config incomplete — connecting directly")
		}
		conn, err = net.DialTimeout("tcp", addr, 15*time.Second)
	}
	if err != nil {
		return fmt.Errorf("TCP connection failed: %w", err)
	}
	c.conn = conn

	var d *smb2.Dialer

	switch c.AuthMode {
	case AuthKerberos:
		c.log("[INFO] Performing Kerberos (SPNEGO) authentication...")
		targetSPN := c.krbSPN
		if targetSPN == "" {
			targetSPN = fmt.Sprintf("cifs/%s", c.Target)
		}
		c.log(fmt.Sprintf("[INFO] Using SPN: %s", targetSPN))
		d = &smb2.Dialer{
			Initiator: &smb2.Krb5Initiator{
				Client:    c.krbClient,
				TargetSPN: targetSPN,
			},
		}
	default: // AuthNTLM
		c.log("[INFO] Performing NTLM authentication (pass-the-hash)...")
		d = &smb2.Dialer{
			Initiator: &smb2.NTLMInitiator{
				User:   c.Username,
				Domain: c.Domain,
				Hash:   c.NTHash,
			},
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	session, err := d.DialConn(ctx, conn, addr)
	if err != nil {
		conn.Close()
		return fmt.Errorf("SMB authentication failed: %w", err)
	}
	c.session = session
	c.log("[INFO] SMB authentication successful!")
	return nil
}

// resolveTarget resolves a hostname using the custom DNS server over TCP.
// TCP is used so that the query works through a SOCKS4/5 proxy tunnel.
func (c *SMBClient) resolveTarget(hostname string) (string, error) {
	return resolveHostname(hostname, c.Proxy)
}

// resolveHostname resolves a hostname via the custom DNS server in proxyConf
// using TCP.  If a SOCKS proxy is also configured, the DNS query is tunnelled
// through it.  This is a standalone function so it can be used before an
// SMBClient is fully constructed.
func resolveHostname(hostname string, proxyConf *ProxyConfig) (string, error) {
	if proxyConf == nil || proxyConf.DNSServer == "" {
		return "", fmt.Errorf("no custom DNS server configured")
	}
	dnsAddr := proxyConf.DNSServer
	if !strings.Contains(dnsAddr, ":") {
		dnsAddr = net.JoinHostPort(dnsAddr, "53")
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if proxyConf.Host != "" && proxyConf.Port != "" {
				return dialViaProxyStandalone(dnsAddr, proxyConf)
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", dnsAddr)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ips, err := resolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return "", fmt.Errorf("DNS lookup for %s failed: %w", hostname, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("DNS lookup for %s returned no results", hostname)
	}
	return ips[0].IP.String(), nil
}

// dialViaProxyStandalone connects to targetAddr through a SOCKS proxy without
// needing an SMBClient instance.
func dialViaProxyStandalone(targetAddr string, proxyConf *ProxyConfig) (net.Conn, error) {
	proxyAddr := net.JoinHostPort(proxyConf.Host, proxyConf.Port)
	switch strings.ToLower(proxyConf.Type) {
	case "socks4":
		// SOCKS4 requires IP — resolve locally first
		host, portStr, _ := net.SplitHostPort(targetAddr)
		ip := net.ParseIP(host)
		if ip == nil {
			ips, err := net.LookupIP(host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("SOCKS4: cannot resolve %s", host)
			}
			ip = ips[0]
		}
		targetAddr = net.JoinHostPort(ip.String(), portStr)
		conn, err := net.DialTimeout("tcp", proxyAddr, 15*time.Second)
		if err != nil {
			return nil, err
		}
		port, _ := strconv.Atoi(portStr)
		ip4 := ip.To4()
		if ip4 == nil {
			conn.Close()
			return nil, fmt.Errorf("SOCKS4: IPv6 not supported")
		}
		req := []byte{0x04, 0x01, byte(port >> 8), byte(port), ip4[0], ip4[1], ip4[2], ip4[3], 0x00}
		if _, err := conn.Write(req); err != nil {
			conn.Close()
			return nil, err
		}
		resp := make([]byte, 8)
		if _, err := io.ReadFull(conn, resp); err != nil {
			conn.Close()
			return nil, err
		}
		if resp[1] != 0x5A {
			conn.Close()
			return nil, fmt.Errorf("SOCKS4 rejected: 0x%02X", resp[1])
		}
		return conn, nil
	default: // socks5
		var auth *proxy.Auth
		if proxyConf.Username != "" {
			auth = &proxy.Auth{User: proxyConf.Username, Password: proxyConf.Password}
		}
		dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, proxy.Direct)
		if err != nil {
			return nil, err
		}
		return dialer.Dial("tcp", targetAddr)
	}
}

// startKDCLocalProxy starts a local TCP listener that forwards every accepted
// connection to kdcAddr through the SOCKS proxy.  This allows gokrb5 (which
// dials the KDC directly) to reach the KDC via our tunnel.
func startKDCLocalProxy(kdcAddr string, proxyConf *ProxyConfig, logFunc func(string)) (net.Listener, string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", fmt.Errorf("listen failed: %w", err)
	}
	localAddr := ln.Addr().String()

	go func() {
		for {
			local, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func() {
				defer local.Close()
				remote, err := dialViaProxyStandalone(kdcAddr, proxyConf)
				if err != nil {
					if logFunc != nil {
						logFunc(fmt.Sprintf("[WARN] KDC proxy dial failed: %v", err))
					}
					return
				}
				defer remote.Close()
				done := make(chan struct{})
				go func() {
					io.Copy(remote, local)
					close(done)
				}()
				io.Copy(local, remote)
				<-done
			}()
		}
	}()

	return ln, localAddr, nil
}

// dialViaProxy connects through a SOCKS4 or SOCKS5 proxy.
func (c *SMBClient) dialViaProxy(targetAddr string) (net.Conn, error) {
	proxyAddr := net.JoinHostPort(c.Proxy.Host, c.Proxy.Port)
	c.log(fmt.Sprintf("[INFO] Using %s proxy: %s", strings.ToUpper(c.Proxy.Type), proxyAddr))

	switch strings.ToLower(c.Proxy.Type) {
	case "socks5":
		return c.dialSOCKS5(proxyAddr, targetAddr)
	case "socks4":
		return c.dialSOCKS4(proxyAddr, targetAddr)
	default:
		return c.dialSOCKS5(proxyAddr, targetAddr)
	}
}

// dialSOCKS5 connects via a SOCKS5 proxy.
func (c *SMBClient) dialSOCKS5(proxyAddr, targetAddr string) (net.Conn, error) {
	var auth *proxy.Auth
	if c.Proxy.Username != "" {
		auth = &proxy.Auth{
			User:     c.Proxy.Username,
			Password: c.Proxy.Password,
		}
	}
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 proxy setup failed: %w", err)
	}
	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 proxy connect failed: %w", err)
	}
	return conn, nil
}

// dialSOCKS4 connects via a SOCKS4 proxy (no auth, IP-only).
func (c *SMBClient) dialSOCKS4(proxyAddr, targetAddr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("SOCKS4 proxy connection failed: %w", err)
	}

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("invalid target address: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS4: invalid port %q: %w", portStr, err)
	}

	// Resolve hostname to IP for SOCKS4
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		// Try parsing as IP directly
		ip := net.ParseIP(host)
		if ip == nil {
			conn.Close()
			return nil, fmt.Errorf("SOCKS4: cannot resolve %s", host)
		}
		ips = []net.IP{ip}
	}
	ip4 := ips[0].To4()
	if ip4 == nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS4: IPv6 not supported, got %s", ips[0])
	}

	// SOCKS4 CONNECT request
	req := []byte{
		0x04,                        // VER
		0x01,                        // CMD: CONNECT
		byte(port >> 8), byte(port), // DSTPORT (big-endian)
		ip4[0], ip4[1], ip4[2], ip4[3], // DSTIP
		0x00, // USERID (empty, null-terminated)
	}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS4 write failed: %w", err)
	}

	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS4 read failed: %w", err)
	}
	if resp[1] != 0x5A {
		conn.Close()
		return nil, fmt.Errorf("SOCKS4 connect rejected: status 0x%02X", resp[1])
	}

	c.log("[INFO] SOCKS4 tunnel established")
	return conn, nil
}

// ListShares returns share names from the connected SMB server.
func (c *SMBClient) ListShares() ([]string, error) {
	if c.session == nil {
		return nil, fmt.Errorf("not connected")
	}
	names, err := c.session.ListSharenames()
	if err != nil {
		return nil, fmt.Errorf("failed to list shares: %w", err)
	}
	c.log(fmt.Sprintf("[INFO] Found %d shares", len(names)))
	return names, nil
}

// getShare mounts and caches a share.
func (c *SMBClient) getShare(shareName string) (*smb2.Share, error) {
	if s, ok := c.mountCache[shareName]; ok {
		return s, nil
	}
	s, err := c.session.Mount(shareName)
	if err != nil {
		return nil, fmt.Errorf("failed to mount share %s: %w", shareName, err)
	}
	c.mountCache[shareName] = s
	return s, nil
}

// ListDir lists files and directories in a share at the given path.
func (c *SMBClient) ListDir(shareName, path string) ([]DirEntry, error) {
	if c.session == nil {
		return nil, fmt.Errorf("not connected")
	}
	share, err := c.getShare(shareName)
	if err != nil {
		return nil, err
	}

	// Normalize path
	if path == "" || path == "/" {
		path = "."
	}
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		path = "."
	}
	// Convert forward slashes to backslashes for SMB
	smbPath := strings.ReplaceAll(path, "/", "\\")

	entries, err := share.ReadDir(smbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	result := make([]DirEntry, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if name == "." || name == ".." {
			continue
		}
		result = append(result, DirEntry{
			Name:      name,
			IsDir:     e.IsDir(),
			Size:      e.Size(),
			LastWrite: e.ModTime(),
		})
	}
	return result, nil
}

// DownloadFile downloads a file from an SMB share to a local destination.
func (c *SMBClient) DownloadFile(shareName, remotePath, localPath string) error {
	if c.session == nil {
		return fmt.Errorf("not connected")
	}
	share, err := c.getShare(shareName)
	if err != nil {
		return err
	}

	remotePath = strings.TrimPrefix(remotePath, "/")
	smbPath := strings.ReplaceAll(remotePath, "/", "\\")

	c.log(fmt.Sprintf("[INFO] Downloading %s:%s → %s", shareName, smbPath, localPath))
	rf, err := share.Open(smbPath)
	if err != nil {
		return fmt.Errorf("failed to open remote file: %w", err)
	}
	defer rf.Close()

	lf, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}

	bw := bufio.NewWriterSize(lf, 64*1024)
	n, copyErr := io.Copy(bw, rf)
	flushErr := bw.Flush()
	closeErr := lf.Close()

	if copyErr != nil {
		os.Remove(localPath)
		return fmt.Errorf("download failed: %w", copyErr)
	}
	if flushErr != nil {
		os.Remove(localPath)
		return fmt.Errorf("download flush failed: %w", flushErr)
	}
	if closeErr != nil {
		return fmt.Errorf("download close failed: %w", closeErr)
	}
	c.log(fmt.Sprintf("[INFO] Downloaded %d bytes", n))
	return nil
}

// UploadFile uploads a local file to an SMB share.
func (c *SMBClient) UploadFile(shareName, remotePath, localPath string) error {
	if c.session == nil {
		return fmt.Errorf("not connected")
	}
	share, err := c.getShare(shareName)
	if err != nil {
		return err
	}

	remotePath = strings.TrimPrefix(remotePath, "/")
	smbPath := strings.ReplaceAll(remotePath, "/", "\\")

	c.log(fmt.Sprintf("[INFO] Uploading %s → %s:%s", localPath, shareName, smbPath))
	lf, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer lf.Close()

	rf, err := share.Create(smbPath)
	if err != nil {
		return fmt.Errorf("failed to create remote file: %w", err)
	}
	defer rf.Close()

	br := bufio.NewReaderSize(lf, 64*1024)
	n, err := io.Copy(rf, br)
	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}
	c.log(fmt.Sprintf("[INFO] Uploaded %d bytes", n))
	return nil
}

// DownloadFolder recursively downloads an entire folder from SMB to a local directory.
func (c *SMBClient) DownloadFolder(shareName, remotePath, localDir string) error {
	if c.session == nil {
		return fmt.Errorf("not connected")
	}
	entries, err := c.ListDir(shareName, remotePath)
	if err != nil {
		return fmt.Errorf("failed to list %s: %w", remotePath, err)
	}
	for _, entry := range entries {
		if entry.Name == "." || entry.Name == ".." {
			continue
		}
		remoteItem := remotePath + entry.Name
		localItem := filepath.Join(localDir, entry.Name)
		if entry.IsDir {
			if err := os.MkdirAll(localItem, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", localItem, err)
			}
			if err := c.DownloadFolder(shareName, remoteItem+"/", localItem); err != nil {
				return err
			}
		} else {
			if err := c.DownloadFile(shareName, remoteItem, localItem); err != nil {
				c.log(fmt.Sprintf("[WARN] Failed to download %s: %s", remoteItem, err))
			}
		}
	}
	return nil
}

// Disconnect closes all mounted shares and the SMB session.
func (c *SMBClient) Disconnect() {
	for name, s := range c.mountCache {
		s.Umount()
		delete(c.mountCache, name)
	}
	if c.session != nil {
		c.session.Logoff()
		c.session = nil
	}
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	if c.kdcProxy != nil {
		c.kdcProxy.Close()
		c.kdcProxy = nil
	}
	c.log("[INFO] Disconnected from SMB server")
}
