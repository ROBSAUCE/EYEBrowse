package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
	"golang.org/x/net/proxy"
)

// ProxyConfig holds SOCKS proxy settings.
type ProxyConfig struct {
	Type     string // "socks4", "socks5", or ""
	Host     string
	Port     string
	Username string
	Password string
}

// DirEntry represents a file or directory entry from an SMB share.
type DirEntry struct {
	Name      string
	IsDir     bool
	Size      int64
	LastWrite time.Time
}

// SMBClient wraps go-smb2 for pass-the-hash SMB browsing.
type SMBClient struct {
	Domain   string
	Username string
	NTHash   []byte // raw 16-byte NT hash
	Target   string
	Port     int
	Proxy    *ProxyConfig

	session    *smb2.Session
	conn       net.Conn
	mountCache map[string]*smb2.Share
	logFunc    func(string)
}

// NewSMBClient creates a new SMBClient. ntlmHash can be "LM:NT" or just "NT" hex string.
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

func (c *SMBClient) log(msg string) {
	if c.logFunc != nil {
		c.logFunc(msg)
	}
}

// Connect establishes the SMB session using pass-the-hash via SOCKS proxy if configured.
func (c *SMBClient) Connect() error {
	addr := net.JoinHostPort(c.Target, fmt.Sprintf("%d", c.Port))
	c.log(fmt.Sprintf("[INFO] Connecting to %s ...", addr))

	var conn net.Conn
	var err error

	if c.Proxy != nil && c.Proxy.Host != "" && c.Proxy.Port != "" {
		conn, err = c.dialViaProxy(addr)
	} else {
		conn, err = net.DialTimeout("tcp", addr, 15*time.Second)
	}
	if err != nil {
		return fmt.Errorf("TCP connection failed: %w", err)
	}
	c.conn = conn

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:   c.Username,
			Domain: c.Domain,
			Hash:   c.NTHash,
		},
	}

	c.log("[INFO] Performing NTLM authentication (pass-the-hash)...")
	session, err := d.Dial(conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("SMB authentication failed: %w", err)
	}
	c.session = session
	c.log("[INFO] SMB authentication successful!")
	return nil
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
	c.log("[INFO] Disconnected from SMB server")
}
