# EyeBrowse Go v1 — SMB File Explorer

A cross-platform GUI tool for pen testers to browse, download, upload, and preview files on SMB shares using NTLM pass-the-hash or Kerberos ticket authentication. Written in Go with no IOC-flagged libraries. Single binary, no external dependencies at runtime.

## Features

### Authentication
- **NTLM Pass-the-Hash** — Connect with only the NT hash (LM:NT or NT-only format)
- **Kerberos (CCache / Kirbi)** — Load `.ccache` or `.kirbi` ticket files directly
- **TGT & TGS Support** — Use a Ticket Granting Ticket (TGT) for any service, or a pre-existing Service Ticket (TGS) for direct auth without KDC contact
- **Base64 Kirbi Paste** — Paste a base64-encoded `.kirbi` ticket inline (e.g. from Rubeus output)
- **Ticket Validation** — Detects expired tickets, zero-key tgtdeleg tickets, and shows parsed ticket details before connecting

### Network
- **SOCKS4 & SOCKS5 Proxy** — Toggle-able proxy with enable/disable checkbox; routes SMB and KDC traffic through the tunnel
- **Custom DNS over TCP** — Resolve hostnames through a specified DNS server, tunneled through SOCKS when configured
- **KDC Proxy Tunneling** — Automatically forwards Kerberos KDC traffic through SOCKS via a local TCP proxy
- **KDC Host Override** — Optionally specify the KDC hostname/IP when it differs from the target

### File Browser
- **GUI File Browser** — Browse shares, navigate directories, sort by name/type/size/date
- **File Operations** — Download files/folders, upload files, preview text and images
- **Office Preview** — Basic preview support for common Office file formats
- **Pattern Analysis** — Highlights files matching common sensitive data patterns (credentials, configs, keys)
- **Visited Tracking** — Highlights previously visited directories and files
- **Favorites** — Save and manage frequently accessed locations (NTLM sessions)
- **Tags** — Tag files/folders and export tagged items to clipboard or file

### General
- **Terminal Log** — Real-time operation log with timestamps and debug output
- **Encrypted Credential Storage** — NTLM hashes stored encrypted (AES-256-GCM) in preferences

## Build

```bash
# Requires Go 1.21+
go mod tidy
go build -o eyebrowse .
```

### macOS App Bundle

```bash
make build   # builds binary + .app bundle with icon
make run     # builds and opens the .app
make clean   # removes build artifacts
```

## Run

```bash
./eyebrowse
```

## Usage

### NTLM (Pass-the-Hash)
1. **Configure Proxy (optional):** Settings → SOCKS Proxy → enable checkbox, set type/host/port
2. **Connect:** Click "Connect" → select "NTLM (Pass-the-Hash)" → enter Domain, Username, NTLM Hash, Target
3. **Browse:** Select a share from the left panel, double-click folders to navigate

### Kerberos (CCache / Kirbi)
1. **Connect:** Click "Connect" → select "Kerberos (CCache / Kirbi)"
2. **Load ticket:** Browse for a `.ccache` or `.kirbi` file, **OR** paste a base64 kirbi and click "Parse Ticket"
3. **KDC Host (optional):** If the KDC differs from the target, enter it in the KDC Host field
4. **Enter target** and click Connect

### Hash Format

- Full format: `aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0`
- NT-only format: `31d6cfe0d16ae931b73c59d7e0c089c0`


