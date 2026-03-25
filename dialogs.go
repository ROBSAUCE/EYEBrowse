package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

// AuthResult holds the values from the authentication dialog.
type AuthResult struct {
	Mode       AuthMode
	Domain     string
	Username   string
	NTLMHash   string
	Target     string
	CcachePath string // Kerberos ccache file path
	KDCHost    string // optional explicit KDC hostname/IP for Kerberos
}

// ShowAuthDialog displays the SMB connection dialog and calls onConnect with the result.
func ShowAuthDialog(win fyne.Window, prefs fyne.Preferences, onConnect func(AuthResult)) {
	// --- Shared fields ---
	targetEntry := widget.NewEntry()
	targetEntry.SetPlaceHolder("192.168.1.100 or dc01.corp.local")
	targetEntry.SetText(prefs.StringWithFallback("auth_target", ""))

	// --- NTLM fields ---
	domainEntry := widget.NewEntry()
	domainEntry.SetPlaceHolder("WORKGROUP")
	domainEntry.SetText(prefs.StringWithFallback("auth_domain", ""))

	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("Administrator")
	usernameEntry.SetText(prefs.StringWithFallback("auth_username", ""))

	hashEntry := widget.NewPasswordEntry()
	hashEntry.SetPlaceHolder("NTLM hash (LM:NT or NT)")
	hashEntry.SetText(decryptString(prefs.StringWithFallback("auth_hash", "")))

	ntlmForm := widget.NewForm(
		widget.NewFormItem("Domain (optional):", domainEntry),
		widget.NewFormItem("Username:", usernameEntry),
		widget.NewFormItem("NTLM Hash:", hashEntry),
	)

	// --- Kerberos fields ---
	// File picker row
	ccacheLabel := widget.NewLabel("No file selected")
	ccacheLabel.Wrapping = fyne.TextTruncate
	var selectedCcache string
	if saved := prefs.StringWithFallback("auth_ccache", ""); saved != "" {
		ccacheLabel.SetText(filepath.Base(saved))
		selectedCcache = saved
	}

	// Ticket detail output (shared between file picker and base64 parse)
	ticketDetailText := widget.NewMultiLineEntry()
	ticketDetailText.Wrapping = fyne.TextWrapWord
	ticketDetailText.SetMinRowsVisible(6)
	ticketDetailText.Disable()
	ticketDetailText.SetPlaceHolder("Parsed ticket details will appear here...")

	// Track whether the user wants to use base64 input instead of a file
	var kirbiBase64Active bool

	ccacheBrowseBtn := widget.NewButton("Browse...", func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			reader.Close()
			path := reader.URI().Path()
			selectedCcache = path
			kirbiBase64Active = false
			ccacheLabel.SetText(filepath.Base(path))
		}, win)
		fd.SetFilter(storage.NewExtensionFileFilter([]string{".ccache", ".kirbi"}))
		fd.Show()
	})
	ccacheClearBtn := widget.NewButton("Clear", func() {
		selectedCcache = ""
		ccacheLabel.SetText("No file selected")
		prefs.SetString("auth_ccache", "")
	})

	// Base64 kirbi paste area
	kirbiB64Entry := widget.NewMultiLineEntry()
	kirbiB64Entry.SetPlaceHolder("Paste base64-encoded .kirbi ticket here...")
	kirbiB64Entry.Wrapping = fyne.TextWrapBreak
	kirbiB64Entry.SetMinRowsVisible(3)
	if saved := prefs.StringWithFallback("auth_kirbi_b64", ""); saved != "" {
		kirbiB64Entry.SetText(saved)
	}

	parseBtn := widget.NewButton("Parse Ticket", func() {
		b64 := kirbiB64Entry.Text
		if b64 == "" {
			dialog.ShowError(fmt.Errorf("paste a base64 kirbi ticket first"), win)
			return
		}
		details, err := parseKirbiBase64(b64)
		if err != nil {
			ticketDetailText.SetText("")
			dialog.ShowError(fmt.Errorf("parse failed: %s", err), win)
			return
		}
		ticketDetailText.SetText(details)
		kirbiBase64Active = true
		ccacheLabel.SetText("(using pasted base64)")
	})

	clearB64Btn := widget.NewButton("Clear", func() {
		kirbiB64Entry.SetText("")
		ticketDetailText.SetText("")
		kirbiBase64Active = false
		prefs.SetString("auth_kirbi_b64", "")
		if selectedCcache != "" {
			ccacheLabel.SetText(filepath.Base(selectedCcache))
		} else {
			ccacheLabel.SetText("No file selected")
		}
	})

	kdcEntry := widget.NewEntry()
	kdcEntry.SetPlaceHolder("(auto-detect from target)")
	kdcEntry.SetText(prefs.StringWithFallback("auth_kdc", ""))

	krbForm := widget.NewForm(
		widget.NewFormItem("Ticket File:", container.NewBorder(nil, nil, nil, container.NewHBox(ccacheBrowseBtn, ccacheClearBtn), ccacheLabel)),
		widget.NewFormItem("KDC Host:", kdcEntry),
	)

	krbContent := container.NewVBox(
		krbForm,
		widget.NewSeparator(),
		widget.NewLabel("— OR paste base64 kirbi —"),
		kirbiB64Entry,
		container.NewHBox(parseBtn, clearB64Btn, layout.NewSpacer()),
		ticketDetailText,
	)

	// --- Auth mode toggle ---
	ntlmPanel := container.NewVBox(ntlmForm)
	krbPanel := container.NewVBox(krbContent)
	krbPanel.Hide()

	authModeSelect := widget.NewSelect([]string{"NTLM (Pass-the-Hash)", "Kerberos (CCache / Kirbi)"}, func(sel string) {
		switch sel {
		case "Kerberos (CCache / Kirbi)":
			ntlmPanel.Hide()
			krbPanel.Show()
		default:
			krbPanel.Hide()
			ntlmPanel.Show()
		}
	})
	savedMode := prefs.StringWithFallback("auth_mode", "NTLM (Pass-the-Hash)")
	// Migrate old pref value
	if savedMode == "Kerberos (CCache / TGT)" {
		savedMode = "Kerberos (CCache / Kirbi)"
	}
	authModeSelect.SetSelected(savedMode)

	content := container.NewVBox(
		widget.NewForm(widget.NewFormItem("Auth Type:", authModeSelect)),
		ntlmPanel,
		krbPanel,
		widget.NewForm(widget.NewFormItem("Target IP/Hostname:", targetEntry)),
	)

	d := dialog.NewCustomConfirm("Connect to SMB Share", "Connect", "Cancel",
		content,
		func(ok bool) {
			if !ok {
				return
			}
			target := targetEntry.Text
			if target == "" {
				dialog.ShowError(
					fmt.Errorf("target IP/Hostname cannot be empty"),
					win,
				)
				return
			}

			prefs.SetString("auth_mode", authModeSelect.Selected)
			prefs.SetString("auth_target", target)

			if authModeSelect.Selected == "Kerberos (CCache / Kirbi)" {
				prefs.SetString("auth_kdc", kdcEntry.Text)
				kdc := strings.TrimSpace(kdcEntry.Text)

				if kirbiBase64Active && kirbiB64Entry.Text != "" {
					// Save base64 to prefs and write to temp file
					prefs.SetString("auth_kirbi_b64", kirbiB64Entry.Text)
					tmpPath, err := saveKirbiBase64ToTempFile(kirbiB64Entry.Text)
					if err != nil {
						dialog.ShowError(
							fmt.Errorf("failed to save kirbi: %s", err),
							win,
						)
						return
					}
					onConnect(AuthResult{
						Mode:       AuthKerberos,
						Target:     target,
						CcachePath: tmpPath,
						KDCHost:    kdc,
					})
				} else if selectedCcache != "" {
					prefs.SetString("auth_ccache", selectedCcache)
					onConnect(AuthResult{
						Mode:       AuthKerberos,
						Target:     target,
						CcachePath: selectedCcache,
						KDCHost:    kdc,
					})
				} else {
					dialog.ShowError(
						fmt.Errorf("select a ticket file or paste a base64 kirbi"),
						win,
					)
					return
				}
			} else {
				// Save NTLM preferences (encrypt the hash)
				prefs.SetString("auth_domain", domainEntry.Text)
				prefs.SetString("auth_username", usernameEntry.Text)
				if encHash, err := encryptString(hashEntry.Text); err == nil {
					prefs.SetString("auth_hash", encHash)
				} else {
					prefs.SetString("auth_hash", hashEntry.Text)
				}
				onConnect(AuthResult{
					Mode:     AuthNTLM,
					Domain:   domainEntry.Text,
					Username: usernameEntry.Text,
					NTLMHash: hashEntry.Text,
					Target:   target,
				})
			}
		}, win)
	d.Resize(fyne.NewSize(550, 580))
	d.Show()
}

// LoadProxySettings loads proxy configuration from preferences.
func LoadProxySettings(prefs fyne.Preferences) *ProxyConfig {
	if !prefs.BoolWithFallback("proxy_enabled", false) {
		return nil
	}
	host := prefs.StringWithFallback("proxy_host", "")
	port := prefs.StringWithFallback("proxy_port", "")
	if host == "" || port == "" {
		return nil
	}
	return &ProxyConfig{
		Type:      prefs.StringWithFallback("proxy_type", "socks5"),
		Host:      host,
		Port:      port,
		Username:  prefs.StringWithFallback("proxy_user", ""),
		Password:  prefs.StringWithFallback("proxy_pass", ""),
		DNSServer: prefs.StringWithFallback("dns_server", ""),
	}
}

// ShowProxyDialog displays the SOCKS proxy settings dialog.
func ShowProxyDialog(win fyne.Window, prefs fyne.Preferences) {
	enabledCheck := widget.NewCheck("Enable SOCKS Proxy", nil)
	enabledCheck.SetChecked(prefs.BoolWithFallback("proxy_enabled", false))

	typeSelect := widget.NewSelect([]string{"socks5", "socks4"}, nil)
	typeSelect.SetSelected(prefs.StringWithFallback("proxy_type", "socks5"))

	hostEntry := widget.NewEntry()
	hostEntry.SetPlaceHolder("e.g. 127.0.0.1")
	hostEntry.SetText(prefs.StringWithFallback("proxy_host", "127.0.0.1"))

	portEntry := widget.NewEntry()
	portEntry.SetPlaceHolder("1080")
	portEntry.SetText(prefs.StringWithFallback("proxy_port", ""))

	userEntry := widget.NewEntry()
	userEntry.SetPlaceHolder("(optional)")
	userEntry.SetText(prefs.StringWithFallback("proxy_user", ""))

	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("(optional)")
	passEntry.SetText(prefs.StringWithFallback("proxy_pass", ""))

	dnsEntry := widget.NewEntry()
	dnsEntry.SetPlaceHolder("e.g. 10.0.0.2 (optional, uses TCP)")
	dnsEntry.SetText(prefs.StringWithFallback("dns_server", ""))

	clearBtn := widget.NewButton("Clear All", func() {
		enabledCheck.SetChecked(false)
		typeSelect.SetSelected("socks5")
		hostEntry.SetText("")
		portEntry.SetText("")
		userEntry.SetText("")
		passEntry.SetText("")
		dnsEntry.SetText("")
	})

	form := widget.NewForm(
		widget.NewFormItem("Proxy Type:", typeSelect),
		widget.NewFormItem("Host:", hostEntry),
		widget.NewFormItem("Port:", portEntry),
		widget.NewFormItem("Username:", userEntry),
		widget.NewFormItem("Password:", passEntry),
	)

	dnsForm := widget.NewForm(
		widget.NewFormItem("DNS Server:", dnsEntry),
	)
	dnsHint := widget.NewLabel("TCP DNS — resolves through SOCKS proxy when set")
	dnsHint.TextStyle = fyne.TextStyle{Italic: true}

	content := container.NewVBox(
		enabledCheck,
		widget.NewSeparator(),
		form,
		widget.NewSeparator(),
		dnsForm,
		dnsHint,
		container.NewHBox(layout.NewSpacer(), clearBtn),
	)

	d := dialog.NewCustomConfirm("SOCKS Proxy Settings", "Save", "Cancel",
		content,
		func(ok bool) {
			if !ok {
				return
			}
			prefs.SetBool("proxy_enabled", enabledCheck.Checked)
			prefs.SetString("proxy_type", typeSelect.Selected)
			prefs.SetString("proxy_host", hostEntry.Text)
			prefs.SetString("proxy_port", portEntry.Text)
			prefs.SetString("proxy_user", userEntry.Text)
			prefs.SetString("proxy_pass", passEntry.Text)
			prefs.SetString("dns_server", dnsEntry.Text)
		}, win)
	d.Resize(fyne.NewSize(420, 480))
	d.Show()
}
