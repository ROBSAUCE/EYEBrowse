package main

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

// AuthResult holds the values from the authentication dialog.
type AuthResult struct {
	Domain   string
	Username string
	NTLMHash string
	Target   string
}

// ShowAuthDialog displays the SMB connection dialog and calls onConnect with the result.
func ShowAuthDialog(win fyne.Window, prefs fyne.Preferences, onConnect func(AuthResult)) {
	domainEntry := widget.NewEntry()
	domainEntry.SetPlaceHolder("WORKGROUP")
	domainEntry.SetText(prefs.StringWithFallback("auth_domain", ""))

	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("Administrator")
	usernameEntry.SetText(prefs.StringWithFallback("auth_username", ""))

	hashEntry := widget.NewPasswordEntry()
	hashEntry.SetPlaceHolder("NTLM hash (LM:NT or NT)")
	hashEntry.SetText(decryptString(prefs.StringWithFallback("auth_hash", "")))

	targetEntry := widget.NewEntry()
	targetEntry.SetPlaceHolder("192.168.1.100")
	targetEntry.SetText(prefs.StringWithFallback("auth_target", ""))

	form := widget.NewForm(
		widget.NewFormItem("Domain (optional):", domainEntry),
		widget.NewFormItem("Username:", usernameEntry),
		widget.NewFormItem("NTLM Hash:", hashEntry),
		widget.NewFormItem("Target IP/Hostname:", targetEntry),
	)

	d := dialog.NewCustomConfirm("Connect to SMB Share", "Connect", "Cancel",
		container.NewVBox(form),
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
			// Save preferences (encrypt the hash)
			prefs.SetString("auth_domain", domainEntry.Text)
			prefs.SetString("auth_username", usernameEntry.Text)
			if encHash, err := encryptString(hashEntry.Text); err == nil {
				prefs.SetString("auth_hash", encHash)
			} else {
				prefs.SetString("auth_hash", hashEntry.Text)
			}
			prefs.SetString("auth_target", target)

			onConnect(AuthResult{
				Domain:   domainEntry.Text,
				Username: usernameEntry.Text,
				NTLMHash: hashEntry.Text,
				Target:   target,
			})
		}, win)
	d.Resize(fyne.NewSize(450, 300))
	d.Show()
}

// LoadProxySettings loads proxy configuration from preferences.
func LoadProxySettings(prefs fyne.Preferences) *ProxyConfig {
	host := prefs.StringWithFallback("proxy_host", "")
	port := prefs.StringWithFallback("proxy_port", "")
	if host == "" || port == "" {
		return nil
	}
	return &ProxyConfig{
		Type:     prefs.StringWithFallback("proxy_type", "socks5"),
		Host:     host,
		Port:     port,
		Username: prefs.StringWithFallback("proxy_user", ""),
		Password: prefs.StringWithFallback("proxy_pass", ""),
	}
}

// ShowProxyDialog displays the SOCKS proxy settings dialog.
func ShowProxyDialog(win fyne.Window, prefs fyne.Preferences) {
	typeSelect := widget.NewSelect([]string{"socks5", "socks4"}, nil)
	typeSelect.SetSelected(prefs.StringWithFallback("proxy_type", "socks5"))

	hostEntry := widget.NewEntry()
	hostEntry.SetPlaceHolder("127.0.0.1")
	hostEntry.SetText(prefs.StringWithFallback("proxy_host", ""))

	portEntry := widget.NewEntry()
	portEntry.SetPlaceHolder("1080")
	portEntry.SetText(prefs.StringWithFallback("proxy_port", ""))

	userEntry := widget.NewEntry()
	userEntry.SetPlaceHolder("(optional)")
	userEntry.SetText(prefs.StringWithFallback("proxy_user", ""))

	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("(optional)")
	passEntry.SetText(prefs.StringWithFallback("proxy_pass", ""))

	clearBtn := widget.NewButton("Clear Proxy", func() {
		typeSelect.SetSelected("socks5")
		hostEntry.SetText("")
		portEntry.SetText("")
		userEntry.SetText("")
		passEntry.SetText("")
	})

	form := widget.NewForm(
		widget.NewFormItem("Proxy Type:", typeSelect),
		widget.NewFormItem("Host:", hostEntry),
		widget.NewFormItem("Port:", portEntry),
		widget.NewFormItem("Username:", userEntry),
		widget.NewFormItem("Password:", passEntry),
	)

	content := container.NewVBox(
		form,
		container.NewHBox(layout.NewSpacer(), clearBtn),
	)

	d := dialog.NewCustomConfirm("SOCKS Proxy Settings", "Save", "Cancel",
		content,
		func(ok bool) {
			if !ok {
				return
			}
			prefs.SetString("proxy_type", typeSelect.Selected)
			prefs.SetString("proxy_host", hostEntry.Text)
			prefs.SetString("proxy_port", portEntry.Text)
			prefs.SetString("proxy_user", userEntry.Text)
			prefs.SetString("proxy_pass", passEntry.Text)
		}, win)
	d.Resize(fyne.NewSize(420, 350))
	d.Show()
}
