package main

import (
	_ "embed"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
)

//go:embed eyebrowse.png
var logoPNG []byte

func main() {
	a := app.NewWithID("com.eyebrowse.smbexplorer")
	a.Settings().SetTheme(&EyeBrowseTheme{})

	win := a.NewWindow("EyeBrowse - SMB File Explorer")
	win.Resize(fyne.NewSize(1100, 750))

	var logoRes fyne.Resource
	if len(logoPNG) > 0 {
		logoRes = fyne.NewStaticResource("eyebrowse.png", logoPNG)
	}

	// Set app-level icon (dock/taskbar) and window icon
	if logoRes != nil {
		a.SetIcon(logoRes)
		win.SetIcon(logoRes)
	}

	_ = NewExplorer(a, win, logoRes)

	win.ShowAndRun()
}
