package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

const doubleClickMs = 400

var predefinedTags = []string{"Credential", "Sensitive", "PII", "Interesting", "Config", "Loot"}

// tappableCell is a table cell that handles left-click (tap) and right-click (secondary tap).
type tappableCell struct {
	widget.BaseWidget
	label          *widget.Label
	onTap          func()
	onSecondaryTap func()
}

func newTappableCell() *tappableCell {
	t := &tappableCell{
		label: widget.NewLabel(""),
	}
	t.ExtendBaseWidget(t)
	return t
}

func (t *tappableCell) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(t.label)
}

func (t *tappableCell) Tapped(_ *fyne.PointEvent) {
	if t.onTap != nil {
		t.onTap()
	}
}

func (t *tappableCell) TappedSecondary(_ *fyne.PointEvent) {
	if t.onSecondaryTap != nil {
		t.onSecondaryTap()
	}
}

// Explorer is the main application window controller.
type Explorer struct {
	win   fyne.Window
	app   fyne.App
	prefs fyne.Preferences

	// SMB state
	smbClient     *SMBClient
	currentUser   string
	currentTarget string
	currentShare  string
	currentPath   string
	visitedDirs   map[string]bool // "server|share|path" -> true
	visitedFiles  map[string]bool // "server|share|filepath" -> true (downloaded/previewed)
	mu            sync.Mutex

	// Sorted file entries
	entries []DirEntry
	sortCol int
	sortAsc bool

	// Favorites
	favorites []Favorite
	favList   *widget.List

	// Tags: UNC path → list of tag strings
	tags map[string][]string

	// UI widgets
	breadcrumbBar    *fyne.Container
	shareList        *widget.List
	shareNames       []string
	fileTable        *widget.Table
	terminalText     *widget.Entry
	previewLabel     *canvas.Image
	previewText      *widget.Entry
	previewPanel     *fyne.Container
	previewContent   *fyne.Container
	previewImgScroll *container.Scroll
	logoImage        *canvas.Image

	// Double-click / selection state
	lastClickRow  int
	lastClickTime time.Time
	selectedRow   int

	// Layout references
	mainSplit    *container.Split
	contentSplit *container.Split

	// Temp file tracking for preview cleanup
	lastPreviewTmp string

	// Log ring buffer
	logLines []string
	logMax   int
}

// Favorite represents a saved bookmark to a share+folder.
type Favorite struct {
	Name     string `json:"name"`
	Domain   string `json:"domain"`
	Username string `json:"username"`
	Hash     string `json:"hash"`
	Target   string `json:"target"`
	Share    string `json:"share"`
	Path     string `json:"path"`
}

// NewExplorer creates and initializes the explorer UI.
func NewExplorer(app fyne.App, win fyne.Window, logoRes fyne.Resource) *Explorer {
	e := &Explorer{
		win:          win,
		app:          app,
		prefs:        app.Preferences(),
		visitedDirs:  make(map[string]bool),
		visitedFiles: make(map[string]bool),
		sortCol:      0,
		sortAsc:      true,
		logMax:       500,
		lastClickRow: -1,
		selectedRow:  -1,
		tags:         make(map[string][]string),
	}
	e.loadFavorites()
	e.loadTags()
	e.buildUI(logoRes)
	return e
}

func (e *Explorer) logMsg(msg string) {
	ts := time.Now().Format("15:04:05")
	line := fmt.Sprintf("[%s] %s", ts, msg)
	e.logLines = append(e.logLines, line)
	if len(e.logLines) > e.logMax {
		e.logLines = e.logLines[len(e.logLines)-e.logMax:]
	}
	if e.terminalText != nil {
		e.terminalText.SetText(strings.Join(e.logLines, "\n"))
		e.terminalText.CursorRow = len(e.logLines) - 1
	}
}

func (e *Explorer) updateBreadcrumb() {
	if e.breadcrumbBar == nil {
		return
	}
	e.breadcrumbBar.Objects = nil

	if e.currentUser == "" && e.currentTarget == "" {
		e.breadcrumbBar.Add(widget.NewLabel("Working Directory"))
		e.breadcrumbBar.Refresh()
		return
	}

	if e.currentUser != "" {
		lbl := widget.NewLabel(fmt.Sprintf("User: %s", e.currentUser))
		lbl.TextStyle = fyne.TextStyle{Bold: true}
		e.breadcrumbBar.Add(lbl)
		e.breadcrumbBar.Add(widget.NewLabel(" | "))
	}
	if e.currentTarget != "" {
		lbl := widget.NewLabel(fmt.Sprintf("Server: %s", e.currentTarget))
		lbl.TextStyle = fyne.TextStyle{Bold: true}
		e.breadcrumbBar.Add(lbl)
	}
	if e.currentShare != "" {
		e.breadcrumbBar.Add(widget.NewLabel(" > "))
		share := e.currentShare
		btn := widget.NewButton(share, func() {
			e.currentPath = ""
			e.updateBreadcrumb()
			e.loadSharePath(share, "")
		})
		btn.Importance = widget.LowImportance
		e.breadcrumbBar.Add(btn)
	}
	if e.currentPath != "" {
		parts := strings.Split(strings.TrimSuffix(e.currentPath, "/"), "/")
		for i, part := range parts {
			if part == "" {
				continue
			}
			pathUpTo := strings.Join(parts[:i+1], "/") + "/"
			e.breadcrumbBar.Add(widget.NewLabel(" > "))
			p := pathUpTo
			btn := widget.NewButton(part, func() {
				e.currentPath = p
				e.updateBreadcrumb()
				e.loadSharePath(e.currentShare, p)
			})
			btn.Importance = widget.LowImportance
			e.breadcrumbBar.Add(btn)
		}
	}
	e.breadcrumbBar.Refresh()
}

func (e *Explorer) visitedKey(path string) string {
	return fmt.Sprintf("%s|%s|%s", e.currentTarget, e.currentShare, path)
}

func (e *Explorer) fileKey(path string) string {
	return fmt.Sprintf("%s|%s|%s", e.currentTarget, e.currentShare, path)
}

func (e *Explorer) buildUI(logoRes fyne.Resource) {
	// --- Menu ---
	settingsMenu := fyne.NewMenu("Settings",
		fyne.NewMenuItem("SOCKS Proxy...", func() {
			ShowProxyDialog(e.win, e.prefs)
		}),
	)
	favoritesMenu := fyne.NewMenu("Favorites",
		fyne.NewMenuItem("⭐ Add Current Location...", func() { e.addFavoriteDialog() }),
		fyne.NewMenuItem("Manage Favorites...", func() { e.showManageFavoritesDialog() }),
	)
	tagsMenu := fyne.NewMenu("Tags",
		fyne.NewMenuItem("🏷 Manage Tags...", func() { e.showManageTagsDialog() }),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("📋 Export by Tag to Clipboard...", func() { e.showExportByTagDialog() }),
		fyne.NewMenuItem("📋 Export All Tagged to Clipboard", func() { e.exportAllTagged() }),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("💾 Export by Tag to File...", func() { e.showExportByTagToFile() }),
		fyne.NewMenuItem("💾 Export All Tagged to File", func() { e.exportAllTaggedToFile() }),
	)
	e.win.SetMainMenu(fyne.NewMainMenu(settingsMenu, favoritesMenu, tagsMenu))

	// --- Toolbar ---
	toolbar := widget.NewToolbar(
		widget.NewToolbarAction(theme.LoginIcon(), func() { e.showAuthDialog() }),
		widget.NewToolbarAction(theme.LogoutIcon(), func() { e.disconnect() }),
		widget.NewToolbarSeparator(),
		widget.NewToolbarAction(theme.UploadIcon(), func() { e.uploadFile() }),
		widget.NewToolbarAction(theme.DownloadIcon(), func() { e.downloadSelected() }),
		widget.NewToolbarSeparator(),
		widget.NewToolbarAction(theme.ViewRefreshIcon(), func() { e.refresh() }),
	)
	// Add text labels below toolbar icons
	connectBtn := widget.NewButton("Connect", func() { e.showAuthDialog() })
	disconnectBtn := widget.NewButton("Disconnect", func() { e.disconnect() })
	uploadBtn := widget.NewButton("Upload", func() { e.uploadFile() })
	downloadBtn := widget.NewButton("Download", func() { e.downloadSelected() })
	refreshBtn := widget.NewButton("Refresh", func() { e.refresh() })

	favBtn := widget.NewButton("⭐ Favorites", func() { e.addFavoriteDialog() })

	toolbarRow := container.NewHBox(
		connectBtn, disconnectBtn,
		widget.NewSeparator(),
		uploadBtn, downloadBtn,
		widget.NewSeparator(),
		refreshBtn,
		widget.NewSeparator(),
		favBtn,
	)

	// --- Breadcrumb navigation bar ---
	e.breadcrumbBar = container.NewHBox(widget.NewLabel("Working Directory"))
	statusBG := canvas.NewRectangle(ColorStatusBG)
	statusBar := container.NewStack(statusBG, container.NewPadded(
		container.NewHScroll(e.breadcrumbBar),
	))

	// --- Shares panel (left) with logo background ---
	e.shareNames = []string{"No shares found or not connected."}
	e.shareList = widget.NewList(
		func() int { return len(e.shareNames) },
		func() fyne.CanvasObject {
			return container.NewHBox(
				widget.NewLabel("Share Name Placeholder"),
				layout.NewSpacer(),
				widget.NewButton("⭐", nil),
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			box := obj.(*fyne.Container)
			label := box.Objects[0].(*widget.Label)
			favBtn := box.Objects[2].(*widget.Button)
			if id < len(e.shareNames) {
				label.SetText(e.shareNames[id])
				shareName := strings.TrimRight(e.shareNames[id], "\x00")
				favBtn.OnTapped = func() {
					e.addFavoriteForPath(shareName, "")
				}
			}
		},
	)
	e.shareList.OnSelected = func(id widget.ListItemID) {
		if e.smbClient == nil || id >= len(e.shareNames) {
			return
		}
		name := strings.TrimRight(e.shareNames[id], "\x00")
		e.currentShare = name
		e.currentPath = ""
		e.updateBreadcrumb()
		e.loadSharePath(name, "")
	}

	// Logo — transparent background behind the shares list
	if logoRes != nil {
		e.logoImage = canvas.NewImageFromResource(logoRes)
		e.logoImage.FillMode = canvas.ImageFillContain
		e.logoImage.Translucency = 0.75 // 75% transparent
	}
	var sharesPanel fyne.CanvasObject
	if e.logoImage != nil {
		sharesPanel = container.NewStack(e.logoImage, e.shareList)
	} else {
		sharesPanel = e.shareList
	}
	// --- Favorites panel (below shares) ---
	e.favList = widget.NewList(
		func() int { return len(e.favorites) },
		func() fyne.CanvasObject {
			return container.NewHBox(
				widget.NewLabel("\\\\server\\share\\path placeholder"),
				layout.NewSpacer(),
				widget.NewButtonWithIcon("", theme.ContentCopyIcon(), nil),
				widget.NewButtonWithIcon("", theme.DeleteIcon(), nil),
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			box := obj.(*fyne.Container)
			label := box.Objects[0].(*widget.Label)
			copyBtn := box.Objects[2].(*widget.Button)
			delBtn := box.Objects[3].(*widget.Button)
			if id < len(e.favorites) {
				fav := e.favorites[id]
				label.SetText(fav.Name)
				copyBtn.OnTapped = func() {
					e.win.Clipboard().SetContent(fav.Name)
					e.logMsg(fmt.Sprintf("[INFO] Copied to clipboard: %s", fav.Name))
				}
				delBtn.OnTapped = func() { e.removeFavorite(id) }
			}
		},
	)
	e.favList.OnSelected = func(id widget.ListItemID) {
		if id < len(e.favorites) {
			go e.connectToFavorite(e.favorites[id])
		}
		e.favList.UnselectAll()
	}

	favTitle := widget.NewLabel("Favorites")
	favTitle.TextStyle = fyne.TextStyle{Bold: true}

	favContent := container.NewBorder(favTitle, nil, nil, nil, e.favList)

	sharesBox := container.NewBorder(
		widget.NewLabel("Available Shares"), nil, nil, nil,
		container.NewVSplit(
			sharesPanel,
			favContent,
		),
	)

	// --- File table (center) ---
	e.fileTable = widget.NewTable(
		func() (int, int) {
			return len(e.entries), 4
		},
		func() fyne.CanvasObject {
			return newTappableCell()
		},
		func(id widget.TableCellID, obj fyne.CanvasObject) {
			cell := obj.(*tappableCell)
			label := cell.label
			if id.Row >= len(e.entries) {
				label.SetText("")
				cell.onTap = nil
				cell.onSecondaryTap = nil
				return
			}
			entry := e.entries[id.Row]
			row := id.Row
			switch id.Col {
			case 0:
				prefix := "📄 "
				suffix := ""
				if entry.IsDir {
					prefix = "📁 "
				}
				if entry.Name == ".." {
					prefix = "⬆ "
				}
				// History icon for visited dirs
				if entry.IsDir && entry.Name != ".." {
					dirKey := e.visitedKey(e.currentPath + entry.Name + "/")
					if e.visitedDirs[dirKey] {
						suffix = " 👁"
					}
				}
				// History icon for downloaded/previewed files
				if !entry.IsDir {
					fileKey := e.fileKey(e.currentPath + entry.Name)
					if e.visitedFiles[fileKey] {
						suffix = " 👁"
					}
				}
				// Show tags inline
				if !entry.IsDir || (entry.IsDir && entry.Name != "..") {
					tagName := entry.Name
					if entry.IsDir {
						tagName = entry.Name + "/"
					}
					unc := e.uncPath(tagName)
					if tags, ok := e.tags[unc]; ok && len(tags) > 0 {
						for _, t := range tags {
							suffix += " [" + t + "]"
						}
					}
				}
				label.SetText(prefix + entry.Name + suffix)
				// Highlight visited dirs
				dirKey := e.visitedKey(e.currentPath + entry.Name + "/")
				fileKey := e.fileKey(e.currentPath + entry.Name)
				if (entry.IsDir && entry.Name != ".." && e.visitedDirs[dirKey]) ||
					(!entry.IsDir && e.visitedFiles[fileKey]) {
					label.Importance = widget.HighImportance
				} else {
					label.Importance = widget.MediumImportance
				}
			case 1:
				if entry.IsDir {
					label.SetText("Folder")
				} else {
					label.SetText("File")
				}
			case 2:
				if entry.IsDir {
					label.SetText("")
				} else {
					label.SetText(humanSize(entry.Size))
				}
			case 3:
				if entry.LastWrite.IsZero() {
					label.SetText("")
				} else {
					label.SetText(entry.LastWrite.Format("2006-01-02 15:04:05"))
				}
			}
			// Left-click: select + double-click detection
			cell.onTap = func() {
				now := time.Now()
				isDouble := e.lastClickRow == row && now.Sub(e.lastClickTime) < doubleClickMs*time.Millisecond
				e.lastClickRow = row
				e.lastClickTime = now
				if isDouble {
					e.onTableDoubleClick(row)
				} else {
					e.selectedRow = row
				}
			}
			// Right-click: context menu
			cell.onSecondaryTap = func() {
				e.showItemContextMenu(row)
			}
		},
	)

	// Column widths
	e.fileTable.SetColumnWidth(0, 300)
	e.fileTable.SetColumnWidth(1, 80)
	e.fileTable.SetColumnWidth(2, 100)
	e.fileTable.SetColumnWidth(3, 160)

	// Header row
	headerName := newHeaderButton("Name", func() { e.sortBy(0) })
	headerType := newHeaderButton("Type", func() { e.sortBy(1) })
	headerSize := newHeaderButton("Size", func() { e.sortBy(2) })
	headerDate := newHeaderButton("Last Modified", func() { e.sortBy(3) })
	tableHeader := container.NewHBox(
		container.NewGridWrap(fyne.NewSize(300, 30), headerName),
		container.NewGridWrap(fyne.NewSize(80, 30), headerType),
		container.NewGridWrap(fyne.NewSize(100, 30), headerSize),
		container.NewGridWrap(fyne.NewSize(160, 30), headerDate),
	)

	// Left-click and double-click are handled by tappableCell.onTap.
	// Right-click is handled by tappableCell.onSecondaryTap.
	// OnSelected is kept as a fallback to clear selection highlight.
	e.fileTable.OnSelected = func(id widget.TableCellID) {
		e.fileTable.UnselectAll()
	}

	tablePanel := container.NewBorder(tableHeader, nil, nil, nil, e.fileTable)

	// --- Preview panel (right) ---
	e.previewLabel = canvas.NewImageFromResource(nil)
	e.previewLabel.FillMode = canvas.ImageFillContain
	e.previewLabel.SetMinSize(fyne.NewSize(50, 50))
	e.previewImgScroll = container.NewScroll(e.previewLabel)

	e.previewText = widget.NewMultiLineEntry()
	e.previewText.Wrapping = fyne.TextWrapWord

	e.previewContent = container.NewMax()

	previewTitle := widget.NewLabel("File Preview")
	previewTitle.TextStyle = fyne.TextStyle{Bold: true}
	scanBtn := widget.NewButton("Scan Secrets", func() { e.scanPreviewForSecrets() })
	scanBtn.Importance = widget.HighImportance
	e.previewPanel = container.NewBorder(
		container.NewHBox(previewTitle, layout.NewSpacer(), scanBtn),
		nil, nil, nil,
		e.previewContent,
	)

	// --- Terminal (bottom) ---
	e.terminalText = widget.NewMultiLineEntry()
	e.terminalText.Wrapping = fyne.TextWrapWord
	e.terminalText.Disable()
	e.terminalText.SetPlaceHolder("Terminal output...")

	termBG := canvas.NewRectangle(ColorTerminalBG)
	termPanel := container.NewStack(termBG, e.terminalText)
	termBox := container.NewBorder(
		widget.NewLabel("Terminal"), nil, nil, nil,
		termPanel,
	)

	// --- Layout assembly ---
	// Shares (left) | Files (center) | Preview (right)
	e.contentSplit = container.NewHSplit(
		tablePanel,
		e.previewPanel,
	)
	e.contentSplit.SetOffset(0.7)

	e.mainSplit = container.NewHSplit(
		sharesBox,
		e.contentSplit,
	)
	e.mainSplit.SetOffset(0.2)

	// Top section + bottom terminal
	topSection := container.NewBorder(
		container.NewVBox(toolbar, toolbarRow, statusBar),
		nil, nil, nil,
		e.mainSplit,
	)

	mainVSplit := container.NewVSplit(topSection, termBox)
	mainVSplit.SetOffset(0.82)

	e.win.SetContent(mainVSplit)
	e.logMsg("[INFO] EyeBrowse Go v1 ready.")
}

func newHeaderButton(label string, onTap func()) *widget.Button {
	btn := widget.NewButton(label, onTap)
	btn.Importance = widget.LowImportance
	return btn
}

func humanSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// knownTextExts is the set of file extensions treated as text/notepad-readable (package-level for efficiency).
var knownTextExts = map[string]bool{
	// Plain text & docs
	".txt": true, ".log": true, ".md": true, ".markdown": true, ".rst": true, ".tex": true, ".rtf": true,
	// Config & data
	".json": true, ".xml": true, ".yaml": true, ".yml": true, ".toml": true, ".ini": true, ".cfg": true,
	".conf": true, ".properties": true, ".env": true, ".editorconfig": true, ".gitignore": true, ".gitattributes": true,
	// Scripting & programming
	".py": true, ".go": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
	".rb": true, ".pl": true, ".pm": true, ".lua": true, ".php": true, ".java": true, ".kt": true,
	".c": true, ".h": true, ".cpp": true, ".hpp": true, ".cs": true, ".rs": true, ".swift": true,
	".r": true, ".m": true, ".mm": true, ".scala": true, ".groovy": true, ".dart": true,
	// Shell & batch
	".sh": true, ".bash": true, ".zsh": true, ".fish": true, ".bat": true, ".cmd": true, ".ps1": true, ".psm1": true, ".psd1": true,
	// Web
	".html": true, ".htm": true, ".css": true, ".scss": true, ".sass": true, ".less": true, ".svg": true,
	// Database & query
	".sql": true, ".graphql": true, ".gql": true,
	// Windows / system
	".reg": true, ".vbs": true, ".wsf": true, ".inf": true, ".manifest": true, ".policy": true,
	// Build & CI
	".makefile": true, ".cmake": true, ".gradle": true, ".dockerfile": true,
	".tf": true, ".tfvars": true, ".hcl": true,
	// Misc text
	".csv": true, ".tsv": true, ".diff": true, ".patch": true, ".asm": true, ".nfo": true,
	".srt": true, ".sub": true, ".vtt": true, ".pem": true, ".crt": true, ".key": true, ".pub": true,
}

// isKnownTextExt returns true if the file extension is a known text/notepad-readable format.
func isKnownTextExt(ext string) bool {
	return knownTextExts[ext]
}

// --- Actions ---

func (e *Explorer) showAuthDialog() {
	ShowAuthDialog(e.win, e.prefs, func(auth AuthResult) {
		go e.connectSMB(auth)
	})
}

func (e *Explorer) connectSMB(auth AuthResult) {
	proxyConf := LoadProxySettings(e.prefs)

	client, err := NewSMBClient(
		auth.Domain, auth.Username, auth.NTLMHash, auth.Target,
		445, proxyConf, e.logMsg,
	)
	if err != nil {
		e.logMsg(fmt.Sprintf("[ERROR] %s", err))
		e.showError("Connection Failed", err.Error())
		return
	}

	if err := client.Connect(); err != nil {
		e.logMsg(fmt.Sprintf("[ERROR] %s", err))
		e.showError("Connection Failed", err.Error())
		return
	}

	shares, err := client.ListShares()
	if err != nil {
		e.logMsg(fmt.Sprintf("[ERROR] %s", err))
		e.showError("List Shares Failed", err.Error())
		client.Disconnect()
		return
	}

	e.mu.Lock()
	e.smbClient = client
	e.currentUser = auth.Username
	e.currentTarget = auth.Target
	e.currentShare = ""
	e.currentPath = ""
	e.visitedDirs = make(map[string]bool)
	e.visitedFiles = make(map[string]bool)
	e.mu.Unlock()

	e.updateShareList(shares)
	e.updateBreadcrumb()
	e.logMsg(fmt.Sprintf("[INFO] Connected to %s as %s", auth.Target, auth.Username))
	e.showInfo("Connection Successful", fmt.Sprintf("Connected to %s as %s", auth.Target, auth.Username))
}

func (e *Explorer) disconnect() {
	e.mu.Lock()
	if e.smbClient != nil {
		e.smbClient.Disconnect()
		e.smbClient = nil
	}
	e.currentUser = ""
	e.currentTarget = ""
	e.currentShare = ""
	e.currentPath = ""
	e.visitedDirs = make(map[string]bool)
	e.visitedFiles = make(map[string]bool)
	e.mu.Unlock()

	e.updateShareList(nil)
	e.updateBreadcrumb()
	e.clearPreview()
	e.entries = nil
	e.fileTable.Refresh()
	e.logMsg("[INFO] Disconnected.")
}

func (e *Explorer) updateShareList(shares []string) {
	if len(shares) == 0 {
		e.shareNames = []string{"No shares found or not connected."}
	} else {
		e.shareNames = shares
	}
	e.shareList.Refresh()
}

func (e *Explorer) loadSharePath(share, path string) {
	if e.smbClient == nil {
		return
	}
	e.currentShare = share
	e.currentPath = path
	e.updateBreadcrumb()

	entries, err := e.smbClient.ListDir(share, path)
	if err != nil {
		e.logMsg(fmt.Sprintf("[ERROR] Failed to list directory: %s", err))
		e.showError("List Directory Failed", err.Error())
		e.entries = nil
		e.fileTable.Refresh()
		return
	}

	// Prepend ".." if not at root
	if path != "" && path != "/" {
		entries = append([]DirEntry{{Name: "..", IsDir: true}}, entries...)
	}

	e.entries = entries
	e.applySorting()
	e.fileTable.Refresh()
	// Scroll to top to force Fyne to re-render all visible rows
	e.fileTable.ScrollTo(widget.TableCellID{Row: 0, Col: 0})
	e.logMsg(fmt.Sprintf("[INFO] Listed %d entries in %s/%s", len(entries), share, path))
}

func (e *Explorer) sortBy(col int) {
	if e.sortCol == col {
		e.sortAsc = !e.sortAsc
	} else {
		e.sortCol = col
		e.sortAsc = true
	}
	e.applySorting()
	e.fileTable.Refresh()
}

func (e *Explorer) applySorting() {
	if len(e.entries) == 0 {
		return
	}
	// Keep ".." always first
	startIdx := 0
	if len(e.entries) > 0 && e.entries[0].Name == ".." {
		startIdx = 1
	}
	sortable := e.entries[startIdx:]

	sort.SliceStable(sortable, func(i, j int) bool {
		a, b := sortable[i], sortable[j]
		var less bool
		switch e.sortCol {
		case 0:
			less = strings.ToLower(a.Name) < strings.ToLower(b.Name)
		case 1:
			less = a.IsDir && !b.IsDir
		case 2:
			less = a.Size < b.Size
		case 3:
			less = a.LastWrite.Before(b.LastWrite)
		}
		if !e.sortAsc {
			less = !less
		}
		return less
	})
}

// onTableDoubleClick handles entering folders or previewing files on double-click.
func (e *Explorer) onTableDoubleClick(row int) {
	if row < 0 || row >= len(e.entries) {
		return
	}
	entry := e.entries[row]

	if entry.IsDir {
		if entry.Name == ".." {
			if e.currentPath == "" || e.currentPath == "/" {
				return
			}
			parts := strings.Split(strings.TrimSuffix(e.currentPath, "/"), "/")
			parts = parts[:len(parts)-1]
			e.currentPath = strings.Join(parts, "/")
			if e.currentPath != "" {
				e.currentPath += "/"
			}
		} else {
			folderPath := e.currentPath + entry.Name + "/"
			e.visitedDirs[e.visitedKey(folderPath)] = true
			e.currentPath = folderPath
		}
		e.updateBreadcrumb()
		e.loadSharePath(e.currentShare, e.currentPath)
	} else {
		// Double-click on file → preview
		go e.previewFile(entry.Name)
	}
}

// showItemContextMenu shows a context menu for the clicked row.
func (e *Explorer) showItemContextMenu(row int) {
	if row < 0 || row >= len(e.entries) {
		return
	}
	entry := e.entries[row]
	var items []*fyne.MenuItem

	if entry.Name == ".." {
		items = append(items, fyne.NewMenuItem("Go Up", func() {
			e.onTableDoubleClick(row)
		}))
	} else if entry.IsDir {
		dirUnc := e.uncPath(entry.Name + "/")
		items = append(items,
			fyne.NewMenuItem("Open Folder", func() {
				e.onTableDoubleClick(row)
			}),
			fyne.NewMenuItem("Download Folder", func() {
				go e.downloadFolder(entry.Name)
			}),
			fyne.NewMenuItem("🔍 Scan Folder for Secrets", func() {
				go e.scanFolder(entry.Name)
			}),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("⭐ Add to Favorites", func() {
				e.addFavoriteForPath(e.currentShare, e.currentPath+entry.Name+"/")
			}),
			fyne.NewMenuItem("📋 Copy UNC Path", func() {
				e.win.Clipboard().SetContent(dirUnc)
				e.logMsg(fmt.Sprintf("[INFO] Copied: %s", dirUnc))
			}),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("🏷 Tag...", func() {
				e.showTagDialog(dirUnc)
			}),
		)
	} else {
		fileUnc := e.uncPath(entry.Name)
		items = append(items,
			fyne.NewMenuItem("Preview", func() {
				go e.previewFile(entry.Name)
			}),
			fyne.NewMenuItem("Download", func() {
				go e.downloadSingleFile(entry.Name)
			}),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("⭐ Add to Favorites", func() {
				e.addFavoriteForPath(e.currentShare, e.currentPath+entry.Name)
			}),
			fyne.NewMenuItem("📋 Copy UNC Path", func() {
				e.win.Clipboard().SetContent(fileUnc)
				e.logMsg(fmt.Sprintf("[INFO] Copied: %s", fileUnc))
			}),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("🏷 Tag...", func() {
				e.showTagDialog(fileUnc)
			}),
		)
	}

	menu := fyne.NewMenu("", items...)
	popup := widget.NewPopUpMenu(menu, e.win.Canvas())
	pos := fyne.CurrentApp().Driver().AbsolutePositionForObject(e.fileTable)
	popup.ShowAtPosition(fyne.NewPos(pos.X+150, pos.Y+float32(row*30)+30))
}

// uncPath builds a UNC path for the given entry name.
func (e *Explorer) uncPath(entryName string) string {
	path := strings.ReplaceAll(e.currentPath+entryName, "/", "\\")
	return fmt.Sprintf("\\\\%s\\%s\\%s", e.currentTarget, e.currentShare, path)
}

func (e *Explorer) refresh() {
	if e.smbClient == nil || e.currentShare == "" {
		return
	}
	e.loadSharePath(e.currentShare, e.currentPath)
}

func (e *Explorer) downloadSelected() {
	if e.smbClient == nil {
		e.showError("Not Connected", "Connect to an SMB server first.")
		return
	}
	if e.selectedRow >= 0 && e.selectedRow < len(e.entries) {
		entry := e.entries[e.selectedRow]
		if entry.IsDir && entry.Name != ".." {
			go e.downloadFolder(entry.Name)
		} else if !entry.IsDir {
			go e.downloadSingleFile(entry.Name)
		}
	} else {
		e.logMsg("[INFO] Select a file or folder first, then click Download.")
	}
}

func (e *Explorer) downloadSingleFile(filename string) {
	if e.smbClient == nil {
		return
	}
	smbPath := strings.TrimPrefix(e.currentPath+filename, "/")

	localPath, err := nativeSaveFile("Save file as", filename)
	if err != nil || localPath == "" {
		e.logMsg("[INFO] Download cancelled.")
		return
	}

	e.logMsg(fmt.Sprintf("[INFO] Downloading %s ...", filename))
	if err := e.smbClient.DownloadFile(e.currentShare, smbPath, localPath); err != nil {
		e.logMsg(fmt.Sprintf("[ERROR] Download failed: %s", err))
		e.showError("Download Failed", err.Error())
	} else {
		e.visitedFiles[e.fileKey(e.currentPath+filename)] = true
		e.fileTable.Refresh()
		e.logMsg(fmt.Sprintf("[INFO] Saved to %s", localPath))
		e.showInfo("Download Complete", fmt.Sprintf("File saved to %s", localPath))
	}
}

func (e *Explorer) downloadFolder(folderName string) {
	if e.smbClient == nil {
		return
	}
	localDir, err := nativeChooseFolder("Choose destination folder for download")
	if err != nil || localDir == "" {
		e.logMsg("[INFO] Folder download cancelled.")
		return
	}
	targetDir := filepath.Join(localDir, folderName)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		e.logMsg(fmt.Sprintf("[ERROR] Failed to create local directory: %s", err))
		return
	}
	remotePath := e.currentPath + folderName + "/"
	e.logMsg(fmt.Sprintf("[INFO] Downloading folder %s → %s ...", remotePath, targetDir))
	if err := e.smbClient.DownloadFolder(e.currentShare, remotePath, targetDir); err != nil {
		e.logMsg(fmt.Sprintf("[ERROR] Folder download failed: %s", err))
		e.showError("Folder Download Failed", err.Error())
	} else {
		e.logMsg(fmt.Sprintf("[INFO] Folder downloaded to %s", targetDir))
		e.showInfo("Download Complete", fmt.Sprintf("Folder saved to %s", targetDir))
	}
}

func (e *Explorer) uploadFile() {
	if e.smbClient == nil {
		e.showError("Not Connected", "Connect to an SMB server first.")
		return
	}
	if e.currentShare == "" {
		e.showError("No Share", "Select a share first.")
		return
	}

	localPath, err := nativeOpenFile("Choose file to upload")
	if err != nil || localPath == "" {
		e.logMsg("[INFO] Upload cancelled.")
		return
	}
	remoteName := filepath.Base(localPath)
	remotePath := strings.TrimPrefix(e.currentPath+remoteName, "/")

	go func() {
		e.logMsg(fmt.Sprintf("[INFO] Uploading %s ...", remoteName))
		if err := e.smbClient.UploadFile(e.currentShare, remotePath, localPath); err != nil {
			e.logMsg(fmt.Sprintf("[ERROR] Upload failed: %s", err))
			e.showError("Upload Failed", err.Error())
		} else {
			e.logMsg(fmt.Sprintf("[INFO] Uploaded %s", remoteName))
			e.showInfo("Upload Complete", fmt.Sprintf("Uploaded %s", remoteName))
			e.refresh()
		}
	}()
}

// --- Preview ---

func (e *Explorer) cleanupPreviewTmp() {
	if e.lastPreviewTmp != "" {
		os.Remove(e.lastPreviewTmp)
		e.lastPreviewTmp = ""
	}
}

func (e *Explorer) previewFile(filename string) {
	if e.smbClient == nil {
		return
	}
	smbPath := strings.TrimPrefix(e.currentPath+filename, "/")

	// Clean up previous preview temp file
	e.cleanupPreviewTmp()

	tmpDir := os.TempDir()
	localTmp := filepath.Join(tmpDir, fmt.Sprintf("eyebrowse_preview_%d_%s", os.Getpid(), filename))

	e.logMsg(fmt.Sprintf("[INFO] Downloading for preview: %s", filename))
	if err := e.smbClient.DownloadFile(e.currentShare, smbPath, localTmp); err != nil {
		e.logMsg(fmt.Sprintf("[ERROR] Preview download failed: %s", err))
		e.showPreviewMessage("Failed to download file for preview.")
		return
	}
	e.lastPreviewTmp = localTmp

	// Mark file as visited
	e.visitedFiles[e.fileKey(e.currentPath+filename)] = true
	e.fileTable.Refresh()

	ext := strings.ToLower(filepath.Ext(filename))

	// Image preview
	if ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".gif" || ext == ".bmp" || ext == ".webp" || ext == ".ico" || ext == ".svg" {
		e.previewLabel.File = localTmp
		e.previewLabel.Refresh()
		e.previewContent.Objects = []fyne.CanvasObject{e.previewImgScroll}
		e.previewContent.Refresh()
		e.logMsg("[INFO] Image preview displayed.")
		return
	}

	// Office/PDF text extraction
	if isOfficeExt(ext) {
		text, err := extractTextFromFile(localTmp)
		if err != nil {
			e.logMsg(fmt.Sprintf("[WARN] Office extraction failed: %s", err))
			e.showPreviewMessage(fmt.Sprintf("Failed to extract text from %s file.", ext))
			return
		}
		if text == "" {
			e.showPreviewMessage("No text content found in document.")
			return
		}
		e.previewText.SetText(text)
		e.previewContent.Objects = []fyne.CanvasObject{e.previewText}
		e.previewContent.Refresh()
		e.logMsg(fmt.Sprintf("[INFO] %s preview displayed.", ext))
		return
	}

	// Known text/notepad-readable extensions — always show as text preview
	knownText := isKnownTextExt(ext)

	// Read file for content-based detection
	f, err := os.Open(localTmp)
	if err != nil {
		e.showPreviewMessage("Cannot open file for preview.")
		return
	}
	defer f.Close()

	buf := make([]byte, 2048)
	n, _ := f.Read(buf)
	buf = buf[:n]

	isText := knownText
	if !isText {
		// Heuristic: check if first 2KB is printable text
		isText = true
		for _, b := range buf {
			if b < 32 && b != 9 && b != 10 && b != 13 {
				isText = false
				break
			}
		}
	}

	if isText && (n > 0 || knownText) {
		f.Seek(0, io.SeekStart)
		textBuf := make([]byte, 64*1024)
		nn, _ := f.Read(textBuf)
		text := string(textBuf[:nn])

		e.previewText.SetText(text)
		e.previewContent.Objects = []fyne.CanvasObject{e.previewText}
		e.previewContent.Refresh()
		e.logMsg("[INFO] Text preview displayed.")
		return
	}

	e.showPreviewMessage("No preview available for this file type.")
}

func (e *Explorer) showPreviewMessage(msg string) {
	e.previewText.SetText(msg)
	e.previewContent.Objects = []fyne.CanvasObject{e.previewText}
	e.previewContent.Refresh()
}

func (e *Explorer) clearPreview() {
	e.cleanupPreviewTmp()
	e.previewText.SetText("")
	e.previewContent.Objects = nil
	e.previewContent.Refresh()
}

// --- Folder Scan ---

// FileFinding represents a sensitive data finding with its source file.
type FileFinding struct {
	File    string
	Finding Finding
}

// listAllFiles recursively lists all file paths under the given share/path.
func (e *Explorer) listAllFiles(share, path string, depth int) []string {
	if depth > 10 || e.smbClient == nil {
		return nil
	}
	entries, err := e.smbClient.ListDir(share, path)
	if err != nil {
		e.logMsg(fmt.Sprintf("[WARN] Cannot list %s: %s", path, err))
		return nil
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir {
			subPath := path + entry.Name + "/"
			files = append(files, e.listAllFiles(share, subPath, depth+1)...)
		} else {
			files = append(files, path+entry.Name)
		}
	}
	return files
}

// isScannable returns true if the file extension is something we can extract text from.
func isScannable(ext string) bool {
	return isKnownTextExt(ext) || isOfficeExt(ext)
}

// scanFolder recursively scans a folder for sensitive data patterns.
func (e *Explorer) scanFolder(folderName string) {
	if e.smbClient == nil {
		return
	}
	remotePath := e.currentPath + folderName + "/"
	e.logMsg(fmt.Sprintf("[INFO] Starting folder scan: %s/%s", e.currentShare, remotePath))

	// Recursively list all files
	allFiles := e.listAllFiles(e.currentShare, remotePath, 0)
	if len(allFiles) == 0 {
		e.logMsg("[INFO] No files found in folder.")
		e.showInfo("Folder Scan", "No files found in this folder.")
		return
	}
	e.logMsg(fmt.Sprintf("[INFO] Found %d files to scan", len(allFiles)))

	// Filter to scannable files
	var scanFiles []string
	for _, f := range allFiles {
		ext := strings.ToLower(filepath.Ext(f))
		if isScannable(ext) {
			scanFiles = append(scanFiles, f)
		} else {
			// Check unknown extensions later via heuristic
			scanFiles = append(scanFiles, f)
		}
	}

	var allFindings []FileFinding
	tmpDir := os.TempDir()
	scanned := 0

	for i, remoteFile := range scanFiles {
		localName := filepath.Base(remoteFile)
		localTmp := filepath.Join(tmpDir, fmt.Sprintf("eyebrowse_scan_%d_%d_%s", os.Getpid(), i, localName))

		smbPath := strings.TrimPrefix(remoteFile, "/")
		if err := e.smbClient.DownloadFile(e.currentShare, smbPath, localTmp); err != nil {
			os.Remove(localTmp)
			continue
		}

		text := extractTextForScan(localTmp)
		os.Remove(localTmp)

		if text == "" {
			continue
		}
		scanned++

		findings := scanForSensitiveData(text)
		for _, f := range findings {
			allFindings = append(allFindings, FileFinding{
				File:    remoteFile,
				Finding: f,
			})
		}

		// Progress logging every 10 files
		if (i+1)%10 == 0 || i == len(scanFiles)-1 {
			e.logMsg(fmt.Sprintf("[INFO] Scan progress: %d/%d files (%d findings so far)", i+1, len(scanFiles), len(allFindings)))
		}
	}

	e.logMsg(fmt.Sprintf("[INFO] Folder scan complete: scanned %d text files, %d findings", scanned, len(allFindings)))
	e.showFolderScanResults(folderName, allFindings)
}

// showFolderScanResults displays the folder scan results in a dialog.
func (e *Explorer) showFolderScanResults(folderName string, findings []FileFinding) {
	if len(findings) == 0 {
		e.showInfo("Folder Scan Complete", fmt.Sprintf("No sensitive patterns found in %s/", folderName))
		return
	}

	// Group by file, then by pattern within each file
	type fileGroup struct {
		file     string
		findings []FileFinding
	}
	orderMap := make(map[string]int)
	var groups []fileGroup
	for _, f := range findings {
		idx, exists := orderMap[f.File]
		if !exists {
			idx = len(groups)
			orderMap[f.File] = idx
			groups = append(groups, fileGroup{file: f.File})
		}
		groups[idx].findings = append(groups[idx].findings, f)
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("Folder: %s/\nTotal findings: %d across %d files\n", folderName, len(findings), len(groups)))
	for _, g := range groups {
		lines = append(lines, fmt.Sprintf("=== %s (%d matches) ===", g.file, len(g.findings)))
		for _, f := range g.findings {
			lines = append(lines, fmt.Sprintf("  [%s] Line %d: %s", f.Finding.PatternName, f.Finding.LineNum, f.Finding.Match))
		}
		lines = append(lines, "")
	}

	resultText := strings.Join(lines, "\n")

	resultEntry := widget.NewMultiLineEntry()
	resultEntry.SetText(resultText)
	resultEntry.Wrapping = fyne.TextWrapWord

	copyBtn := widget.NewButton("Copy All to Clipboard", func() {
		e.win.Clipboard().SetContent(resultText)
		e.logMsg("[INFO] Folder scan results copied to clipboard.")
	})

	content := container.NewBorder(nil, copyBtn, nil, nil, resultEntry)

	d := dialog.NewCustom(
		fmt.Sprintf("Folder Scan: %s/ - %d Findings", folderName, len(findings)),
		"Close",
		container.NewGridWrap(fyne.NewSize(750, 450), content),
		e.win,
	)
	d.Resize(fyne.NewSize(800, 530))
	d.Show()
}

// --- UNC Navigation ---

// parseUNCPath parses a UNC path like \\server\share\path\to\file into components.
func parseUNCPath(unc string) (server, share, path string, ok bool) {
	// Strip leading backslashes
	s := strings.TrimLeft(unc, "\\")
	parts := strings.SplitN(s, "\\", 3)
	if len(parts) < 2 {
		return "", "", "", false
	}
	server = parts[0]
	share = parts[1]
	if len(parts) == 3 {
		path = strings.ReplaceAll(parts[2], "\\", "/")
	}
	return server, share, path, true
}

// navigateToUNCPath navigates the explorer to the parent directory of a UNC path.
// If already connected to the same server, navigates directly.
// If not connected, shows an info message.
func (e *Explorer) navigateToUNCPath(unc string) {
	server, share, path, ok := parseUNCPath(unc)
	if !ok {
		e.showInfo("Navigation", "Could not parse UNC path: "+unc)
		return
	}

	// Check if we're connected to the same server
	if e.smbClient == nil || !strings.EqualFold(e.currentTarget, server) {
		e.showInfo("Navigation", fmt.Sprintf("Not connected to %s.\nConnect first, then navigate.", server))
		return
	}

	// Determine parent directory path
	parentPath := path
	if parentPath != "" && !strings.HasSuffix(parentPath, "/") {
		// It's a file path — navigate to parent
		idx := strings.LastIndex(parentPath, "/")
		if idx >= 0 {
			parentPath = parentPath[:idx+1]
		} else {
			parentPath = ""
		}
	}

	e.loadSharePath(share, parentPath)
	e.logMsg(fmt.Sprintf("[INFO] Navigated to %s/%s via tag", share, parentPath))
}

// --- Helpers ---

func (e *Explorer) showError(title, msg string) {
	dialog.ShowError(fmt.Errorf("%s", msg), e.win)
}

func (e *Explorer) showInfo(title, msg string) {
	dialog.ShowInformation(title, msg, e.win)
}

// --- Favorites ---

const favPrefsKey = "favorites_json"

func (e *Explorer) loadFavorites() {
	raw := e.prefs.StringWithFallback(favPrefsKey, "[]")
	var favs []Favorite
	if err := json.Unmarshal([]byte(raw), &favs); err != nil {
		e.favorites = nil
		return
	}
	e.favorites = favs
}

func (e *Explorer) saveFavorites() {
	data, err := json.Marshal(e.favorites)
	if err != nil {
		return
	}
	e.prefs.SetString(favPrefsKey, string(data))
	if e.favList != nil {
		e.favList.Refresh()
	}
}

func (e *Explorer) addFavoriteDialog() {
	if e.currentTarget == "" || e.currentShare == "" {
		e.showError("No Location", "Connect to a share and navigate to a folder first.")
		return
	}
	e.addFavoriteForPath(e.currentShare, e.currentPath)
}

// addFavoriteForPath saves a favorite using the current connection + specified share/path as a UNC path.
func (e *Explorer) addFavoriteForPath(share, path string) {
	if e.currentTarget == "" {
		e.showError("Not Connected", "Connect to an SMB server first.")
		return
	}
	pathBackslash := strings.ReplaceAll(path, "/", "\\")
	unc := fmt.Sprintf("\\\\%s\\%s\\%s", e.currentTarget, share, pathBackslash)
	// Remove trailing backslash for cleanliness
	unc = strings.TrimRight(unc, "\\")

	// Check for duplicate
	for _, f := range e.favorites {
		if f.Name == unc {
			e.logMsg(fmt.Sprintf("[INFO] Favorite already exists: %s", unc))
			return
		}
	}

	// Store the hash encrypted in the favorite
	rawHash := decryptString(e.prefs.StringWithFallback("auth_hash", ""))
	encHash, err := encryptString(rawHash)
	if err != nil {
		encHash = rawHash // fallback to plaintext if encryption fails
	}
	fav := Favorite{
		Name:     unc,
		Domain:   e.prefs.StringWithFallback("auth_domain", ""),
		Username: e.prefs.StringWithFallback("auth_username", ""),
		Hash:     encHash,
		Target:   e.currentTarget,
		Share:    share,
		Path:     path,
	}
	e.favorites = append(e.favorites, fav)
	e.saveFavorites()
	e.logMsg(fmt.Sprintf("[INFO] Favorite saved: %s", unc))
}

func (e *Explorer) removeFavorite(index int) {
	if index < 0 || index >= len(e.favorites) {
		return
	}
	name := e.favorites[index].Name
	e.favorites = append(e.favorites[:index], e.favorites[index+1:]...)
	e.saveFavorites()
	e.logMsg(fmt.Sprintf("[INFO] Favorite removed: %s", name))
}

func (e *Explorer) showManageFavoritesDialog() {
	if len(e.favorites) == 0 {
		dialog.ShowInformation("Favorites", "No favorites saved yet.\nUse ⭐ Add to Favorites from the context menu.", e.win)
		return
	}

	var list *widget.List
	list = widget.NewList(
		func() int { return len(e.favorites) },
		func() fyne.CanvasObject {
			return container.NewHBox(
				widget.NewLabel("\\\\server\\share\\path placeholder text"),
				layout.NewSpacer(),
				widget.NewButtonWithIcon("", theme.ContentCopyIcon(), nil),
				widget.NewButton("Go", nil),
				widget.NewButtonWithIcon("", theme.DeleteIcon(), nil),
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			box := obj.(*fyne.Container)
			label := box.Objects[0].(*widget.Label)
			copyBtn := box.Objects[2].(*widget.Button)
			goBtn := box.Objects[3].(*widget.Button)
			delBtn := box.Objects[4].(*widget.Button)
			if id < len(e.favorites) {
				fav := e.favorites[id]
				label.SetText(fav.Name)
				copyBtn.OnTapped = func() {
					e.win.Clipboard().SetContent(fav.Name)
					e.logMsg(fmt.Sprintf("[INFO] Copied: %s", fav.Name))
				}
				goBtn.OnTapped = func() {
					go e.connectToFavorite(fav)
				}
				idx := id
				delBtn.OnTapped = func() {
					e.removeFavorite(idx)
					list.Refresh()
				}
			}
		},
	)

	d := dialog.NewCustom("Manage Favorites", "Close",
		container.NewGridWrap(fyne.NewSize(700, 350), list), e.win)
	d.Resize(fyne.NewSize(750, 420))
	d.Show()
}

func (e *Explorer) connectToFavorite(fav Favorite) {
	e.logMsg(fmt.Sprintf("[INFO] Connecting to favorite: %s", fav.Name))

	// Disconnect existing if connected
	e.mu.Lock()
	if e.smbClient != nil {
		e.smbClient.Disconnect()
		e.smbClient = nil
	}
	e.mu.Unlock()

	auth := AuthResult{
		Domain:   fav.Domain,
		Username: fav.Username,
		NTLMHash: decryptString(fav.Hash),
		Target:   fav.Target,
	}

	proxyConf := LoadProxySettings(e.prefs)
	client, err := NewSMBClient(
		auth.Domain, auth.Username, auth.NTLMHash, auth.Target,
		445, proxyConf, e.logMsg,
	)
	if err != nil {
		e.logMsg(fmt.Sprintf("[ERROR] %s", err))
		e.showError("Favorite Connect Failed", err.Error())
		return
	}
	if err := client.Connect(); err != nil {
		e.logMsg(fmt.Sprintf("[ERROR] %s", err))
		e.showError("Favorite Connect Failed", err.Error())
		return
	}

	shares, err := client.ListShares()
	if err != nil {
		e.logMsg(fmt.Sprintf("[ERROR] %s", err))
		e.showError("List Shares Failed", err.Error())
		client.Disconnect()
		return
	}

	e.mu.Lock()
	e.smbClient = client
	e.currentUser = auth.Username
	e.currentTarget = auth.Target
	e.currentShare = ""
	e.currentPath = ""
	e.visitedDirs = make(map[string]bool)
	e.visitedFiles = make(map[string]bool)
	e.mu.Unlock()

	e.updateShareList(shares)
	e.updateBreadcrumb()
	e.logMsg(fmt.Sprintf("[INFO] Connected to %s as %s", auth.Target, auth.Username))

	// Clear stale preview and file entries
	e.clearPreview()
	e.entries = nil
	e.fileTable.Refresh()

	// Navigate to the saved share and path
	if fav.Share != "" {
		e.loadSharePath(fav.Share, fav.Path)
	}
}

// --- Tags ---

const tagsPrefsKey = "tags_json"

func (e *Explorer) loadTags() {
	raw := e.prefs.StringWithFallback(tagsPrefsKey, "{}")
	var t map[string][]string
	if err := json.Unmarshal([]byte(raw), &t); err != nil {
		e.tags = make(map[string][]string)
		return
	}
	e.tags = t
}

func (e *Explorer) saveTags() {
	data, err := json.Marshal(e.tags)
	if err != nil {
		return
	}
	e.prefs.SetString(tagsPrefsKey, string(data))
}

// allUniqueTags returns a sorted list of all tag names currently in use.
func (e *Explorer) allUniqueTags() []string {
	seen := make(map[string]bool)
	for _, tags := range e.tags {
		for _, t := range tags {
			seen[t] = true
		}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// showTagDialog shows a dialog to add/remove tags for a UNC path.
func (e *Explorer) showTagDialog(unc string) {
	current := make(map[string]bool)
	for _, t := range e.tags[unc] {
		current[t] = true
	}

	// Create checkboxes for predefined tags
	checks := make(map[string]*widget.Check)
	var checkWidgets []fyne.CanvasObject
	for _, tag := range predefinedTags {
		t := tag
		chk := widget.NewCheck(t, nil)
		chk.Checked = current[t]
		checks[t] = chk
		checkWidgets = append(checkWidgets, chk)
	}

	// Custom tag entry
	customEntry := widget.NewEntry()
	customEntry.SetPlaceHolder("Custom tag name...")

	pathLabel := widget.NewLabel(unc)
	pathLabel.Wrapping = fyne.TextWrapWord
	pathLabel.TextStyle = fyne.TextStyle{Monospace: true}

	content := container.NewVBox(
		widget.NewLabel("Path:"),
		pathLabel,
		widget.NewSeparator(),
		widget.NewLabel("Tags:"),
	)
	for _, w := range checkWidgets {
		content.Add(w)
	}
	content.Add(widget.NewSeparator())
	content.Add(widget.NewLabel("Custom tag:"))
	content.Add(customEntry)

	d := dialog.NewCustomConfirm("Tag Item", "Save", "Cancel",
		container.NewVScroll(content),
		func(ok bool) {
			if !ok {
				return
			}
			var newTags []string
			for _, tag := range predefinedTags {
				if checks[tag].Checked {
					newTags = append(newTags, tag)
				}
			}
			custom := strings.TrimSpace(customEntry.Text)
			if custom != "" {
				// Add custom tag if not already present
				found := false
				for _, t := range newTags {
					if strings.EqualFold(t, custom) {
						found = true
						break
					}
				}
				if !found {
					newTags = append(newTags, custom)
				}
			}
			if len(newTags) == 0 {
				delete(e.tags, unc)
			} else {
				e.tags[unc] = newTags
			}
			e.saveTags()
			e.fileTable.Refresh()
			e.logMsg(fmt.Sprintf("[INFO] Tags updated for %s: %v", unc, newTags))
		}, e.win)
	d.Resize(fyne.NewSize(500, 450))
	d.Show()
}

// showManageTagsDialog shows all tagged items with their tags.
func (e *Explorer) showManageTagsDialog() {
	if len(e.tags) == 0 {
		dialog.ShowInformation("Tags", "No items tagged yet.\nRight-click a file or folder and select 🏷 Tag...", e.win)
		return
	}

	// Build a sorted list of UNC paths
	paths := make([]string, 0, len(e.tags))
	for p := range e.tags {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var list *widget.List
	list = widget.NewList(
		func() int { return len(paths) },
		func() fyne.CanvasObject {
			return container.NewHBox(
				widget.NewLabel("\\\\server\\share\\path [Tag1] [Tag2] placeholder"),
				layout.NewSpacer(),
				widget.NewButton("Go", nil),
				widget.NewButtonWithIcon("", theme.ContentCopyIcon(), nil),
				widget.NewButtonWithIcon("", theme.DocumentIcon(), nil),
				widget.NewButtonWithIcon("", theme.DeleteIcon(), nil),
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			if id >= len(paths) {
				return
			}
			box := obj.(*fyne.Container)
			label := box.Objects[0].(*widget.Label)
			goBtn := box.Objects[2].(*widget.Button)
			copyBtn := box.Objects[3].(*widget.Button)
			editBtn := box.Objects[4].(*widget.Button)
			delBtn := box.Objects[5].(*widget.Button)

			p := paths[id]
			tagStr := ""
			for _, t := range e.tags[p] {
				tagStr += " [" + t + "]"
			}
			label.SetText(p + tagStr)

			goBtn.OnTapped = func() {
				e.navigateToUNCPath(p)
			}
			copyBtn.OnTapped = func() {
				e.win.Clipboard().SetContent(p)
				e.logMsg(fmt.Sprintf("[INFO] Copied: %s", p))
			}
			editBtn.OnTapped = func() {
				e.showTagDialog(p)
			}
			idx := id
			delBtn.OnTapped = func() {
				delete(e.tags, paths[idx])
				e.saveTags()
				e.fileTable.Refresh()
				// Rebuild paths list
				paths = paths[:0]
				for pp := range e.tags {
					paths = append(paths, pp)
				}
				sort.Strings(paths)
				list.Refresh()
			}
		},
	)

	d := dialog.NewCustom("Manage Tags", "Close",
		container.NewGridWrap(fyne.NewSize(750, 400), list), e.win)
	d.Resize(fyne.NewSize(800, 480))
	d.Show()
}

// showExportByTagDialog lets the user pick a tag and copies all matching UNC paths.
func (e *Explorer) showExportByTagDialog() {
	uniqueTags := e.allUniqueTags()
	if len(uniqueTags) == 0 {
		dialog.ShowInformation("Export by Tag", "No tags found.\nRight-click files and use 🏷 Tag... to tag items first.", e.win)
		return
	}

	tagSelect := widget.NewSelect(uniqueTags, nil)
	tagSelect.PlaceHolder = "Select a tag..."

	d := dialog.NewCustomConfirm("Export UNC Paths by Tag", "Copy to Clipboard", "Cancel",
		container.NewVBox(
			widget.NewLabel("Choose a tag to export all matching UNC paths:"),
			tagSelect,
		),
		func(ok bool) {
			if !ok || tagSelect.Selected == "" {
				return
			}
			tag := tagSelect.Selected
			var lines []string
			for unc, tags := range e.tags {
				for _, t := range tags {
					if t == tag {
						lines = append(lines, unc)
						break
					}
				}
			}
			sort.Strings(lines)
			result := strings.Join(lines, "\n")
			e.win.Clipboard().SetContent(result)
			e.logMsg(fmt.Sprintf("[INFO] Exported %d UNC paths for tag [%s] to clipboard", len(lines), tag))
			e.showInfo("Exported", fmt.Sprintf("Copied %d UNC paths tagged [%s] to clipboard.", len(lines), tag))
		}, e.win)
	d.Resize(fyne.NewSize(400, 200))
	d.Show()
}

// exportAllTagged copies all tagged UNC paths (with their tags) to clipboard.
func (e *Explorer) exportAllTagged() {
	if len(e.tags) == 0 {
		dialog.ShowInformation("Export All Tagged", "No items tagged yet.", e.win)
		return
	}

	result := e.buildAllTaggedExport()
	e.win.Clipboard().SetContent(result)
	count := len(e.tags)
	e.logMsg(fmt.Sprintf("[INFO] Exported %d tagged UNC paths to clipboard", count))
	e.showInfo("Exported", fmt.Sprintf("Copied %d tagged UNC paths to clipboard.", count))
}

// exportAllTaggedToFile saves all tagged UNC paths to a file chosen by the user.
func (e *Explorer) exportAllTaggedToFile() {
	if len(e.tags) == 0 {
		dialog.ShowInformation("Export All Tagged", "No items tagged yet.", e.win)
		return
	}

	result := e.buildAllTaggedExport()
	go func() {
		path, err := nativeSaveFile("Save Tagged UNC Paths", "tagged_paths.txt")
		if err != nil || path == "" {
			return
		}
		if err := os.WriteFile(path, []byte(result), 0644); err != nil {
			e.logMsg(fmt.Sprintf("[ERROR] Failed to write file: %s", err))
			e.showError("Export Failed", err.Error())
			return
		}
		count := len(e.tags)
		e.logMsg(fmt.Sprintf("[INFO] Exported %d tagged UNC paths to %s", count, path))
		e.showInfo("Exported", fmt.Sprintf("Saved %d tagged UNC paths to:\n%s", count, path))
	}()
}

// buildAllTaggedExport builds the export string for all tagged items.
func (e *Explorer) buildAllTaggedExport() string {
	paths := make([]string, 0, len(e.tags))
	for p := range e.tags {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var lines []string
	for _, p := range paths {
		tagStr := strings.Join(e.tags[p], ", ")
		lines = append(lines, fmt.Sprintf("%s  [%s]", p, tagStr))
	}
	return strings.Join(lines, "\n")
}

// showExportByTagToFile lets the user pick a tag and saves matching UNC paths to a file.
func (e *Explorer) showExportByTagToFile() {
	uniqueTags := e.allUniqueTags()
	if len(uniqueTags) == 0 {
		dialog.ShowInformation("Export by Tag", "No tags found.\nRight-click files and use 🏷 Tag... to tag items first.", e.win)
		return
	}

	tagSelect := widget.NewSelect(uniqueTags, nil)
	tagSelect.PlaceHolder = "Select a tag..."

	d := dialog.NewCustomConfirm("Export UNC Paths by Tag to File", "Save to File", "Cancel",
		container.NewVBox(
			widget.NewLabel("Choose a tag to export all matching UNC paths:"),
			tagSelect,
		),
		func(ok bool) {
			if !ok || tagSelect.Selected == "" {
				return
			}
			tag := tagSelect.Selected
			var lines []string
			for unc, tags := range e.tags {
				for _, t := range tags {
					if t == tag {
						lines = append(lines, unc)
						break
					}
				}
			}
			sort.Strings(lines)
			result := strings.Join(lines, "\n")

			go func() {
				path, err := nativeSaveFile("Save Tagged UNC Paths", fmt.Sprintf("tag_%s.txt", tag))
				if err != nil || path == "" {
					return
				}
				if err := os.WriteFile(path, []byte(result), 0644); err != nil {
					e.logMsg(fmt.Sprintf("[ERROR] Failed to write file: %s", err))
					e.showError("Export Failed", err.Error())
					return
				}
				e.logMsg(fmt.Sprintf("[INFO] Exported %d UNC paths for tag [%s] to %s", len(lines), tag, path))
				e.showInfo("Exported", fmt.Sprintf("Saved %d UNC paths tagged [%s] to:\n%s", len(lines), tag, path))
			}()
		}, e.win)
	d.Resize(fyne.NewSize(400, 200))
	d.Show()
}
