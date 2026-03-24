package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// EyeBrowseTheme is a custom dark theme matching the Python EyeBrowse color scheme.
type EyeBrowseTheme struct{}

var _ fyne.Theme = (*EyeBrowseTheme)(nil)

func (t *EyeBrowseTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return color.NRGBA{R: 0x2B, G: 0x2B, B: 0x2B, A: 0xFF}
	case theme.ColorNameButton:
		return color.NRGBA{R: 0x3C, G: 0x3C, B: 0x3C, A: 0xFF}
	case theme.ColorNameForeground:
		return color.NRGBA{R: 0xE0, G: 0xE0, B: 0xE0, A: 0xFF}
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 0x15, G: 0x65, B: 0xC0, A: 0xFF} // Dark blue accent
	case theme.ColorNameHeaderBackground:
		return color.NRGBA{R: 0x1E, G: 0x1E, B: 0x1E, A: 0xFF}
	case theme.ColorNameInputBackground:
		return color.NRGBA{R: 0x1E, G: 0x1E, B: 0x1E, A: 0xFF}
	case theme.ColorNameSeparator:
		return color.NRGBA{R: 0x44, G: 0x44, B: 0x44, A: 0xFF}
	case theme.ColorNameHover:
		return color.NRGBA{R: 0x15, G: 0x65, B: 0xC0, A: 0x44}
	case theme.ColorNameSelection:
		return color.NRGBA{R: 0x15, G: 0x65, B: 0xC0, A: 0x88}
	case theme.ColorNameDisabled:
		return color.NRGBA{R: 0xB0, G: 0xB0, B: 0xB0, A: 0xFF}
	}
	return theme.DefaultTheme().Color(name, theme.VariantDark)
}

func (t *EyeBrowseTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (t *EyeBrowseTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (t *EyeBrowseTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 4
	case theme.SizeNameText:
		return 13
	}
	return theme.DefaultTheme().Size(name)
}

// Color constants matching the Python EyeBrowse color scheme.
var (
	ColorTerminalBG = color.NRGBA{R: 0x10, G: 0x10, B: 0x10, A: 0xFF} // #101010
	ColorStatusBG   = color.NRGBA{R: 0x1E, G: 0x1E, B: 0x1E, A: 0xFF}
)
