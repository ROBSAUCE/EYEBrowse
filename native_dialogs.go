package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// nativeOpenFile shows the OS native file-open dialog and returns the selected path.
// Returns empty string if the user cancels.
func nativeOpenFile(title string) (string, error) {
	script := fmt.Sprintf(`set f to POSIX path of (choose file with prompt "%s")
return f`, escapeAppleScript(title))
	return runOsascript(script)
}

// nativeSaveFile shows the OS native file-save dialog and returns the chosen path.
// Returns empty string if the user cancels.
func nativeSaveFile(title, defaultName string) (string, error) {
	script := fmt.Sprintf(`set f to POSIX path of (choose file name with prompt "%s" default name "%s")
return f`, escapeAppleScript(title), escapeAppleScript(defaultName))
	return runOsascript(script)
}

// nativeChooseFolder shows the OS native folder-picker dialog.
func nativeChooseFolder(title string) (string, error) {
	script := fmt.Sprintf(`set f to POSIX path of (choose folder with prompt "%s")
return f`, escapeAppleScript(title))
	return runOsascript(script)
}

func runOsascript(script string) (string, error) {
	cmd := exec.Command("osascript", "-e", script)
	out, err := cmd.Output()
	if err != nil {
		return "", err // user cancelled or error
	}
	return strings.TrimSpace(string(out)), nil
}

func escapeAppleScript(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
