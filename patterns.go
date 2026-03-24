package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// SensitivePattern defines a named regex pattern for detecting sensitive data.
type SensitivePattern struct {
	Name    string
	Pattern *regexp.Regexp
}

// Finding represents a single match of a sensitive pattern in text.
type Finding struct {
	PatternName string
	Match       string
	LineNum     int
}

// buildLeetPattern generates a regex string for a word allowing common leet-speak substitutions.
func buildLeetPattern(word string) string {
	var buf strings.Builder
	for _, ch := range strings.ToLower(word) {
		switch ch {
		case 'a':
			buf.WriteString("[a@4]")
		case 'b':
			buf.WriteString("[b8]")
		case 'e':
			buf.WriteString("[e3]")
		case 'g':
			buf.WriteString("[g9]")
		case 'i':
			buf.WriteString("[i1!]")
		case 'l':
			buf.WriteString("[l1|]")
		case 'o':
			buf.WriteString("[o0]")
		case 's':
			buf.WriteString("[s$5]")
		case 't':
			buf.WriteString("[t7+]")
		default:
			buf.WriteRune(ch)
		}
	}
	return buf.String()
}

// ============================================================================
// Password Detection Algorithm — Tiered approach to minimize false positives
//
// How people form passwords (research-based):
//   1. Dictionary word + digit suffix (monkey123, football3)
//   2. Leet-speak substitution (p@ssw0rd, h4ck3r, 0Ptiv)
//   3. Season/month + year (Summer2024!, January2023)
//   4. Keyboard walk patterns (qwerty, asdf1234, 1qaz2wsx)
//   5. Capitalized word + digits + special (Welcome1!, Company2024#)
//   6. Common phrases (letmein, iloveyou, trustno1)
//   7. Numeric sequences (123456, 111111)
//
// Heuristic Password Scoring — no dictionary, pure structural analysis.
//
// Scores each token on multiple independent signals that distinguish
// passwords from normal text. An LLM recognizes "MICRO@dmin1" as a
// password because of character-class mixing, leet substitution, trailing
// digits, and pronounceability after normalization. This algorithm
// quantifies those same signals into a numeric confidence score.
//
// Signals (each contributes points):
//   1. Character-class diversity  (upper, lower, digit, special)
//   2. Character-class transitions (how interleaved the mixing is)
//   3. Leet-speak substitutions   (@→a, 0→o, 3→e, $→s, etc.)
//   4. Trailing modifiers         (digits/specials appended to a word base)
//   5. Embedded specials/digits   (special chars or leet digits inside letters)
//   6. Pronounceability           (vowel ratio after leet normalization)
//   7. Length in typical range    (6-20 characters)
//
// Pre-filters exclude emails, URLs, hex strings, file paths, and pure numbers.
// ============================================================================

var sensitivePatterns = []SensitivePattern{
	// --- Identity ---
	{"SSN", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},

	// --- Financial ---
	{"Credit Card (Visa)", regexp.MustCompile(`\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`)},
	{"Credit Card (MasterCard)", regexp.MustCompile(`\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`)},
	{"Credit Card (Amex)", regexp.MustCompile(`\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b`)},

	// --- Credentials ---
	{"Password Assignment", regexp.MustCompile(`(?i)(password|passwd|pwd|pass)\s*[=:]\s*\S+`)},
	{"Credential Assignment", regexp.MustCompile(`(?i)(credential|secret|private[_-]?key)\s*[=:]\s*\S+`)},
	{"Connection String", regexp.MustCompile(`(?i)(connection[_-]?string|connstr|dsn)\s*[=:]\s*\S+`)},
	{"Basic Auth Header", regexp.MustCompile(`(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]+`)},
	{"Bearer Token", regexp.MustCompile(`(?i)(Authorization:\s*Bearer|bearer[_-]?token)\s+[A-Za-z0-9._\-]+`)},
	{"Net-NTLMv2 Hash", regexp.MustCompile(`(?i)[a-zA-Z0-9]+::\S+:\S+:\S+:\S+`)},

	// --- API Keys & Tokens ---
	{"API Key Assignment", regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[=:]\s*\S+`)},
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"AWS Secret Key", regexp.MustCompile(`(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*[A-Za-z0-9/+=]{40}`)},
	{"Generic Token", regexp.MustCompile(`(?i)(access[_-]?token|auth[_-]?token|session[_-]?token)\s*[=:]\s*\S+`)},
	{"GitHub Token", regexp.MustCompile(`gh[ps]_[A-Za-z0-9_]{36,}`)},
	{"Slack Token", regexp.MustCompile(`xox[bpras]-[A-Za-z0-9-]+`)},
	{"Azure Client Secret", regexp.MustCompile(`(?i)(client[_-]?secret)\s*[=:]\s*\S+`)},

	// --- SSH & Crypto ---
	{"SSH Private Key", regexp.MustCompile(`-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`)},
	{"PGP Private Key", regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`)},

	// --- Database ---
	{"Database URL", regexp.MustCompile(`(?i)(mysql|postgres|postgresql|mongodb|redis|mssql|sqlserver)://\S+`)},
	{"JDBC Connection", regexp.MustCompile(`(?i)jdbc:[a-z]+://\S+`)},

	// --- Network ---
	{"Private IP Address", regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`)},
	{"Email Address", regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`)},

	// --- Windows / AD ---
	{"Net User Command", regexp.MustCompile(`(?i)net\s+user\s+\S+`)},
	{"Cmdkey Credential", regexp.MustCompile(`(?i)cmdkey\s+/add:\S+`)},
	{"Registry Password", regexp.MustCompile(`(?i)reg\s+(add|query)\s+.*(?i)(password|secret).*`)},
	{"NTLM Hash (32 hex)", regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`)},
	{"Kerberos Ticket", regexp.MustCompile(`(?i)(krb5cc_|\.kirbi|\.ccache)`)},

	// --- Structural Password Patterns ---
	// Season + year (Summer2024, W1nt3r2023!, etc.)
	{"Season+Year Password", regexp.MustCompile(`(?i)\b(` +
		buildLeetPattern("spring") + `|` +
		buildLeetPattern("summer") + `|` +
		buildLeetPattern("autumn") + `|` +
		buildLeetPattern("fall") + `|` +
		buildLeetPattern("winter") +
		`)(20\d{2}|\d{2})[!@#$%^&*]?\b`)},

	// Month + year (January2024!, March2023, etc.)
	{"Month+Year Password", regexp.MustCompile(`(?i)\b(january|february|march|april|may|june|july|august|september|october|november|december)(20\d{2}|\d{2})[!@#$%^&*]?\b`)},

	// Keyboard walks
	{"Keyboard Walk", regexp.MustCompile(`(?i)\b(qwerty|asdfgh|zxcvbn|qazwsx|1qaz2wsx|qwert|asdf1234)\d{0,4}[!@#$%^&*]?\b`)},

	// Numeric sequences
	{"Numeric Sequence", regexp.MustCompile(`\b(123456789?0?|1234567?|12345|111111|000000|123123|654321|112233|121212)\b`)},

	// Pattern: [A-Z][a-z]+[0-9]{1,4}[!@#$%^&*] — "Welcome1!", "Company2024#"
	{"Capitalized Word+Digits+Special", regexp.MustCompile(`\b[A-Z][a-z]{3,12}\d{1,4}[!@#$%^&*]\b`)},
}

// leetNormalize replaces common leet-speak characters back to their letter equivalents.
func leetNormalize(s string) string {
	var buf strings.Builder
	for _, ch := range s {
		switch ch {
		case '@', '4':
			buf.WriteByte('a')
		case '8':
			buf.WriteByte('b')
		case '3':
			buf.WriteByte('e')
		case '9':
			buf.WriteByte('g')
		case '1', '!':
			buf.WriteByte('i')
		case '|':
			buf.WriteByte('l')
		case '0':
			buf.WriteByte('o')
		case '$', '5':
			buf.WriteByte('s')
		case '7', '+':
			buf.WriteByte('t')
		default:
			buf.WriteRune(ch)
		}
	}
	return strings.ToLower(buf.String())
}

// hasLetters returns true if the string contains at least one ASCII letter.
func hasLetters(s string) bool {
	for _, ch := range s {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
			return true
		}
	}
	return false
}

// splitToken separates trailing digits/specials from the word base.
// e.g. "football3!" -> ("football", "3!"), "p@ssw0rd" -> ("p@ssw0rd", "")
func splitToken(tok string) (base string, suffix string) {
	end := len(tok)
	for end > 0 {
		ch := tok[end-1]
		if (ch >= '0' && ch <= '9') || ch == '!' || ch == '@' || ch == '#' ||
			ch == '$' || ch == '%' || ch == '^' || ch == '&' || ch == '*' {
			end--
		} else {
			break
		}
	}
	if end == 0 {
		return "", tok
	}
	return tok[:end], tok[end:]
}

// countLeetSubs counts how many characters differ between the lowercased original
// and the leet-normalized form, indicating leet substitutions.
func countLeetSubs(s string) int {
	lower := strings.ToLower(s)
	norm := leetNormalize(s)
	if len(lower) != len(norm) {
		return 0
	}
	count := 0
	for i := 0; i < len(lower); i++ {
		if lower[i] != norm[i] {
			count++
		}
	}
	return count
}

// ---------------------------------------------------------------------------
// charClass returns an integer class ID for a byte:
//
//	0 = uppercase, 1 = lowercase, 2 = digit, 3 = special
//
// ---------------------------------------------------------------------------
func charClass(ch byte) int {
	switch {
	case ch >= 'A' && ch <= 'Z':
		return 0
	case ch >= 'a' && ch <= 'z':
		return 1
	case ch >= '0' && ch <= '9':
		return 2
	default:
		return 3
	}
}

// countClassTransitions counts how many times the character class changes
// when reading the token left-to-right. More transitions = more interleaved
// mixing, a strong password signal.
func countClassTransitions(tok string) int {
	if len(tok) <= 1 {
		return 0
	}
	transitions := 0
	prev := charClass(tok[0])
	for i := 1; i < len(tok); i++ {
		cur := charClass(tok[i])
		if cur != prev {
			transitions++
			prev = cur
		}
	}
	return transitions
}

// isLeetDigit returns true if the digit is commonly used as a leet substitution.
func isLeetDigit(ch byte) bool {
	return ch == '0' || ch == '1' || ch == '3' || ch == '4' ||
		ch == '5' || ch == '7' || ch == '8' || ch == '9'
}

// isLetter returns true if ch is an ASCII letter.
func isLetter(ch byte) bool {
	return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
}

// isSpecialChar returns true for common password special characters.
func isSpecialChar(ch byte) bool {
	return ch == '@' || ch == '$' || ch == '!' || ch == '#' || ch == '%' ||
		ch == '^' || ch == '&' || ch == '*' || ch == '+' || ch == '|' ||
		ch == '~' || ch == '?' || ch == '.'
}

// vowelRatio computes vowels / total letters in a lowercase string.
func vowelRatio(s string) float64 {
	letters, vowels := 0, 0
	for _, ch := range s {
		if ch >= 'a' && ch <= 'z' {
			letters++
			if ch == 'a' || ch == 'e' || ch == 'i' || ch == 'o' || ch == 'u' {
				vowels++
			}
		}
	}
	if letters == 0 {
		return 0
	}
	return float64(vowels) / float64(letters)
}

// isPrefiltered returns true if the token is clearly not a password
// (email, URL, hex string, file path, pure digits, UUID, etc.)
func isPrefiltered(tok string) bool {
	// Email: has @ with a dot after it
	if atIdx := strings.IndexByte(tok, '@'); atIdx > 0 && atIdx < len(tok)-1 {
		if strings.ContainsRune(tok[atIdx+1:], '.') {
			return true
		}
	}
	// URL
	lower := strings.ToLower(tok)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(lower, "ftp://") {
		return true
	}
	// File path
	if strings.HasPrefix(tok, "/") || strings.HasPrefix(tok, "\\\\") ||
		(len(tok) > 2 && tok[1] == ':' && (tok[2] == '\\' || tok[2] == '/')) {
		return true
	}
	// Pure hex string (8+ chars, all hex) — caught by NTLM hash pattern
	if len(tok) >= 8 {
		allHex := true
		for _, ch := range tok {
			if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
				allHex = false
				break
			}
		}
		if allHex {
			return true
		}
	}
	// Pure digits
	allDigit := true
	for _, ch := range tok {
		if ch < '0' || ch > '9' {
			allDigit = false
			break
		}
	}
	if allDigit {
		return true
	}
	// UUID pattern (8-4-4-4-12 hex)
	if len(tok) == 36 && tok[8] == '-' && tok[13] == '-' && tok[18] == '-' && tok[23] == '-' {
		return true
	}
	// Filename: contains a dot followed by a 2-4 letter extension
	if dotIdx := strings.LastIndexByte(tok, '.'); dotIdx > 0 && dotIdx < len(tok)-1 {
		ext := tok[dotIdx+1:]
		if len(ext) >= 2 && len(ext) <= 4 {
			allAlpha := true
			for _, ch := range ext {
				if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
					allAlpha = false
					break
				}
			}
			if allAlpha {
				return true
			}
		}
	}
	return false
}

// passwordScore computes a confidence score (0–100) that a token is a password.
// The algorithm evaluates multiple independent structural signals without
// using any dictionary. Higher scores = higher confidence.
func passwordScore(tok string) int {
	n := len(tok)
	if n < 4 || n > 30 {
		return 0
	}
	if !hasLetters(tok) {
		return 0
	}
	if isPrefiltered(tok) {
		return 0
	}

	// --- Count character classes ---
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for i := 0; i < n; i++ {
		switch {
		case tok[i] >= 'A' && tok[i] <= 'Z':
			hasUpper = true
		case tok[i] >= 'a' && tok[i] <= 'z':
			hasLower = true
		case tok[i] >= '0' && tok[i] <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	classCount := 0
	if hasUpper {
		classCount++
	}
	if hasLower {
		classCount++
	}
	if hasDigit {
		classCount++
	}
	if hasSpecial {
		classCount++
	}

	score := 0

	// --- Signal 1: Character-class diversity (max 25) ---
	switch classCount {
	case 4:
		score += 25
	case 3:
		score += 18
	case 2:
		if hasSpecial || (hasDigit && hasUpper) {
			score += 8
		}
	}

	// --- Signal 2: Character-class transitions (max 10) ---
	transitions := countClassTransitions(tok)
	switch {
	case transitions >= 4:
		score += 10
	case transitions >= 3:
		score += 7
	case transitions >= 2:
		score += 4
	}

	// --- Signal 3: Leet-speak substitutions (max 25) ---
	// Only count leet subs in the BASE portion of the token (before trailing
	// digits/specials). This prevents "test123" from scoring leet points
	// just because the trailing digits 1,3 map to i,e in the leet table.
	base, _ := splitToken(tok)
	leetCount := countLeetSubs(base)
	switch {
	case leetCount >= 3:
		score += 25
	case leetCount >= 2:
		score += 20
	case leetCount >= 1:
		score += 12
	}

	// --- Signal 4: Trailing modifiers (max 14) ---
	_, suffix := splitToken(tok)
	if len(suffix) > 0 {
		hasTD, hasTS := false, false
		for i := 0; i < len(suffix); i++ {
			if suffix[i] >= '0' && suffix[i] <= '9' {
				hasTD = true
			} else {
				hasTS = true
			}
		}
		if hasTD {
			score += 8
		}
		if hasTS {
			score += 6
		}
	}

	// --- Signal 5: Embedded specials (max 4) ---
	if n > 2 {
		for i := 1; i < n-1; i++ {
			if isSpecialChar(tok[i]) && (isLetter(tok[i-1]) || isLetter(tok[i+1])) {
				score += 4
				break
			}
		}
	}

	// --- Signal 6: Embedded leet-like digits (max 6) ---
	// Require a letter on BOTH sides to distinguish leet (h4ck3r) from
	// normal word+digit patterns (test123, file001).
	embeddedLeet := 0
	if n > 2 {
		for i := 1; i < n-1; i++ {
			if isLeetDigit(tok[i]) && isLetter(tok[i-1]) && isLetter(tok[i+1]) {
				embeddedLeet++
			}
		}
	}
	if embeddedLeet > 0 {
		bonus := embeddedLeet * 3
		if bonus > 6 {
			bonus = 6
		}
		score += bonus
	}

	// --- Signal 7: Pronounceability after normalization (max 10) ---
	normalized := leetNormalize(tok)
	normBase, _ := splitToken(normalized)
	if len(normBase) >= 3 {
		vr := vowelRatio(normBase)
		if vr >= 0.15 && vr <= 0.6 {
			score += 10
		}
	}

	// --- Signal 8: Length in typical password range (max 5) ---
	if n >= 6 && n <= 20 {
		score += 5
	} else if n >= 4 {
		score += 2
	}

	return score
}

// passwordScoreLabel returns the finding label for a given score, or "".
func passwordScoreLabel(score int) string {
	if score >= 45 {
		return "Likely Password"
	}
	if score >= 30 {
		return "Possible Password"
	}
	return ""
}

// extractPasswordTokens splits a line into candidate tokens by whitespace
// and trims common delimiters. More robust than regex word boundaries for
// tokens containing special characters (e.g. "MICRO@dmin1").
func extractPasswordTokens(line string) []string {
	fields := strings.Fields(line)
	var tokens []string
	for _, f := range fields {
		f = strings.Trim(f, "\"'`,;:()[]{}/<>\r\n\t")
		if len(f) >= 4 && len(f) <= 30 && hasLetters(f) {
			tokens = append(tokens, f)
		}
	}
	return tokens
}

// scanForPasswords scans text for password-like tokens using heuristic scoring.
func scanForPasswords(text string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	lines := strings.Split(text, "\n")

	for lineIdx, line := range lines {
		tokens := extractPasswordTokens(line)
		for _, tok := range tokens {
			key := fmt.Sprintf("%d:%s", lineIdx, strings.ToLower(tok))
			if seen[key] {
				continue
			}
			score := passwordScore(tok)
			label := passwordScoreLabel(score)
			if label != "" {
				seen[key] = true
				findings = append(findings, Finding{
					PatternName: fmt.Sprintf("%s (score:%d)", label, score),
					Match:       tok,
					LineNum:     lineIdx + 1,
				})
			}
		}
	}
	return findings
}

// scanForSensitiveData scans text line by line against all sensitive patterns.
func scanForSensitiveData(text string) []Finding {
	var findings []Finding
	lines := strings.Split(text, "\n")
	for lineIdx, line := range lines {
		for _, p := range sensitivePatterns {
			matches := p.Pattern.FindAllString(line, 5)
			for _, m := range matches {
				display := m
				if len(display) > 120 {
					display = display[:120] + "..."
				}
				findings = append(findings, Finding{
					PatternName: p.Name,
					Match:       display,
					LineNum:     lineIdx + 1,
				})
			}
		}
	}
	// Run tiered password detection algorithm
	findings = append(findings, scanForPasswords(text)...)

	return findings
}

// scanPreviewForSecrets scans the current preview text for sensitive patterns and shows results.
func (e *Explorer) scanPreviewForSecrets() {
	text := e.previewText.Text
	if text == "" {
		e.showInfo("Scan Complete", "No text content to scan.\nPreview a file first.")
		return
	}

	findings := scanForSensitiveData(text)
	if len(findings) == 0 {
		e.showInfo("Scan Complete", "No sensitive patterns detected in preview.")
		e.logMsg("[INFO] Sensitive scan: 0 findings")
		return
	}

	// Group findings by pattern name (ordered by first occurrence)
	type group struct {
		name  string
		items []Finding
	}
	orderMap := make(map[string]int)
	var groups []group
	for _, f := range findings {
		idx, exists := orderMap[f.PatternName]
		if !exists {
			idx = len(groups)
			orderMap[f.PatternName] = idx
			groups = append(groups, group{name: f.PatternName})
		}
		groups[idx].items = append(groups[idx].items, f)
	}

	// Sort groups by name for consistent display
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].name < groups[j].name
	})

	var lines []string
	lines = append(lines, fmt.Sprintf("Found %d potential sensitive items:\n", len(findings)))
	for _, g := range groups {
		lines = append(lines, fmt.Sprintf("=== %s (%d matches) ===", g.name, len(g.items)))
		for _, item := range g.items {
			lines = append(lines, fmt.Sprintf("  Line %d: %s", item.LineNum, item.Match))
		}
		lines = append(lines, "")
	}

	resultText := strings.Join(lines, "\n")

	resultEntry := widget.NewMultiLineEntry()
	resultEntry.SetText(resultText)
	resultEntry.Wrapping = fyne.TextWrapWord

	copyBtn := widget.NewButton("Copy All to Clipboard", func() {
		e.win.Clipboard().SetContent(resultText)
		e.logMsg("[INFO] Scan results copied to clipboard.")
	})

	content := container.NewBorder(nil, copyBtn, nil, nil, resultEntry)

	d := dialog.NewCustom(
		fmt.Sprintf("Sensitive Data Scan - %d Findings", len(findings)),
		"Close",
		container.NewGridWrap(fyne.NewSize(700, 400), content),
		e.win,
	)
	d.Resize(fyne.NewSize(750, 480))
	d.Show()

	e.logMsg(fmt.Sprintf("[INFO] Sensitive scan: %d patterns matched across %d categories", len(findings), len(groups)))
}
