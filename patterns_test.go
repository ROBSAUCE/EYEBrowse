package main

import (
	"fmt"
	"testing"
)

func TestPasswordScoring(t *testing.T) {
	// Passwords that SHOULD be detected (score >= 30)
	shouldDetect := []struct {
		tok       string
		minScore  int
		expectHit bool
	}{
		// The user's specific example
		{"MICRO@dmin1", 45, true},
		// Classic leet-speak
		{"P@ssw0rd", 45, true},
		{"p@$$w0rd", 45, true},
		{"h4ck3r", 30, true},
		// Capitalized word + digits + special
		{"Welcome1!", 45, true},
		{"Company2024#", 45, true},
		{"Summer2024!", 45, true},
		{"January2024!", 45, true},
		{"Tr0ub4dor&3", 45, true},
		// Leet-speak IT words
		{"@dmin", 30, true},
		{"t3st!", 30, true},
		{"$erver1", 30, true},
		{"r00t!", 30, true},
		// Mixed case + digits
		{"Server2019", 30, true},
		{"Windows10!", 45, true},
		// Multi-leet
		{"0Ptiv", 30, true},
		{"n3tw0rk!", 45, true},
		// Real-world password patterns
		{"L3tM3!n", 45, true},
		{"Ch@ng3Me!", 45, true},
		{"M@sterK3y1", 45, true},
		{"$uP3rUs3r", 45, true},
		{"Pr!nc3ss99", 45, true},
		{"G0ld3nK3y!", 45, true},
		{"Acc3$$2024", 45, true},
		{"S3cur!ty1", 45, true},
		{"F!r3w@ll1", 45, true},
	}

	// Normal text that should NOT be detected (score < 30)
	shouldNotDetect := []struct {
		tok      string
		maxScore int
	}{
		// Plain English words
		{"document", 29},
		{"password", 29},
		{"server", 29},
		{"admin", 29},
		{"network", 29},
		{"README", 29},
		{"config", 29},
		{"system", 29},
		{"security", 29},
		{"firewall", 29},
		{"database", 29},
		{"username", 29},
		{"management", 29},
		// Technical terms
		{"localhost", 29},
		{"ethernet", 29},
		{"protocol", 29},
		{"interface", 29},
		// Simple words with digits (not password-like enough)
		{"test123", 29},
		{"file001", 29},
		{"user42", 29},
		{"version2", 29},
		// Common filenames / identifiers
		{"index.html", 29},
		{"setup.exe", 29},
		{"config.yaml", 29},
		// Abbreviations / acronyms
		{"HTTP", 29},
		{"JSON", 29},
		{"NTLM", 29},
		{"TCP", 29},
		// CamelCase code identifiers
		{"toString", 29},
		{"fileName", 29},
		{"getUserName", 29},
	}

	fmt.Println("=== Passwords that SHOULD be detected ===")
	for _, tc := range shouldDetect {
		score := passwordScore(tc.tok)
		label := passwordScoreLabel(score)
		status := "✓"
		if score < tc.minScore {
			status = "✗ MISS"
			t.Errorf("MISS: %q scored %d, expected >= %d", tc.tok, score, tc.minScore)
		}
		fmt.Printf("  %s %-20s score=%3d  %s\n", status, tc.tok, score, label)
	}

	fmt.Println("\n=== Normal text that should NOT be detected ===")
	for _, tc := range shouldNotDetect {
		score := passwordScore(tc.tok)
		label := passwordScoreLabel(score)
		status := "✓"
		if score > tc.maxScore {
			status = "✗ FP"
			t.Errorf("FALSE POSITIVE: %q scored %d, expected <= %d (%s)", tc.tok, score, tc.maxScore, label)
		}
		fmt.Printf("  %s %-20s score=%3d  %s\n", status, tc.tok, score, label)
	}
}
