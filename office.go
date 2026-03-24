package main

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ledongthuc/pdf"
)

// isOfficeExt returns true if the extension is a supported office/PDF format.
func isOfficeExt(ext string) bool {
	switch ext {
	case ".pdf", ".docx", ".xlsx", ".pptx":
		return true
	}
	return false
}

// extractTextFromFile extracts plain text from supported office/PDF file types.
func extractTextFromFile(localPath string) (string, error) {
	ext := strings.ToLower(filepath.Ext(localPath))
	switch ext {
	case ".pdf":
		return extractPDF(localPath)
	case ".docx":
		return extractDOCX(localPath)
	case ".xlsx":
		return extractXLSX(localPath)
	case ".pptx":
		return extractPPTX(localPath)
	default:
		return "", fmt.Errorf("unsupported format: %s", ext)
	}
}

// extractPDF extracts text from a PDF file using page-by-page plain text extraction.
func extractPDF(path string) (string, error) {
	f, r, err := pdf.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open PDF: %w", err)
	}
	defer f.Close()

	var buf strings.Builder
	numPages := r.NumPage()
	for i := 1; i <= numPages; i++ {
		p := r.Page(i)
		if p.V.IsNull() {
			continue
		}
		rows, err := p.GetTextByRow()
		if err != nil {
			continue
		}
		for _, row := range rows {
			for j, word := range row.Content {
				if j > 0 {
					// Insert space between text objects to preserve word boundaries
					buf.WriteString(" ")
				}
				buf.WriteString(word.S)
			}
			buf.WriteString("\n")
		}
		buf.WriteString("\n")
		// Limit extraction to ~512KB of text
		if buf.Len() > 512*1024 {
			break
		}
	}
	return buf.String(), nil
}

// extractDOCX extracts text from a .docx file (Office Open XML Word document).
func extractDOCX(path string) (string, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return "", fmt.Errorf("failed to open DOCX: %w", err)
	}
	defer r.Close()

	var buf strings.Builder
	// Extract from main document, headers, footers
	targets := []string{"word/document.xml"}
	for _, f := range r.File {
		if strings.HasPrefix(f.Name, "word/header") || strings.HasPrefix(f.Name, "word/footer") {
			targets = append(targets, f.Name)
		}
	}

	for _, target := range targets {
		for _, f := range r.File {
			if f.Name != target {
				continue
			}
			text, err := extractXMLText(f, "t", "p")
			if err == nil {
				buf.WriteString(text)
			}
		}
	}
	return buf.String(), nil
}

// extractXLSX extracts text from a .xlsx file (Office Open XML Spreadsheet).
func extractXLSX(path string) (string, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return "", fmt.Errorf("failed to open XLSX: %w", err)
	}
	defer r.Close()

	// First, collect shared strings
	var sharedStrings []string
	for _, f := range r.File {
		if f.Name == "xl/sharedStrings.xml" {
			rc, err := f.Open()
			if err != nil {
				break
			}
			decoder := xml.NewDecoder(rc)
			var currentSI strings.Builder
			inSI := false
			for {
				tok, err := decoder.Token()
				if err != nil {
					break
				}
				switch t := tok.(type) {
				case xml.StartElement:
					if t.Name.Local == "si" {
						inSI = true
						currentSI.Reset()
					}
					if t.Name.Local == "t" && inSI {
						var text string
						if err := decoder.DecodeElement(&text, &t); err == nil {
							currentSI.WriteString(text)
						}
					}
				case xml.EndElement:
					if t.Name.Local == "si" {
						sharedStrings = append(sharedStrings, currentSI.String())
						inSI = false
					}
				}
			}
			rc.Close()
		}
	}

	// Then read sheet contents — extract inline strings and cell values
	var buf strings.Builder
	for _, f := range r.File {
		if !strings.HasPrefix(f.Name, "xl/worksheets/sheet") || !strings.HasSuffix(f.Name, ".xml") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		decoder := xml.NewDecoder(rc)
		for {
			tok, err := decoder.Token()
			if err != nil {
				break
			}
			if se, ok := tok.(xml.StartElement); ok {
				if se.Name.Local == "v" || se.Name.Local == "t" {
					var text string
					if err := decoder.DecodeElement(&text, &se); err == nil && text != "" {
						buf.WriteString(text)
						buf.WriteString("\t")
					}
				}
				if se.Name.Local == "row" {
					buf.WriteString("\n")
				}
			}
		}
		buf.WriteString("\n")
		rc.Close()
	}

	// Append shared strings (these contain the actual cell text values)
	if len(sharedStrings) > 0 {
		buf.WriteString("\n--- Shared Strings ---\n")
		for _, s := range sharedStrings {
			buf.WriteString(s)
			buf.WriteString("\n")
		}
	}
	return buf.String(), nil
}

// extractPPTX extracts text from a .pptx file (Office Open XML Presentation).
func extractPPTX(path string) (string, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return "", fmt.Errorf("failed to open PPTX: %w", err)
	}
	defer r.Close()

	var buf strings.Builder
	slideNum := 0
	for _, f := range r.File {
		if !strings.HasPrefix(f.Name, "ppt/slides/slide") || !strings.HasSuffix(f.Name, ".xml") {
			continue
		}
		slideNum++
		buf.WriteString(fmt.Sprintf("--- Slide %d ---\n", slideNum))
		text, err := extractXMLText(f, "t", "p")
		if err == nil {
			buf.WriteString(text)
		}
		buf.WriteString("\n")
	}
	// Also extract from notes
	for _, f := range r.File {
		if strings.HasPrefix(f.Name, "ppt/notesSlides/") && strings.HasSuffix(f.Name, ".xml") {
			text, err := extractXMLText(f, "t", "p")
			if err == nil && strings.TrimSpace(text) != "" {
				buf.WriteString("--- Speaker Notes ---\n")
				buf.WriteString(text)
				buf.WriteString("\n")
			}
		}
	}
	return buf.String(), nil
}

// extractXMLText is a helper that reads a zip file entry, parsing XML and extracting
// text from elements with the given textTag local name. newlineTag causes a newline.
func extractXMLText(f *zip.File, textTag, newlineTag string) (string, error) {
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()

	var buf strings.Builder
	decoder := xml.NewDecoder(rc)
	// Limit read to 512KB
	decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}

	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == textTag {
				var text string
				if err := decoder.DecodeElement(&text, &t); err == nil {
					buf.WriteString(text)
				}
			}
		case xml.EndElement:
			if t.Name.Local == newlineTag {
				buf.WriteString("\n")
			}
		}
	}
	return buf.String(), nil
}

// extractTextForScan extracts text from a file for scanning purposes.
// Supports plain text files, office documents, and PDFs.
// Returns empty string if the file type is unsupported or extraction fails.
func extractTextForScan(localPath string) string {
	ext := strings.ToLower(filepath.Ext(localPath))

	// Office/PDF formats
	if isOfficeExt(ext) {
		text, err := extractTextFromFile(localPath)
		if err != nil {
			return ""
		}
		return text
	}

	// Known text formats — read directly
	if isKnownTextExt(ext) {
		return readTextFile(localPath)
	}

	// Unknown extension — heuristic binary check on first 2KB
	data := readTextFile(localPath)
	if len(data) == 0 {
		return ""
	}
	sample := data
	if len(sample) > 2048 {
		sample = sample[:2048]
	}
	for _, b := range []byte(sample) {
		if b < 32 && b != 9 && b != 10 && b != 13 {
			return "" // binary file
		}
	}
	return data
}

// readTextFile reads a file as text, limited to 512KB.
func readTextFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	buf := make([]byte, 512*1024)
	n, _ := f.Read(buf)
	return string(buf[:n])
}
