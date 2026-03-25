package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// loadKirbiAsCCache reads a .kirbi file (KRB_CRED ASN.1 format, e.g. from
// Mimikatz / Rubeus) and converts it into a gokrb5 CCache so that it can be
// fed into client.NewFromCCache the same way a standard ccache file would be.
func loadKirbiAsCCache(kirbiPath string) (*credentials.CCache, error) {
	data, err := os.ReadFile(kirbiPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read kirbi file: %w", err)
	}
	return kirbiBytesToCCache(data)
}

// kirbiBytesToCCache converts raw KRB_CRED bytes into a gokrb5 CCache.
func kirbiBytesToCCache(data []byte) (*credentials.CCache, error) {
	krbCred, encPart, err := parseKirbiRaw(data)
	if err != nil {
		return nil, err
	}
	return buildCCacheFromKirbi(krbCred, encPart)
}

// parseKirbiRaw unmarshals raw KRB_CRED bytes and decrypts the EncPart.
func parseKirbiRaw(data []byte) (*messages.KRBCred, *messages.EncKrbCredPart, error) {
	var krbCred messages.KRBCred
	if err := krbCred.Unmarshal(data); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal KRB_CRED: %w", err)
	}

	if len(krbCred.Tickets) == 0 {
		return nil, nil, fmt.Errorf("kirbi contains no tickets")
	}

	// Decrypt the EncPart.  Mimikatz / Rubeus .kirbi exports use etype 0
	// (null encryption) so the Cipher field is the raw ASN.1 EncKrbCredPart.
	var encPart messages.EncKrbCredPart
	if krbCred.EncPart.EType == 0 {
		if err := encPart.Unmarshal(krbCred.EncPart.Cipher); err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal EncKrbCredPart: %w", err)
		}
	} else {
		return nil, nil, fmt.Errorf(
			"kirbi EncPart uses encryption type %d; only unencrypted (etype 0) .kirbi files are supported",
			krbCred.EncPart.EType,
		)
	}

	if len(encPart.TicketInfo) == 0 {
		return nil, nil, fmt.Errorf("kirbi contains no ticket info entries")
	}

	return &krbCred, &encPart, nil
}

// buildCCacheFromKirbi converts parsed KRB_CRED data into ccache binary and unmarshals it.
func buildCCacheFromKirbi(krbCred *messages.KRBCred, encPart *messages.EncKrbCredPart) (*credentials.CCache, error) {
	// Check for all-zero session key — indicates a tgtdeleg ticket where the
	// real session key is unknown.  These tickets cannot be used for TGS
	// exchanges because the KDC will reject the authenticator.
	if len(encPart.TicketInfo) > 0 {
		key := encPart.TicketInfo[0].Key
		allZero := true
		for _, b := range key.KeyValue {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero && len(key.KeyValue) > 0 {
			return nil, fmt.Errorf(
				"session key is all zeros (key type %d, %d bytes) — this is typically a tgtdeleg ticket where the real session key is unknown. "+
					"Use 'Rubeus asktgt' with a password/hash, or 'Rubeus dump /service:krbtgt' from an elevated context to get a ticket with the correct session key",
				key.KeyType, len(key.KeyValue),
			)
		}
	}
	ccBuf := new(bytes.Buffer)

	// --- ccache v4 header ---
	ccBuf.WriteByte(0x05)  // file tag (always 5)
	ccBuf.WriteByte(0x04)  // version 4
	ccWriteInt16(ccBuf, 0) // header length 0 (no header fields)

	// Use the first ticket info entry to determine the default principal.
	info0 := encPart.TicketInfo[0]
	ccWritePrincipal(ccBuf, info0.PName, info0.PRealm)

	// Detect whether any entry is a TGT (server = krbtgt/REALM).
	// If not, this is a TGS-only kirbi (service ticket) and we need to
	// synthesize a dummy TGT so that gokrb5's NewFromCCache succeeds.
	hasTGT := false
	n := len(encPart.TicketInfo)
	if len(krbCred.Tickets) < n {
		n = len(krbCred.Tickets)
	}
	for i := 0; i < n; i++ {
		if isKrbtgt(encPart.TicketInfo[i].SName) {
			hasTGT = true
			break
		}
	}
	if !hasTGT {
		if err := writeDummyTGTEntry(ccBuf, info0); err != nil {
			return nil, fmt.Errorf("failed to write synthetic TGT: %w", err)
		}
	}

	// Write each credential entry.
	for i := 0; i < n; i++ {
		info := encPart.TicketInfo[i]
		tkt := krbCred.Tickets[i]

		tktBytes, err := tkt.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ticket %d: %w", i, err)
		}

		// Client principal
		ccWritePrincipal(ccBuf, info.PName, info.PRealm)
		// Server principal
		ccWritePrincipal(ccBuf, info.SName, info.SRealm)
		// Session key
		ccWriteInt16(ccBuf, int16(info.Key.KeyType))
		ccWriteData(ccBuf, info.Key.KeyValue)
		// Timestamps — AuthTime is optional in KRB-CRED; Rubeus often
		// omits it.  If absent, fall back to StartTime so that gokrb5's
		// session validity check (endTime-authTime)/6 produces a sane
		// value and doesn't trigger an unnecessary TGT renewal.
		authTime := info.AuthTime
		if authTime.IsZero() && !info.StartTime.IsZero() {
			authTime = info.StartTime
		}
		ccWriteTimestamp(ccBuf, authTime)
		ccWriteTimestamp(ccBuf, info.StartTime)
		ccWriteTimestamp(ccBuf, info.EndTime)
		ccWriteTimestamp(ccBuf, info.RenewTill)
		// is_skey
		ccBuf.WriteByte(0)
		// Ticket flags (4 bytes)
		ccWriteFlags(ccBuf, info.Flags)
		// Addresses count (0)
		ccWriteInt32(ccBuf, 0)
		// AuthData count (0)
		ccWriteInt32(ccBuf, 0)
		// Ticket data
		ccWriteData(ccBuf, tktBytes)
		// Second ticket (empty)
		ccWriteData(ccBuf, nil)
	}

	ccBytes := ccBuf.Bytes()

	var ccache credentials.CCache
	if err := ccache.Unmarshal(ccBytes); err != nil {
		return nil, fmt.Errorf("failed to build ccache from kirbi data: %w", err)
	}

	// Verify the session key survived the round-trip.
	// When a dummy TGT was injected, it occupies Credentials[0], so we need
	// to find the credential that corresponds to the first real ticket.
	origKey := encPart.TicketInfo[0].Key
	offset := 0
	if !hasTGT {
		offset = 1 // skip the synthetic dummy TGT at index 0
	}
	if offset < len(ccache.Credentials) {
		rtKey := ccache.Credentials[offset].Key
		if origKey.KeyType != rtKey.KeyType ||
			len(origKey.KeyValue) != len(rtKey.KeyValue) ||
			!bytes.Equal(origKey.KeyValue, rtKey.KeyValue) {
			return nil, fmt.Errorf(
				"session key corrupted during ccache round-trip: kirbi(type=%d len=%d) ccache(type=%d len=%d)",
				origKey.KeyType, len(origKey.KeyValue),
				rtKey.KeyType, len(rtKey.KeyValue),
			)
		}
	}

	return &ccache, nil
}

// parseKirbiBase64 decodes base64-encoded kirbi data and returns a human-readable
// summary of the ticket details.  Returns an error if decoding or parsing fails.
func parseKirbiBase64(b64 string) (string, error) {
	// Strip whitespace (users often paste with line breaks)
	b64 = strings.Join(strings.Fields(b64), "")
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %w", err)
	}
	_, encPart, err := parseKirbiRaw(raw)
	if err != nil {
		return "", err
	}
	return formatTicketDetails(encPart), nil
}

// saveKirbiBase64ToTempFile decodes the base64 kirbi and writes it to a
// temporary file, returning the path.  The caller should clean up the file.
func saveKirbiBase64ToTempFile(b64 string) (string, error) {
	b64 = strings.Join(strings.Fields(b64), "")
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %w", err)
	}
	// Validate it parses before writing
	if _, _, err := parseKirbiRaw(raw); err != nil {
		return "", err
	}
	f, err := os.CreateTemp("", "eyebrowse-*.kirbi")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("failed to write temp kirbi: %w", err)
	}
	f.Close()
	return f.Name(), nil
}

// formatTicketDetails produces a human-readable summary of ticket information.
func formatTicketDetails(encPart *messages.EncKrbCredPart) string {
	var sb strings.Builder
	for i, info := range encPart.TicketInfo {
		if i > 0 {
			sb.WriteString("\n---\n")
		}
		ticketType := "TGS (Service Ticket)"
		if isKrbtgt(info.SName) {
			ticketType = "TGT (Ticket Granting Ticket)"
		}
		sb.WriteString(fmt.Sprintf("Ticket #%d  [%s]\n", i+1, ticketType))
		sb.WriteString(fmt.Sprintf("  Client:     %s@%s\n", info.PName.PrincipalNameString(), info.PRealm))
		sb.WriteString(fmt.Sprintf("  Service:    %s@%s\n", info.SName.PrincipalNameString(), info.SRealm))
		sb.WriteString(fmt.Sprintf("  Key Type:   %d  (%s)\n", info.Key.KeyType, keyTypeName(info.Key.KeyType)))
		sb.WriteString(fmt.Sprintf("  Key Length: %d bytes\n", len(info.Key.KeyValue)))
		allZero := true
		for _, b := range info.Key.KeyValue {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero && len(info.Key.KeyValue) > 0 {
			sb.WriteString("  ** WARNING: Session key is ALL ZEROS (tgtdeleg ticket — cannot be used for TGS) **\n")
		}
		if !info.AuthTime.IsZero() {
			sb.WriteString(fmt.Sprintf("  Auth Time:  %s\n", info.AuthTime.Format(time.RFC3339)))
		}
		if !info.StartTime.IsZero() {
			sb.WriteString(fmt.Sprintf("  Start Time: %s\n", info.StartTime.Format(time.RFC3339)))
		}
		if !info.EndTime.IsZero() {
			sb.WriteString(fmt.Sprintf("  End Time:   %s\n", info.EndTime.Format(time.RFC3339)))
			if time.Now().After(info.EndTime) {
				sb.WriteString("  ** EXPIRED **\n")
			}
		}
		if !info.RenewTill.IsZero() {
			sb.WriteString(fmt.Sprintf("  Renew Till: %s\n", info.RenewTill.Format(time.RFC3339)))
		}
	}
	return sb.String()
}

// isKrbtgt returns true if the principal name represents a krbtgt service (TGT).
func isKrbtgt(pn types.PrincipalName) bool {
	return len(pn.NameString) >= 1 && strings.EqualFold(pn.NameString[0], "krbtgt")
}

// writeDummyTGTEntry writes a synthetic krbtgt/REALM credential entry into the
// ccache buffer.  This is needed when the kirbi only contains a service ticket
// (TGS) because gokrb5's NewFromCCache requires a TGT to be present.
// The dummy TGT is never sent to the KDC — it only satisfies the loader; the
// real service ticket is served from the client's cache.
func writeDummyTGTEntry(buf *bytes.Buffer, info messages.KrbCredInfo) error {
	realm := info.PRealm
	krbtgtSPN := types.PrincipalName{
		NameType:   2, // KRB_NT_SRV_INST
		NameString: []string{"krbtgt", realm},
	}

	// Build a minimal valid ASN.1 Ticket so gokrb5 can unmarshal it.
	dummyTicket := messages.Ticket{
		TktVNO: 5,
		Realm:  realm,
		SName:  krbtgtSPN,
		EncPart: types.EncryptedData{
			EType:  int32(info.Key.KeyType),
			KVNO:   1,
			Cipher: make([]byte, 32),
		},
	}
	dummyTktBytes, err := dummyTicket.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal dummy TGT: %w", err)
	}

	// Client principal
	ccWritePrincipal(buf, info.PName, realm)
	// Server principal (krbtgt/REALM)
	ccWritePrincipal(buf, krbtgtSPN, realm)
	// Session key — use the same type but a dummy value
	ccWriteInt16(buf, int16(info.Key.KeyType))
	dummyKey := make([]byte, len(info.Key.KeyValue))
	for i := range dummyKey {
		dummyKey[i] = 0xFF
	}
	ccWriteData(buf, dummyKey)
	// Timestamps — copy from the real ticket
	authTime := info.AuthTime
	if authTime.IsZero() && !info.StartTime.IsZero() {
		authTime = info.StartTime
	}
	ccWriteTimestamp(buf, authTime)
	ccWriteTimestamp(buf, info.StartTime)
	ccWriteTimestamp(buf, info.EndTime)
	ccWriteTimestamp(buf, info.RenewTill)
	// is_skey
	buf.WriteByte(0)
	// Ticket flags (4 bytes) — use the real ticket's flags
	ccWriteFlags(buf, info.Flags)
	// Addresses count (0)
	ccWriteInt32(buf, 0)
	// AuthData count (0)
	ccWriteInt32(buf, 0)
	// Ticket data
	ccWriteData(buf, dummyTktBytes)
	// Second ticket (empty)
	ccWriteData(buf, nil)
	return nil
}

// keyTypeName returns a human-readable name for a Kerberos encryption type.
func keyTypeName(kt int32) string {
	switch kt {
	case 1:
		return "DES-CBC-CRC"
	case 3:
		return "DES-CBC-MD5"
	case 17:
		return "AES128-CTS-HMAC-SHA1"
	case 18:
		return "AES256-CTS-HMAC-SHA1"
	case 23:
		return "RC4-HMAC"
	case 24:
		return "RC4-HMAC-EXP"
	default:
		return "unknown"
	}
}

// --- ccache binary format helpers (big-endian) ---

func ccWritePrincipal(buf *bytes.Buffer, pn types.PrincipalName, realm string) {
	ccWriteInt32(buf, pn.NameType)
	ccWriteInt32(buf, int32(len(pn.NameString)))
	ccWriteInt32(buf, int32(len(realm)))
	buf.WriteString(realm)
	for _, s := range pn.NameString {
		ccWriteInt32(buf, int32(len(s)))
		buf.WriteString(s)
	}
}

func ccWriteData(buf *bytes.Buffer, data []byte) {
	ccWriteInt32(buf, int32(len(data)))
	if len(data) > 0 {
		buf.Write(data)
	}
}

func ccWriteTimestamp(buf *bytes.Buffer, t time.Time) {
	if t.IsZero() {
		ccWriteInt32(buf, 0)
	} else {
		ccWriteInt32(buf, int32(t.Unix()))
	}
}

func ccWriteFlags(buf *bytes.Buffer, flags asn1.BitString) {
	if len(flags.Bytes) >= 4 {
		buf.Write(flags.Bytes[:4])
	} else {
		padded := make([]byte, 4)
		copy(padded, flags.Bytes)
		buf.Write(padded)
	}
}

func ccWriteInt16(buf *bytes.Buffer, v int16) {
	_ = binary.Write(buf, binary.BigEndian, v)
}

func ccWriteInt32(buf *bytes.Buffer, v int32) {
	_ = binary.Write(buf, binary.BigEndian, v)
}
