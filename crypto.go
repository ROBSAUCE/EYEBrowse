package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"os"
	"strings"
)

const encPrefix = "enc:"

// deriveKey creates a 32-byte AES-256 key from machine-specific data.
// Uses hostname + app identifier so encrypted prefs are not portable between machines.
func deriveKey() []byte {
	hostname, _ := os.Hostname()
	seed := "EyeBrowse-v1:" + hostname + ":com.eyebrowse.smbexplorer"
	hash := sha256.Sum256([]byte(seed))
	return hash[:]
}

// encryptString encrypts a plaintext string using AES-256-GCM.
// Returns a prefixed base64 string: "enc:<base64(nonce+ciphertext)>"
func encryptString(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	key := deriveKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptString decrypts an AES-256-GCM encrypted string.
// If the string lacks the "enc:" prefix, it is returned as-is (backward compatible
// with plaintext values saved before encryption was added).
func decryptString(encrypted string) string {
	if encrypted == "" || !strings.HasPrefix(encrypted, encPrefix) {
		return encrypted // plaintext or empty — backward compatible
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encrypted, encPrefix))
	if err != nil {
		return encrypted
	}
	key := deriveKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return encrypted
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return encrypted
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return encrypted
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return encrypted // decryption failed — return as-is
	}
	return string(plaintext)
}
