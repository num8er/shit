package crypto

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
)

type PSKManager struct {
	mu       sync.RWMutex
	keys     map[string]string
	filePath string
}

func NewPSKManager(filePath string) *PSKManager {
	return &PSKManager{
		keys:     make(map[string]string),
		filePath: filePath,
	}
}

func (m *PSKManager) LoadKeys() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	file, err := os.Open(m.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) == 2 {
			keyID := parts[0]
			key := strings.Trim(parts[1], "\"")
			m.keys[keyID] = key
		}
	}

	return scanner.Err()
}

func (m *PSKManager) SaveKeys() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	file, err := os.Create(m.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for keyID, key := range m.keys {
		fmt.Fprintf(writer, "%s \"%s\"\n", keyID, key)
	}

	return writer.Flush()
}

func (m *PSKManager) GetKey(keyID string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key, exists := m.keys[keyID]
	return key, exists
}

func (m *PSKManager) SetKey(keyID, key string) error {
	m.mu.Lock()
	m.keys[keyID] = key
	m.mu.Unlock()
	return m.SaveKeys()
}

func GeneratePSK() (string, error) {
	bytes := make([]byte, 64)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func HashPSK(psk string) string {
	hash := sha256.Sum256([]byte(psk))
	return hex.EncodeToString(hash[:])
}

func ValidatePSK(psk string) bool {
	return len(psk) == 128
}

// EncryptMessage encrypts data using AES-GCM with the PSK as key and returns base64-encoded result
func EncryptMessage(psk string, plaintext []byte) ([]byte, error) {
	keyHash := sha256.Sum256([]byte(psk))
	key := keyHash[:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	return []byte(encoded), nil
}

// DecryptMessage decrypts base64-encoded data using AES-GCM with the PSK as key
func DecryptMessage(psk string, encodedCiphertext []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(string(encodedCiphertext))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	keyHash := sha256.Sum256([]byte(psk))
	key := keyHash[:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
