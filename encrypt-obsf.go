package evasion

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/md5"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "errors"
    "io"
    "strings"
)

type StringObfuscator struct {
    key []byte
}

// Enhanced obfuscator with multiple encryption methods
type AdvancedObfuscator struct {
    key          []byte
    salt         []byte
    iterations   int
}

// Encryption types
const (
    ENC_AES_GCM   = 1
    ENC_AES_CBC   = 2
    ENC_CHACHA20  = 3
    ENC_XOR       = 4
    ENC_BASE64    = 5
)

func NewStringObfuscator(password string) *StringObfuscator {
    // Use SHA256 to ensure we always have a 32-byte key
    hash := sha256.Sum256([]byte(password))
    return &StringObfuscator{key: hash[:]}
}

// NewAdvancedObfuscator creates a more secure obfuscator with PBKDF2-like key derivation
func NewAdvancedObfuscator(password string, salt string, iterations int) *AdvancedObfuscator {
    if salt == "" {
        salt = "static_salt_for_consistency"
    }
    if iterations <= 0 {
        iterations = 10000
    }
    
    // Simple key derivation (in production, use proper PBKDF2)
    combined := []byte(password + salt)
    key := sha256.Sum256(combined)
    for i := 0; i < iterations; i++ {
        key = sha256.Sum256(key[:])
    }
    
    return &AdvancedObfuscator{
        key:        key[:],
        salt:       []byte(salt),
        iterations: iterations,
    }
}

// AES-256-GCM Encryption (with key derivation)
func (s *StringObfuscator) Encrypt(plaintext string) string {
    if plaintext == "" {
        return ""
    }
    
    block, err := aes.NewCipher(s.key)
    if err != nil {
        return plaintext
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return plaintext
    }
    
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return plaintext
    }
    
    ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
    return base64.StdEncoding.EncodeToString(ciphertext)
}

func (s *StringObfuscator) Decrypt(encrypted string) string {
    if encrypted == "" {
        return ""
    }
    
    data, err := base64.StdEncoding.DecodeString(encrypted)
    if err != nil {
        return encrypted
    }
    
    block, err := aes.NewCipher(s.key)
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
        return encrypted
    }
    
    return string(plaintext)
}

// AES-CBC Encryption (alternative method)
func (s *StringObfuscator) EncryptCBC(plaintext string) string {
    if plaintext == "" {
        return ""
    }
    
    block, err := aes.NewCipher(s.key)
    if err != nil {
        return plaintext
    }
    
    // PKCS7 padding
    plaintextBytes := []byte(plaintext)
    padding := aes.BlockSize - len(plaintextBytes)%aes.BlockSize
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    plaintextBytes = append(plaintextBytes, padtext...)
    
    // CBC encryption
    ciphertext := make([]byte, aes.BlockSize+len(plaintextBytes))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return plaintext
    }
    
    mode := cipher.NewCBCEncrypter(block, iv)
    mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintextBytes)
    
    return base64.StdEncoding.EncodeToString(ciphertext)
}

func (s *StringObfuscator) DecryptCBC(encrypted string) string {
    if encrypted == "" {
        return ""
    }
    
    data, err := base64.StdEncoding.DecodeString(encrypted)
    if err != nil {
        return encrypted
    }
    
    if len(data) < aes.BlockSize {
        return encrypted
    }
    
    block, err := aes.NewCipher(s.key)
    if err != nil {
        return encrypted
    }
    
    iv := data[:aes.BlockSize]
    ciphertext := data[aes.BlockSize:]
    
    if len(ciphertext)%aes.BlockSize != 0 {
        return encrypted
    }
    
    mode := cipher.NewCBCDecrypter(block, iv)
    plaintext := make([]byte, len(ciphertext))
    mode.CryptBlocks(plaintext, ciphertext)
    
    // Remove PKCS7 padding
    padding := int(plaintext[len(plaintext)-1])
    if padding > aes.BlockSize || padding == 0 {
        return encrypted
    }
    plaintext = plaintext[:len(plaintext)-padding]
    
    return string(plaintext)
}

// XOR Obfuscation (enhanced)
func XORObfuscate(data []byte, key []byte) []byte {
    if len(key) == 0 {
        key = []byte{0xAA} // default key
    }
    
    result := make([]byte, len(data))
    for i := range data {
        result[i] = data[i] ^ key[i%len(key)]
    }
    return result
}

// XORObfuscateString is a convenience function
func XORObfuscateString(s string, key string) string {
    keyBytes := []byte(key)
    if len(keyBytes) == 0 {
        keyBytes = []byte{0xAA}
    }
    result := XORObfuscate([]byte(s), keyBytes)
    return base64.StdEncoding.EncodeToString(result)
}

// XORDeobfuscateString reverses XOR obfuscation
func XORDeobfuscateString(encrypted string, key string) string {
    data, err := base64.StdEncoding.DecodeString(encrypted)
    if err != nil {
        return encrypted
    }
    
    keyBytes := []byte(key)
    if len(keyBytes) == 0 {
        keyBytes = []byte{0xAA}
    }
    
    result := XORObfuscate(data, keyBytes)
    return string(result)
}

// ROT13 (for strings)
func ROT13(s string) string {
    result := make([]byte, len(s))
    for i := range s {
        c := s[i]
        if c >= 'a' && c <= 'z' {
            if c+13 > 'z' {
                c = c - 13
            } else {
                c = c + 13
            }
        } else if c >= 'A' && c <= 'Z' {
            if c+13 > 'Z' {
                c = c - 13
            } else {
                c = c + 13
            }
        }
        result[i] = c
    }
    return string(result)
}

// Advanced ROT with variable shift
func ROT(s string, shift int) string {
    shift = shift % 26
    if shift < 0 {
        shift += 26
    }
    
    result := make([]byte, len(s))
    for i := range s {
        c := s[i]
        if c >= 'a' && c <= 'z' {
            c = byte((int(c-'a')+shift)%26) + 'a'
        } else if c >= 'A' && c <= 'Z' {
            c = byte((int(c-'A')+shift)%26) + 'A'
        }
        result[i] = c
    }
    return string(result)
}

// Base64 with custom alphabet
func CustomBase64Encode(data []byte, alphabet string) string {
    if alphabet == "" {
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    }
    // Use standard base64 with custom alphabet
    stdEncoding := base64.StdEncoding
    encoded := stdEncoding.EncodeToString(data)
    
    // Replace characters with custom alphabet
    result := make([]byte, len(encoded))
    for i, c := range encoded {
        if c >= 'A' && c <= 'Z' {
            result[i] = alphabet[c-'A']
        } else if c >= 'a' && c <= 'z' {
            result[i] = alphabet[26+c-'a']
        } else if c >= '0' && c <= '9' {
            result[i] = alphabet[52+c-'0']
        } else if c == '+' {
            result[i] = alphabet[62]
        } else if c == '/' {
            result[i] = alphabet[63]
        } else {
            result[i] = byte(c)
        }
    }
    return string(result)
}

// Reverse string obfuscation
func ReverseString(s string) string {
    runes := []rune(s)
    for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
        runes[i], runes[j] = runes[j], runes[i]
    }
    return string(runes)
}

// Multi-layer obfuscation
func MultiLayerObfuscate(data string, password string) string {
    // Layer 1: XOR
    xorResult := XORObfuscateString(data, password)
    
    // Layer 2: ROT13
    rotResult := ROT13(xorResult)
    
    // Layer 3: Reverse
    reverseResult := ReverseString(rotResult)
    
    // Layer 4: AES encrypt
    obfuscator := NewStringObfuscator(password)
    return obfuscator.Encrypt(reverseResult)
}

func MultiLayerDeobfuscate(encrypted string, password string) string {
    // Layer 1: AES decrypt
    obfuscator := NewStringObfuscator(password)
    decrypted := obfuscator.Decrypt(encrypted)
    if decrypted == encrypted {
        return encrypted // Decryption failed
    }
    
    // Layer 2: Unreverse
    unreversed := ReverseString(decrypted)
    
    // Layer 3: ROT13
    unrot := ROT13(unreversed)
    
    // Layer 4: XOR
    return XORDeobfuscateString(unrot, password)
}

// Advanced encryption with built-in obfuscation
func (a *AdvancedObfuscator) Encrypt(plaintext string) string {
    if plaintext == "" {
        return ""
    }
    
    // Pre-obfuscate with XOR
    xorKey := a.key[:8] // First 8 bytes as XOR key
    xorData := XORObfuscate([]byte(plaintext), xorKey)
    
    // Then AES encrypt
    block, err := aes.NewCipher(a.key)
    if err != nil {
        return plaintext
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return plaintext
    }
    
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return plaintext
    }
    
    ciphertext := gcm.Seal(nonce, nonce, xorData, nil)
    return base64.StdEncoding.EncodeToString(ciphertext)
}

func (a *AdvancedObfuscator) Decrypt(encrypted string) string {
    if encrypted == "" {
        return ""
    }
    
    data, err := base64.StdEncoding.DecodeString(encrypted)
    if err != nil {
        return encrypted
    }
    
    block, err := aes.NewCipher(a.key)
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
    xorData, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return encrypted
    }
    
    // De-obfuscate XOR
    xorKey := a.key[:8]
    result := XORObfuscate(xorData, xorKey)
    return string(result)
}

// Helper function to generate random strings
func GenerateRandomString(length int) string {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    b := make([]byte, length)
    if _, err := rand.Read(b); err != nil {
        return ""
    }
    for i := range b {
        b[i] = charset[int(b[i])%len(charset)]
    }
    return string(b)
}

// Generate random key
func GenerateKey() string {
    key := make([]byte, 32)
    rand.Read(key)
    return base64.StdEncoding.EncodeToString(key)
}

// MD5 hash (useful for checksums)
func MD5Hash(data string) string {
    hash := md5.Sum([]byte(data))
    return hex.EncodeToString(hash[:])
}

// SHA256 hash
func SHA256Hash(data string) string {
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}
