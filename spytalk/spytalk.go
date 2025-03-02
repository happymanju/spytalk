package spytalk

import (
	"bufio"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"io"
)

func MakeRSAKeyPair() (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func GetPublicKey(privKey *rsa.PrivateKey) crypto.PublicKey {
	pubKey := privKey.Public()
	return pubKey
}

func EncodePrivateKeyToPEM(privKey *crypto.PrivateKey) ([]byte, error) {
	encodedKey, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	return encodedKey, nil
}

func EncodePublicKeyToPEM(pubKey *crypto.PublicKey) ([]byte, error) {
	encodedKey, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	return encodedKey, nil
}

func DecodePrivateKeyFromPEM(encodedKey []byte) (crypto.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(encodedKey)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func DecodePublicKeyFromPEM(encodedKey []byte) (crypto.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(encodedKey)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func SavePEMToFile(w io.Writer, encodedKey []byte) (string, error) {
	bw := bufio.NewWriter(w)

	n, err := bw.Write(encodedKey)
	if err != nil {
		return "", err
	}

	err = bw.Flush()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Wrote %d bytes\n", n), nil
}

func GenerateAESKey() []byte {
	aesKey := make([]byte, 32)
	rand.Reader.Read(aesKey)

	return aesKey
}

func EncryptMessageWithAES(key []byte, plaintext []byte) (ciphertext []byte, nonce []byte, err error) {
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, nil, err
	}

	cipherText := make([]byte, 0)
	nonce = make([]byte, gcm.NonceSize())
	rand.Reader.Read(nonce)

	gcm.Seal(cipherText, nonce, plaintext, nil)
	return cipherText, nonce, nil
}

func DecryptMessageWithAES(key []byte, ciphertext []byte, nonce []byte) (plaintext []byte, err error) {
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, err
	}
	plaintext = make([]byte, 0)

	_, err = gcm.Open(plaintext, nonce, ciphertext, nil)
	return plaintext, nil
}

func EncryptAESKeyWithRSA(aesKey []byte, pubKey *rsa.PublicKey) ([]byte, error) {
	encryptedKey, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, pubKey, aesKey, nil)
	if err != nil {
		return nil, err
	}

	return encryptedKey, nil
}

func DecryptAESKeyWithRSA(aesKey []byte, privKey *rsa.PrivateKey) ([]byte, error) {
	decryptedKey, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, privKey, aesKey, nil)
	if err != nil {
		return nil, err
	}
	return decryptedKey, nil
}
