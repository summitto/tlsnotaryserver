package aes_tag

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"notary/utils"
	"os"
	"strconv"
	"time"
)

type TagSigningManager struct {
	signingKey   *ecdsa.PrivateKey
	lastModified time.Time
}

func NewTagSigningManager(signingKeyPath string) (*TagSigningManager, error) {
	file, err := os.ReadFile(signingKeyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(file)

	ecdsaKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	manager := new(TagSigningManager)
	manager.signingKey = ecdsaKey
	manager.lastModified = time.Now()

	log.Printf("Loaded %s tag signing key (curve %s)\n", signingKeyPath, ecdsaKey.Params().Name)

	return manager, nil
}

// Sign returns an ASN.1-encoded ECDSA-SHA256 signature over ciphertext
func (t *TagSigningManager) Sign(ciphertext []string) ([]byte, error) {
	ciphertextBytes := make([]byte, 0)
	// convert strings of decimal bytes into actual bytes for hashing
	for _, byteString := range ciphertext {
		byteNum, err := strconv.Atoi(byteString)
		if err != nil || byteNum < 0 || byteNum > 255 {
			continue
		}
		ciphertextBytes = append(ciphertextBytes, byte(byteNum))
	}
	if len(ciphertextBytes) != len(ciphertext) {
		return nil, errors.New("signing invalid ciphertext failed")
	}
	digest := utils.Sha256(ciphertextBytes)

	return ecdsa.SignASN1(rand.Reader, t.signingKey, digest)
}

func (t *TagSigningManager) ServePublicKey(w http.ResponseWriter, req *http.Request) {
	if t.signingKey == nil {
		w.WriteHeader(http.StatusInternalServerError)
		panic("TagSigningManager: no signing key found")
	}

	derBytes, err := x509.MarshalPKIXPublicKey(&t.signingKey.PublicKey)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	pubKeyPEM := pem.EncodeToMemory(block)
	w.Header().Set("Content-Type", "application/x-pem-file")
	reader := bytes.NewReader(pubKeyPEM)

	http.ServeContent(w, req, "signing-key.pem", t.lastModified, reader)
}
