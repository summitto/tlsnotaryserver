package aes_tag

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"time"
)

func VerifyTag(id string, pohMask string, tagMask string, cipherText []string, aad string, tagShare string) (bool, error) {
	pohMaskRE := regexp.MustCompilePOSIX("^([01]+\n)+[01]+$")
	tagMaskRE := regexp.MustCompilePOSIX("^[01]+$")

	// Verify Powers of H mask as a string of 0 and 1 with line breaks
	if !pohMaskRE.MatchString(pohMask) {
		return false, errors.New("unexpected Powers of H mask format in tag verification")
	}

	// Verify IV tag mask as a string of 0 and 1
	if !tagMaskRE.MatchString(tagMask) {
		return false, errors.New("unexpected IV tag mask format in tag verification")
	}

	// Verify cipher text as a list of strings, where each element is a decimal byte
	for _, s := range cipherText {
		if _, err := strconv.ParseUint(s, 10, 8); err != nil {
			return false, errors.New("unexpected value in cipher text array in tag verification")
		}
	}

	// Verify AAD as a hex string
	decodedAad, err := hex.DecodeString(aad)
	if err != nil || len(decodedAad) != hex.DecodedLen(len(aad)) {
		return false, errors.New("unexpected AAD format in tag verification")
	}

	// Verify tag share as a big integer
	if err := big.NewInt(0).UnmarshalText([]byte(tagShare)); err != nil {
		return false, errors.New("unexpected tag share format in tag verification")
	}

	// generate a name for temporary storage
	nameHash := sha1.New()
	nameHash.Write([]byte(id))
	name := hex.EncodeToString(nameHash.Sum(nil))

	errInternal := errors.New("internal error in tag verification")

	err = os.MkdirAll(name, 0777)
	if err != nil {
		log.Println(err)
		return false, errInternal
	}
	defer os.RemoveAll(name)

	pohFilePath := path.Join(name, "poh")
	eivFilePath := path.Join(name, "eiv")
	ciphertextFilePath := path.Join(name, "ciphertext")

	err = os.WriteFile(pohFilePath, []byte(pohMask), 0666)
	if err != nil {
		log.Println(err)
		return false, errInternal
	}
	err = os.WriteFile(eivFilePath, []byte(tagMask), 0666)
	if err != nil {
		log.Println(err)
		return false, errInternal
	}
	ciphertextContent, err := json.Marshal(cipherText)
	if err != nil {
		log.Println(err)
		return false, errInternal
	}
	err = os.WriteFile(ciphertextFilePath, []byte(ciphertextContent), 0666)
	if err != nil {
		log.Println(err)
		return false, errInternal
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	wd, err := os.Getwd()
	if err != nil {
		log.Println(err)
		return false, errInternal
	}

	cmd := exec.CommandContext(ctx, "python3", path.Join(wd, "src", "verify_tag.py"), pohFilePath, eivFilePath, ciphertextFilePath, aad, tagShare)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Println("Tag verification error:", string(output), err)
	}
	return err == nil, nil
}
