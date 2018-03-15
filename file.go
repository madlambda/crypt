package crypt

import (
	"fmt"
	"io/ioutil"
	"os"
)

// EncryptFile encrypts srcFile using cipher enc into dstFile.
// DstFile must not exists.
func EncryptFile(srcFile, dstFile string, key []byte, enc Crypter) error {
	if _, err := os.Stat(dstFile); err == nil {
		return fmt.Errorf("EncryptFile: destination exists")
	}

	src, err := ioutil.ReadFile(srcFile)
	if err != nil {
		return fmt.Errorf("EncryptFile: %s", err)
	}

	crypted, err := enc(src, key)
	if err != nil {
		return fmt.Errorf("EncryptFile: %s", err)
	}

	err = ioutil.WriteFile(dstFile, crypted, 0644)
	if err != nil {
		return fmt.Errorf("EncryptFile: %s", err)
	}
	return nil
}

// DecryptFile decrypts srcFile using cipher dec and key into dstFile.
func DecryptFile(srcFile, dstFile string, key []byte, dec Decrypter) error {
	if _, err := os.Stat(dstFile); err == nil {
		return fmt.Errorf("DecryptFile: destination exists")
	}

	src, err := ioutil.ReadFile(srcFile)
	if err != nil {
		return fmt.Errorf("DecryptFile: %s", err)
	}

	decrypted, err := dec(src, key)
	if err != nil {
		return fmt.Errorf("EncryptFile: %s", err)
	}

	err = ioutil.WriteFile(dstFile, decrypted, 0644)
	if err != nil {
		return fmt.Errorf("EncryptFile: %s", err)
	}
	return nil
}
