package crypt

import (
	"fmt"
	"io/ioutil"
	"os"
)

// EncryptFile encrypts srcFile using cipher enc into dstFile.
// DstFile must not exists.
func EncryptFile(srcFile, dstFile string, key []byte, enc Cipher) error {
	return transform(srcFile, dstFile, key, enc)
}

// DecryptFile decrypts srcFile using cipher dec and key into dstFile.
func DecryptFile(srcFile, dstFile string, key []byte, dec Cipher) error {
	return transform(srcFile, dstFile, key, dec)
}

func transform(srcFile, dstFile string, key []byte, op Cipher) error {
	if _, err := os.Stat(dstFile); err == nil {
		return fmt.Errorf("transform: destination exists")
	}

	src, err := ioutil.ReadFile(srcFile)
	if err != nil {
		return err
	}

	dst, err := op(src, key)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(dstFile, dst, 0644)
}
