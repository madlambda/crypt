package tea_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/madlambda/crypt"
	"github.com/madlambda/crypt/tea"
	"github.com/madlambda/spells/assert"
)

type testcase struct {
	plain, crypted []byte
	key            []byte
}

var emptyKey = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

func TestEncrypt(t *testing.T) {
	for _, tc := range []testcase{
		{
			plain:   []byte{},
			crypted: []byte{},
			key:     emptyKey,
		},
		{
			plain:   []byte{0},
			crypted: []byte{0x41, 0xea, 0x3a, 0xa, 0x94, 0xba, 0xa9, 0x40},
			key:     emptyKey,
		},
		{
			plain:   []byte{1}, // changing 1 byte gives completely different result
			crypted: []byte{0xa7, 0x63, 0x20, 0x8c, 0x59, 0x8d, 0x9b, 0x83},
			key:     emptyKey,
		},
		{
			plain:   []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			crypted: []byte{0xf6, 0xf4, 0xbf, 0x6e, 0x13, 0x35, 0xb5, 0xb8},
			key:     emptyKey,
		},
		{
			plain:   []byte{0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			crypted: []byte{0x88, 0xad, 0x8c, 0x1b, 0x62, 0xbe, 0x8, 0xdf},
			key:     emptyKey,
		},
		{
			plain:   []byte("i4k"),
			crypted: []byte{0xaa, 0xe5, 0x26, 0xf6, 0xd, 0xf, 0x35, 0x6e},
			key:     emptyKey,
		},
		{
			plain:   []byte("katz"),
			crypted: []byte{0xb6, 0xe7, 0x8, 0xb7, 0x2, 0x2f, 0x97, 0xc},
			key:     emptyKey,
		},
		{
			plain:   []byte("vitor"),
			crypted: []byte{0x6b, 0x9e, 0x93, 0xe7, 0xda, 0x92, 0x86, 0x47},
			key:     emptyKey,
		},
		{
			plain:   []byte("lerax"),
			crypted: []byte{0x82, 0xcc, 0x38, 0x8a, 0x8b, 0x5, 0xd9, 0xb7},
			key:     emptyKey,
		},
		{
			plain:   []byte("secret"),
			crypted: []byte{0xb5, 0xed, 0x76, 0xde, 0xa, 0x9, 0xc4, 0x11},
			key:     []byte("super secret password")[:tea.KeySize],
		},
		{
			plain: []byte(`multiple blocks of data
						  =========================================
						  =========================================`),
			crypted: []byte{0x3b, 0xaa, 0x7d, 0xbd, 0xf2, 0x60, 0x71, 0xd9,
				0x91, 0xab, 0xae, 0x59, 0xfc, 0x90, 0x32, 0xa5, 0xda, 0xa2,
				0x7c, 0x10, 0xce, 0x30, 0x3d, 0xd8, 0xfb, 0x63, 0x1d, 0xea,
				0xe, 0x87, 0xa, 0xf9, 0x53, 0x80, 0xa2, 0xa2, 0xe2, 0x1f,
				0xd6, 0xd9, 0x53, 0x80, 0xa2, 0xa2, 0xe2, 0x1f, 0xd6, 0xd9,
				0x53, 0x80, 0xa2, 0xa2, 0xe2, 0x1f, 0xd6, 0xd9, 0x53, 0x80,
				0xa2, 0xa2, 0xe2, 0x1f, 0xd6, 0xd9, 0x53, 0x80, 0xa2, 0xa2,
				0xe2, 0x1f, 0xd6, 0xd9, 0xd6, 0xf3, 0xdd, 0x59, 0xb2, 0xaa,
				0x6, 0xd5, 0xf6, 0x2b, 0x42, 0x82, 0x89, 0xb4, 0xad, 0xd2,
				0x53, 0x80, 0xa2, 0xa2, 0xe2, 0x1f, 0xd6, 0xd9, 0x53, 0x80,
				0xa2, 0xa2, 0xe2, 0x1f, 0xd6, 0xd9, 0x53, 0x80, 0xa2, 0xa2,
				0xe2, 0x1f, 0xd6, 0xd9, 0x53, 0x80, 0xa2, 0xa2, 0xe2, 0x1f,
				0xd6, 0xd9, 0xba, 0x49, 0x8c, 0xe0, 0x67, 0x16, 0xd5, 0xab},
			key: []byte("secret-secret-secret")[:tea.KeySize],
		},
	} {
		got, err := tea.Encrypt(tc.plain, tc.key)
		assert.NoError(t, err, "fail to encrypt: %s", tc.plain)

		if !reflect.DeepEqual(got, tc.crypted) {
			t.Fatalf("crypt differs: %#v != %#v", got, tc.crypted)
		}

		decrypted, err := tea.Decrypt(got, tc.key)
		assert.NoError(t, err, "fail to decrypt: %s", got)

		if !reflect.DeepEqual(decrypted, tea.Pad(tc.plain)) {
			t.Fatalf("Decryption failed: %v != %v", decrypted, tc.plain)
		}
	}
}

func TestEncryptFile(t *testing.T) {
	wd, err := os.Getwd()
	assert.NoError(t, err, "getting wd")

	plainFiles, err := filepath.Glob(wd + "/_testing/*.txt")
	assert.NoError(t, err, "getting test files")

	var cleanupFiles []string

	defer func() {
		for _, f := range cleanupFiles {
			os.Remove(f)
		}
	}()

	for _, src := range plainFiles {
		cryptFile := strings.Replace(src, ".txt", ".crypt", 1)
		keyFile := strings.Replace(src, ".txt", ".key", 1)

		key, err := ioutil.ReadFile(keyFile)
		assert.NoError(t, err, "read key file: %s", keyFile)

		key = key[:tea.KeySize]

		tmpFile, err := ioutil.TempFile("", "crypt-")
		assert.NoError(t, err, "creating tmp crypt file")
		tmp := tmpFile.Name()
		tmpFile.Close()

		os.Remove(tmp)

		cleanupFiles = append(cleanupFiles, tmp)

		err = crypt.EncryptFile(src, tmp, key, tea.Encrypt)
		assert.NoError(t, err, "encrypting file %s", src)

		expectedCrypt, err := ioutil.ReadFile(cryptFile)
		assert.NoError(t, err, "reading crypt file")

		gotCrypt, err := ioutil.ReadFile(tmp)
		assert.NoError(t, err, "reading gen crypt file")

		if !reflect.DeepEqual(expectedCrypt, gotCrypt) {
			t.Fatalf("Crypted file content differ for %s", src)
		}

		expectedPlain, err := ioutil.ReadFile(src)
		assert.NoError(t, err, "reading plain file")

		gotPlain, err := tea.Decrypt(gotCrypt, key)
		assert.NoError(t, err, "decrypting %s", src)

		// why? we use pad in the plaintext input
		gotPlain = gotPlain[:len(expectedPlain)]
		if !reflect.DeepEqual(expectedPlain, gotPlain) {
			t.Fatalf("decrypted file content differ for %s: '%s' != '%s'",
				src, expectedPlain, gotPlain)
		}
	}
}
