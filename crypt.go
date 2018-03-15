package crypt

type (
	Crypter   func(src []byte, key []byte) ([]byte, error)
	Decrypter func(src []byte, key []byte) ([]byte, error)
)

// Pad data to blocksize
func Pad(data []byte, blocksz int) []byte {
	if len(data)%blocksz != 0 {
		r := blocksz - len(data)%blocksz
		for i := 0; i < r; i++ {
			data = append(data, 0) // padding
		}
	}
	return data
}
