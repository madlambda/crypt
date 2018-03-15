package crypt

// Cipher is a transform operation on src based on key
type Cipher func(src, key []byte) ([]byte, error)

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
