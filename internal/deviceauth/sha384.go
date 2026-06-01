package deviceauth

import "crypto/sha512"

func sha384Sum(data []byte) []byte {
	sum := sha512.Sum384(data)
	return sum[:]
}
