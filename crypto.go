package benchgolib

import (
	"github.com/zeebo/bencode"
)

//arbitraryEncrypt implements a simple for-loop and zero-padding to user s.Cipher to encrypt an arbitrary length byte array. It returns the enciphered byte array, which may not be the same length.
//It first wraps the src string in bencode, so as to allow arbitrary-length decryption.
func (s *Session) arbitraryEncrypt(src string) (string, error) {
	//First, wrap the plaintext in bencode so that it is
	//easy to decrypt, even with zero padding.
	str, err := bencode.EncodeString(string(src))
	if err != nil {
		return "", err
	}

	//Determine the length of the padding.
	blockSize := s.Cipher.BlockSize()
	paddingLength := blockSize - (len(str) % blockSize)

	//Pad with the zero value for bytes, 0x00.
	plain := append([]byte(str), make([]byte, paddingLength)...)
	//len(plain) mod blockSize should now be 0.

	//Next, initialize the ciphertext buffer.
	cipher := make([]byte, len(plain))

	for i := 0; i < len(plain); i += blockSize {
		//Encrypt a block of plaintext, and put it in the
		//Ciphertext buffer, destination, source.
		s.Cipher.Encrypt(cipher[i:i+blockSize], plain[i:i+blockSize])
	}
	return string(cipher), nil
}
