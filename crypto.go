package benchgolib

import (
	"crypto/rand"
	"crypto/rsa"
)

func rsaGen(size int) (key *rsa.PrivateKey, err error) {
	return rsa.GenerateKey(rand.Reader, size)
}

//rsaEncrypt encrypts a byte array to the rsa public key passed it, and returns the resultant byte array.
func rsaEncrypt(key *rsa.PublicKey, data []byte) (crp []byte, err error) {
	return nil, nil
}

//arbitraryEncrypt implements a simple for-loop and zero-padding to user s.Cipher to encrypt an arbitrary length byte array. It returns the enciphered byte array, which may not be the same length.
func (s *Session) arbitraryEncrypt(src string) (string, error) {
	//Determine the length of the padding.
	blockSize := s.Cipher.BlockSize()
	paddingLength := blockSize - (len(src) % blockSize)

	//Pad with the zero value for bytes, 0x00.
	plain := append([]byte(src), make([]byte, paddingLength)...)
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

//arbitraryDecrypt is the sister function for arbitraryEncrypt, which allows an arbitrary length byte array to be decrypted into a string. It undoes arbitraryEncrypt.
func (s *Session) arbitraryDecrypt(src string) string {
	blockSize := s.Cipher.BlockSize()

	cipher := []byte(src)
	plain := make([]byte, len(src))

	for i := 0; i < len(cipher); i += blockSize {
		//Encrypt a block of plaintext, and put it in the
		//Ciphertext buffer, destination, source.
		s.Cipher.Decrypt(plain[i:i+blockSize], cipher[i:i+blockSize])
	}

	return string(plain)
}
