package benchgolib

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

//sessionKeyGen uses crypto/rand to generate 64 random bits to use as a session key.
func sessionKeyGen() (key []byte, err error) {
	key = make([]byte, 8)   //Length 64 bits
	_, err = rand.Read(key) //Fill key with random data
	return
}

//getSID uses crypto/sha256 to compute the session ID by appending the receiving address to the initiating address, hashing them, and taking the first 8 bytes of the result. The network addresses should not have port numbers, and should be in the form as returned by net.SplitHostPort().
func getSID(initiating, receiving string) (sid []byte) {
	//Prepare the sid buffer.
	sid = make([]byte, 8)

	//We must get a hash.Hash object,
	//so that we can use Write() and
	//Sum() to retrieve the hash
	//value, then copy to the buffer.
	hash := sha256.New()
	hash.Write([]byte(initiating + receiving))
	copy(sid, hash.Sum(nil)[0:8])
	return
}

//rsaGen uses crypto/rsa and crypto/rand to generate a new *rsa.PrivateKey of the given size.
func rsaGen(size int) (key *rsa.PrivateKey, err error) {
	return rsa.GenerateKey(rand.Reader, size)
}

//keyEncrypt encrypts a byte array to the rsa public key passed it, and returns the resultant byte array. It uses rand.Reader to pass to rsa.EncryptPKCS1v15.
func keyEncrypt(key *rsa.PublicKey, data []byte) (crp []byte, err error) {
	return rsa.EncryptPKCS1v15(rand.Reader, key, data)
}

//keyDecrypt is the sister function to rsaEncrypt.
func keyDecrypt(key *rsa.PrivateKey, data []byte) (crp []byte, err error) {
	return rsa.DecryptPKCS1v15(rand.Reader, key, data)
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
