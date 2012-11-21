package benchgolib

import (
	"code.google.com/p/go.crypto/cast5"
	"crypto/rsa"
	"errors"
	"github.com/zeebo/bencode"
	"io"
	"math/big"
	"net"
	"time"
)

const (
	Version = "0.2"

	Port           = "8081"
	NewSessionMsg  = "NEW SESSION"
	OkaySessionMsg = "OKAY"

	keySize = 512 //Default keysize for in-memory keys
)

var (
	privKey *rsa.PrivateKey //The in-memory PrivateKey if NewSession isn't given a function for getting it.
)

//Session is the type which encapsulates a single benchgo session, including temporary key, remote taret, and message history. It can be used to send and recieve message objects.
type Session struct {
	SID     int64         //Identifier for the session.
	Cipher  *cast5.Cipher //The CAST5 Cipher type
	RSAKey  RSAKey        //The RSAKey interface for getting a valid RSA key
	Remote  string        //The address of the remote participant.
	History []*Message    //The entire history of message objects.
}

//The Message type is used to encapsulate lone messages, which can be transmitted directly across the wire. It contains the Session ID, timestamp, and the contents of the message, but the timestamp is not transmitted.
type Message struct {
	SID       int64     `bencode:"sid"` //The session identifier.
	Timestamp time.Time `bencode:"-"`   //The time of composition.
	Content   string    `bencode:"c"`   //The message contained by the structure.
}

//The RSAKey interface wraps the internal Get(), which should return a valid *rsa.PrivateKey.
type RSAKey interface {
	Get() *rsa.PrivateKey
}

type defRSAKey struct{}

func (rsaKey defRSAKey) Get() *rsa.PrivateKey {
	return privKey
}

type sessionEstablish struct {
	Version    string `bencode:"v"`
	Type       string `bencode:"t"`
	PKModulus  string `bencode:"m"`
	PKExponent int    `bencode:"e"`
	HalfKey    []byte `bencode:"k"`
}

//NewSession initializes a new session with the remote address. The local address or domain is used to identify the initializing client, (such as with a domain name, as opposed to an IP address.
func NewSession(local, remote string, rsaKey RSAKey) (s *Session, err error) {
	//TODO
	//SID should be further randomized, as by
	//a multiplication or addition, followed
	//by a hash function.
	sid := time.Now().UnixNano()

	//If our rsaKey function was not supplied,
	//then we must define our own.
	if rsaKey == nil {
		//If our in-memory key does not
		//exist, then we must generate it.
		if privKey == nil {
			privKey, err = rsaGen(keySize)
			if err != nil {
				return
			}
		}
		rsaKey = defRSAKey{}
	}

	//Here, we must establish the session key
	//with the remote client. First, we'll
	//make sure that the connection will get
	//through.
	conn, err := net.Dial("tcp", net.JoinHostPort(remote, Port))
	if err != nil {
		return
	}
	e, d := bencode.NewEncoder(conn), bencode.NewDecoder(conn)
	key := make([]byte, 16)

	//Send the message initialization request, with:
	//* Our version
	//* "NEW SESSION"
	//* Our public key
	pubKey := rsaKey.Get().PublicKey
	err = e.Encode(&sessionEstablish{
		Version:    Version,
		Type:       NewSessionMsg,
		PKModulus:  pubKey.N.String(),
		PKExponent: pubKey.E,
	})
	if err != nil {
		return
	}
	return

	//Now we get the remote's response. If establishing:
	//* Their version
	//* "OKAY"
	//* Their public key
	//* Their session key half (encrypted to our key)
	var response sessionEstablish
	err = d.Decode(&response)
	if err != nil {
		return
	}

	if response.Type != OkaySessionMsg || len(response.PKModulus) == 0 || response.PKExponent == 0 || response.HalfKey == nil {
		return nil, errors.New("remote client declined session request")
	}
	remoteModulus, _ := new(big.Int).SetString(response.PKModulus, 0)
	remoteKey := &rsa.PublicKey{
		N: remoteModulus,
		E: response.PKExponent,
	}

	//Supposing that everything was okay, decrypt their HalfKey half
	tmpKey, err := keyDecrypt(rsaKey.Get(), response.HalfKey)
	if err != nil {
		return
	}
	copy(key[0:8], tmpKey)

	tmpKey, err = sessionKeyGen()
	if err != nil {
		return
	}
	copy(key[8:16], tmpKey)

	tmpKey, err = keyEncrypt(remoteKey, key[8:16])
	if err != nil {
		return
	}

	err = e.Encode(&sessionEstablish{
		Version: Version,
		Type:    OkaySessionMsg,
		HalfKey: tmpKey,
	})
	if err != nil {
		return
	}

	cipher, err := cast5.NewCipher(key)
	if err != nil {
		//TODO
		//If there is an error, then we
		//should communicate it to the
		//other party.
		return
	}

	s = &Session{
		SID:     sid,
		Cipher:  cipher,
		RSAKey:  rsaKey,
		Remote:  remote,
		History: make([]*Message, 0),
	}
	return s, nil
}

//ReceiveSession
func ReceiveSession(conn net.Conn, rsaKey RSAKey) (s *Session, err error) {
	defer conn.Close()
	//If our rsaKey function was not supplied,
	//then we must define our own.
	if rsaKey == nil {
		//If our in-memory key does not
		//exist, then we must generate it.
		if privKey == nil {
			privKey, err = rsaGen(keySize)
			if err != nil {
				return
			}
		}
		rsaKey = defRSAKey{}
	}

	e, d := bencode.NewEncoder(conn), bencode.NewDecoder(conn)

	var request sessionEstablish
	err = d.Decode(&request)
	if err != nil {
		return
	}

	if request.Type != NewSessionMsg || len(request.PKModulus) == 0 || request.PKExponent == 0 {
		return
	}
	//Reconstruct the key.
	remoteModulus, _ := new(big.Int).SetString(request.PKModulus, 0)
	remoteKey := &rsa.PublicKey{
		N: remoteModulus,
		E: request.PKExponent,
	}

	key := make([]byte, 16)

	tmpKey, err := sessionKeyGen()
	if err != nil {
		return
	}
	copy(key[0:8], tmpKey)

	tmpKey, err = keyEncrypt(remoteKey, key[0:8])
	if err != nil {
		return
	}

	pubkey := rsaKey.Get().PublicKey
	err = e.Encode(sessionEstablish{
		Version:    Version,
		Type:       OkaySessionMsg,
		PKModulus:  pubkey.N.String(),
		PKExponent: pubkey.E,
		HalfKey:    tmpKey,
	})
	if err != nil {
		return
	}

	var response sessionEstablish
	err = d.Decode(&response)
	if err != nil {
		return
	}
	if response.Type != OkaySessionMsg || response.HalfKey == nil {
		return
	}

	tmpKey, err = keyDecrypt(rsaKey.Get(), response.HalfKey)
	if err != nil {
		return
	}
	copy(key[8:16], tmpKey)

	//Now the local and remote share the key

	cipher, err := cast5.NewCipher(key)
	if err != nil {
		//TODO
		//If there is an error, then we
		//should communicate it to the
		//other party.
		return
	}

	s = &Session{
		SID:     time.Now().UnixNano(),
		Cipher:  cipher,
		RSAKey:  rsaKey,
		Remote:  conn.RemoteAddr().String(),
		History: make([]*Message, 0),
	}
	conn.Close()
	return
}

//SendMessage completely encapsulates the process of sending a single Message to the remote target using a single communication session. It ensures that the Message's SID field is set to the Session's.
func (s *Session) SendMessage(m Message) (err error) {
	//Open a connection to the remote.
	//net.JoinHostPort allows us to use IPv6 addresses without
	//brackets.
	conn, err := net.Dial("tcp", net.JoinHostPort(s.Remote, Port))
	if err != nil {
		//If the connection could not be made,
		//return the error.
		return
	}
	//Stamp the Message with the current SID.
	m.SID = s.SID

	//Encrypt the content.
	m.Content, err = s.arbitraryEncrypt(m.Content)
	if err != nil {
		return
	}

	//Encode direct to the wire.
	err = bencode.NewEncoder(conn).Encode(m)
	if err != nil {
		//If the encoding failed, then
		//return the error.
		return
	}
	//If sending succeeded, then add the message
	//to the history.
	s.History = append(s.History, &m)
	return
}

//SendString wraps SendMessage. It creates a Message with the supplied string in the Content field, and with the timestamp as supplied by time.Now().
func (s *Session) SendString(content string) error {
	return s.SendMessage(Message{
		Timestamp: time.Now(),
		Content:   content,
	})
}

//GetMessage is used to add an already-recieved Message to the History, then decrypt its contents. It returns a separate, decrypted message.
func (s *Session) GetMessage(m Message) *Message {
	//Append the encrypted message to the history.
	s.History = append(s.History, &m)

	//Decrypt the content.
	content := s.arbitraryDecrypt(m.Content)

	//Change the Content to the decrypted version.
	m.Content = content
	return &m
}

//ReceiveMessage is used to retrieve a Message from an input device. It uses bencode to recieve directly from the wire. It does not perform any decryption step.
func ReceiveMessage(r io.Reader) (m *Message, err error) {
	//Since we cannot sensibly handle the error
	//here, we must return it whether or not it
	//is nil. The Message, whether or not it
	//came through, will go with it.
	err = bencode.NewDecoder(r).Decode(&m)
	if err == nil {
		//If there is no error, then the
		//Message is not nil, and we can
		//set the timestamp.
		m.Timestamp = time.Now()
	}
	return
}
