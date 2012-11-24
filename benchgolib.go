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
	Version = "0.4"

	Port           = "9419"
	NewSessionMsg  = "NEW SESSION"
	OkaySessionMsg = "OKAY"

	keySize = 2048 //Default keysize for in-memory keys
)

var (
	defSM *defSessionManager = &defSessionManager{} //The default SessionManager to fall back on
)

//Session is the type which encapsulates a single benchgo session, including temporary key, remote taret, and message history. It can be used to send and recieve message objects.
type Session struct {
	SID     uint64        //Identifier for the session.
	Cipher  *cast5.Cipher //The CAST5 Cipher type
	Remote  string        //The address of the remote participant.
	History []*Message    //The entire history of message objects.
}

//The Message type is used to encapsulate lone messages, which can be transmitted directly across the wire. It contains the Session ID, timestamp, and the contents of the message, but the timestamp is not transmitted.
type Message struct {
	SID       uint64    `bencode:"sid"` //The session identifier.
	Timestamp time.Time `bencode:"-"`   //The time of composition.
	Content   string    `bencode:"c"`   //The message contained by the structure.
}

//The SessionManager interface wraps the internal PrivateKey(), which should return a valid *rsa.PrivateKey, and the internal SessionByID(), which should return a *Session based on the given uint64.
type SessionManager interface {
	AddSession(s *Session) error
	SessionByID(sid uint64) *Session
	PrivateKey() *rsa.PrivateKey
}

type defSessionManager struct {
	Key      *rsa.PrivateKey     //In-memory PrivateKey if NewSession if a proper SessionManager isn't supplied
	Sessions map[uint64]*Session //In-memory Session map for Session and Message functions to use, if SessionManager is not supplied
}

func (m *defSessionManager) AddSession(s *Session) error {
	if m.Sessions == nil {
		m.Sessions = make(map[uint64]*Session, 1)
	}
	m.Sessions[s.SID] = s
	return nil
}

func (m *defSessionManager) SessionByID(sid uint64) *Session {
	return m.Sessions[sid]
}

func (m *defSessionManager) PrivateKey() *rsa.PrivateKey {
	if m.Key == nil {
		var err error
		m.Key, err = rsaGen(keySize)
		if err != nil {
			panic(err)
		}
		//This doesn't catch any errors, possibly
		//resulting in runtime errors.
	}
	return m.Key
}

type sessionEstablish struct {
	Version    string `bencode:"v"`
	Type       string `bencode:"t"`
	PKModulus  string `bencode:"m"`
	PKExponent int    `bencode:"e"`
	HalfKey    []byte `bencode:"k"`
}

//NewSession initializes a new session with the remote address. It causes a dialogue and key exchange between the remote and local clients. If manager is not specified, then this function uses the default one. It makes precisely one call to PrivateKey() on the manager, and keeps the resultant pointer in memory briefly, so as to avoid unnecessary additional calls. If a new Session is initialized properly, NewSession invokes AddSession() on the manager.
func NewSession(remote string, manager SessionManager) (s *Session, err error) {
	//If our manager was not supplied,
	//then we must use the default.
	if manager == nil {
		//If the SessionManager doesn't
		//exist, use the default.
		manager = defSM
	}

	//Here, we must establish the session key
	//with the remote client. First, we'll
	//make sure that the connection will get
	//through.
	conn, err := net.Dial("tcp", net.JoinHostPort(remote, Port))
	if err != nil {
		return
	}
	defer conn.Close()

	//Once the connection is established, both
	//clients will generate a session ID based
	//on a known and determined method.

	//For that, we need the local address, as
	//seen by the remote.
	local, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		//In the unlikely event that this
		//gives an error, close the conn
		//(via defer) and return.
		return
	}
	//This will hash the local and remote
	//together predictably. The remote client
	//will put our address first, as well.
	sid := getSID(local, remote)

	e, d := bencode.NewEncoder(conn), bencode.NewDecoder(conn)
	key := make([]byte, 16)

	//Send the message initialization request, with:
	//* Our version
	//* "NEW SESSION"
	//* Our public key
	privKey := manager.PrivateKey()
	pubKey := privKey.PublicKey
	err = e.Encode(&sessionEstablish{
		Version:    Version,
		Type:       NewSessionMsg,
		PKModulus:  pubKey.N.String(),
		PKExponent: pubKey.E,
	})
	if err != nil {
		return
	}

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
	tmpKey, err := keyDecrypt(privKey, response.HalfKey)
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
		Remote:  remote,
		History: make([]*Message, 0),
	}
	err = manager.AddSession(s)
	return
}

//ReceiveSession
func ReceiveSession(conn net.Conn, manager SessionManager) (s *Session, err error) {
	defer conn.Close()
	//If our manager was not supplied,
	//then we must use the default.
	if manager == nil {
		//If the SessionManager doesn't
		//exist, use the default.
		manager = defSM
	}

	//Now that the connection is established,
	//we need to have the same session ID as
	//the remote client.

	//For that, we need the remote address,
	remote, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return
	}

	//We also need the local address, as
	//seen by the remote.
	local, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		//In the unlikely event that this
		//gives an error, close the conn
		//(via defer) and return.
		return
	}
	//This will hash the local and remote
	//together predictably. We put the
	//remote's address first, as do they.
	sid := getSID(remote, local)

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

	privKey := manager.PrivateKey()
	pubKey := privKey.PublicKey
	err = e.Encode(sessionEstablish{
		Version:    Version,
		Type:       OkaySessionMsg,
		PKModulus:  pubKey.N.String(),
		PKExponent: pubKey.E,
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

	tmpKey, err = keyDecrypt(privKey, response.HalfKey)
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
		SID:     sid,
		Cipher:  cipher,
		Remote:  remote,
		History: make([]*Message, 0),
	}
	err = manager.AddSession(s)
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

//ReceiveMessage is used to retrieve a Message from an input device. It uses bencode to recieve directly from the wire. It uses SessionByID() from the given manager to retrieve the relevant session, then perform the decryption. It returns a pointer to the relevant Session, the undecrypted message, the decrypted contents, and error if neccessary.
func ReceiveMessage(r io.Reader, manager SessionManager) (s *Session, m *Message, content string, err error) {
	//Since we cannot sensibly handle the error
	//here, we must return it whether or not it
	//is nil. The Message, whether or not it
	//came through, will go with it.
	err = bencode.NewDecoder(r).Decode(&m)
	if err != nil || m.SID == 0 {
		return
	}
	//If there is no error, set the timestamp.
	m.Timestamp = time.Now()

	//Now, use the SessionManager to retrieve
	//the relevant Session.
	s = manager.SessionByID(m.SID)
	if s == nil {
		err = errors.New("no session ID matching incoming message")
		return
	}

	content = s.arbitraryDecrypt(m.Content)
	return
}
