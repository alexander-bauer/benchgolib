package benchgolib

import (
	"code.google.com/p/go.crypto/cast5"
	"github.com/zeebo/bencode"
	"io"
	"net"
	"time"
)

const (
	Version = "0.2"

	Port = "8081"
)

//Session is the type which encapsulates a single benchgo session, including temporary key, remote taret, and message history. It can be used to send and recieve message objects.
type Session struct {
	SID     int64         //Identifier for the session.
	Cipher  *cast5.Cipher //To-be-determined.
	Remote  string        //The address of the remote participant.
	History []*Message    //The entire history of message objects.
}

//The Message type is used to encapsulate lone messages, which can be transmitted directly across the wire. It contains the Session ID, timestamp, and the contents of the message, but the timestamp is not transmitted.
type Message struct {
	SID       int64     `bencode:"sid"` //The session identifier.
	Timestamp time.Time `bencode:"-"`   //The time of composition.
	Content   string    `bencode:"c"`   //The message contained by the structure.
}

//NewSession initializes a new session with the remote address. The local address or domain is used to identify the initializing client, (such as with a domain name, as opposed to an IP address.
func NewSession(local, remote string) (s *Session, err error) {
	//TODO
	//SID should be further randomized, as by
	//a multiplication or addition, followed
	//by a hash function.
	sid := time.Now().UnixNano()

	//TODO
	//The key step is really important. This
	//is where the Diffie-Hellman exchange
	//should be made, and the 128-bit key
	//determined.
	key := make([]byte, 16)

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
	return s, nil
}

//SendMessage completely encapsulates the process of sending a single Message to the remote target using a single communication session. It ensures that the Message's SID field is set to the Session's.
func (s *Session) SendMessage(m Message) (err error) {
	conn, err := net.Dial("tcp", s.Remote+":"+Port)
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
