package benchgolib

import (
	"github.com/zeebo/bencode"
	"net"
	"time"
)

const (
	Version = "0.0"

	port = "8081"
)

//Session is the type which encapsulates a single benchgo session, including temporary key, remote taret, and message history. It can be used to send and recieve message objects.
type Session struct {
	ID      string      //Identifier for the session.
	Key     interface{} //To-be-determined.
	Remote  string      //The address of the remote participant.
	History []*Message  //The entire history of message objects.
}

//The Message type is used to encapsulate lone messages to be sent across the wire. It contains the timestamp and the contents of the message.
type Message struct {
	Timestamp string //The time of composition.
	Content   string //The message contained by the structure.
}

//NewSession initializes a new session with the remote address. The local address or domain is used to identify the initializing client, (such as with a domain name, as opposed to an IP address.
func NewSession(local, remote string) (s *Session, err error) {
	s = &Session{
		Remote:  remote,
		History: make([]*Message, 0),
	}
	return s, nil
}

//SendMessage completely encapsulates the process of sending a single message to a single target using a single communication session.
func (s *Session) SendMessage(m *Message) (err error) {
	conn, err := net.Dial("tcp", s.Remote+":"+port)
	if err != nil {
		//If the connection could not be made,
		//return the error.
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
	s.History = append(s.History, m)
	return
}

//SendString is a wrapper for SendMessage. It creates a Message with the supplied string in the Content field, and with the timestamp as supplied by time.Now().
func (s *Session) SendString(content string) error {
	return s.SendMessage(&Message{
		Timestamp: time.Now().String(),
		Content:   content,
	})
}
