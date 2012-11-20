package main

import (
	"bufio"
	bench "github.com/SashaCrofter/benchgolib"
	//"io/ioutil"
	"log"
	"net"
	"os"
	"time"
)

func main() {
	//log.SetOutput(ioutil.Discard)

	log.Println("Starting session.")
	s, err := bench.NewSession("client", ui("Remote address: "))
	if err != nil {
		log.Println(err)
	}
	listen(s)

	log.Println("Composing message.")
	err = s.SendString(ui("Please write your message: "))
	if err != nil {
		log.Println(err)
	}
	log.Println("Sent.")
	time.Sleep(time.Second)
}

func listen(s *bench.Session) {
	ln, err := net.Listen("tcp", "0.0.0.0:"+bench.Port)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Listening on", ln.Addr())
	go func(s *bench.Session) {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Println(conn.RemoteAddr().String(), err)
				continue
			}
			go showMessage(conn, s)
		}
	}(s)
}

func showMessage(conn net.Conn, s *bench.Session) {
	defer conn.Close()
	log.Println("Message.")
	m, err := bench.ReceiveMessage(conn)
	if err != nil {
		log.Println(err)
		return
	}
	if m == nil || s == nil {
		println("nil")
		return
	}
	md := s.GetMessage(*m)

	print("From ", conn.RemoteAddr().String(), ":\n")
	print(" ", md.Content, "\n")
}

func ui(prompt string) string {
	for {
		reader := bufio.NewReader(os.Stdin)
		print(prompt)
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Println(err)
			continue
		}
		return line[:len(line)-1] //Remove the newline byte.
	}
	return ""
}
