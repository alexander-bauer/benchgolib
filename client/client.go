package main

import (
	"bufio"
	bench "github.com/SashaCrofter/benchgolib"
	"io/ioutil"
	"log"
	"net"
	"os"
)

var S *bench.Session

func main() {
	log.SetOutput(ioutil.Discard)

	msg := make(chan *bench.Message) //Create a blocking chan
	listen(msg)

	sessionStr := "no session"

	println("Type a hostname or IP address to start a session.")
	for {
		userinput := ui(sessionStr + "> ")
		if S == nil {
			println("Generating key. (This may take a while.)")
			var err error
			S, err = bench.NewSession("tclient", userinput, nil)
			if err != nil {
				log.Println(err)
				println("Error initializing session.")
				continue
			}
			sessionStr = "s"
		} else {
			S.SendString(userinput)
		}
	}
}

func listen(msg chan *bench.Message) {
	ln, err := net.Listen("tcp", "0.0.0.0:"+bench.Port)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Listening on", ln.Addr())
	go func(msg chan<- *bench.Message) {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Println(conn.RemoteAddr().String(), err)
				continue
			}
			go handle(conn, msg)
		}
	}(msg)
	go func(msg <-chan *bench.Message) {
		for m := range msg {
			showMessage(S, m)
		}
	}(msg)
}

func handle(conn net.Conn, msg chan<- *bench.Message) {
	defer conn.Close()
	log.Println("Incoming from", conn.RemoteAddr().String())
	m, err := bench.ReceiveMessage(conn)
	if err != nil {
		log.Println(err)
		return
	}
	msg <- m
}

func showMessage(s *bench.Session, m *bench.Message) {
	md := s.GetMessage(*m)
	println(md.Content)
}

func ui(prompt string) string {
	for {
		reader := bufio.NewReader(os.Stdin)
		print(prompt)
		line, err := reader.ReadString('\n')
		if err != nil {
			//The user may have meant to exit,
			//as with ctrl+D, so exit here.
			println()
			log.Fatal(err)
		}
		return line[:len(line)-1] //Remove the newline byte.
	}
	return ""
}
