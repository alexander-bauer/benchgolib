package main

import (
	"bufio"
	bench "github.com/SashaCrofter/benchgolib"
	//"io/ioutil"
	"log"
	"net"
	"os"
)

var S *bench.Session

func main() {
	//log.SetOutput(ioutil.Discard)

	listen()

	println("Type a hostname or IP address to start a session.")
	for {
		var sessionStr string
		if S == nil {
			sessionStr = "no session"
		} else {
			sessionStr = S.Remote
		}
		userinput := ui(sessionStr + "> ")
		if S == nil {
			println("Generating key. (This may take a while.)")
			var err error
			S, err = bench.NewSession(userinput, nil)
			if err != nil {
				log.Println(err)
				println("Error initializing session.")
				continue
			}
		} else {
			err := S.SendString(userinput)
			if err != nil {
				log.Println(err)
			}
		}
	}
}

func listen() {
	ln, err := net.Listen("tcp", "0.0.0.0:"+bench.Port)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Listening on", ln.Addr())
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Println(conn.RemoteAddr().String(), err)
				continue
			}
			go handle(conn)
		}
	}()
}

func handle(conn net.Conn) {
	defer conn.Close()
	log.Println("Incoming from", conn.RemoteAddr().String())
	if S == nil {
		s, err := bench.ReceiveSession(conn, nil)
		if err != nil {
			log.Println(err)
		}
		S = s
		return
	}
	_, _, content, err := bench.ReceiveMessage(conn, nil)
	if err != nil {
		log.Println(err)
		return
	}
	println(content)
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
