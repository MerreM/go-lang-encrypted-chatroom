// chatimpl project main.go
package main

import (
	"flag"
	"fmt"
	"go-lang-encrypted-chatroom/chatroom"
	"log"
	"net"
)

func main() {
	listenPort := flag.Int("l", 0, "Listen mode. Specify port")
	sendPort := flag.Int("c", 0, "Client mode. Specify port")
	flag.Parse()
	// Server mode
	if *listenPort != 0 {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", *listenPort))
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		log.Fatal(chatroom.Serve(l))
	} else {
		chatroom.Client(*sendPort)
	}
}
