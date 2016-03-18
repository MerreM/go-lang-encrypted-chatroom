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
	port := flag.Int("l", 0, "Listen mode. Specify port")
	flag.Parse()
	// Server mode
	if *port != 0 {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		log.Fatal(chatroom.Serve(l))
	} else {
		chatroom.Client()
	}

}
