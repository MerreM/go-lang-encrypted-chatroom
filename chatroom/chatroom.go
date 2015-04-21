// chat-room project chat-room.go
package chatroom

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/nacl/box"
)

const BUFFER_SIZE = 512

var buf bytes.Buffer
var logger = log.New(&buf, "Chat Logger: ", log.Llongfile)

// SecureReaderWriterCloser Combined reader/writer for use with shared keys
type SecureReaderWriterCloser struct {
	reader    *SecureReader
	writer    *SecureWriter
	transport io.Closer
}

// Close Closes the transport used by the reader/writer
func (s SecureReaderWriterCloser) Close() error {
	return s.transport.Close()
}

// NewSecureReaderWriterCloser Creates new ReaderWriter with peers key, and private key.
// Slightly annoyed you can get the keys the wrong way round without suitable care.
func NewSecureReaderWriterCloser(priv, peerKey *[32]byte, conn net.Conn) SecureReaderWriterCloser {
	reader := &SecureReader{reader: conn, privateKey: priv, sharedKey: peerKey}
	writer := &SecureWriter{writer: conn, privateKey: priv, sharedKey: peerKey}
	return SecureReaderWriterCloser{reader: reader, writer: writer, transport: conn}
}

// Creates new read encrypted message
func (s SecureReaderWriterCloser) Read(data []byte) (int, error) {
	return s.reader.Read(data)

}

// Writes new encrpyed message
func (s SecureReaderWriterCloser) Write(data []byte) (int, error) {
	return s.writer.Write(data)
}

// SecureReader A secure reader, should be paired with a SecureWriter
type SecureReader struct {
	reader                io.Reader
	privateKey, sharedKey *[32]byte
}

// SecureWriter A secure writer, should be paired with a SecureReader
type SecureWriter struct {
	writer                io.Writer
	privateKey, sharedKey *[32]byte
}

// ErrorDecryption in the decryption.
var ErrorDecryption = errors.New("decryption error")

// GenerateNonce a one-use number using crypto, I trust (perhaps foolishly) that
// it's fine.
func GenerateNonce() (*[24]byte, error) {
	var nonce [24]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return nil, err
	}
	return &nonce, nil

}

// Read encrypted mesasge with private and shared key.
func (r *SecureReader) Read(message []byte) (int, error) {
	var nonce [24]byte
	encryptedData := make([]byte, len(message)+len(nonce)+box.Overhead)
	length, err := r.reader.Read(encryptedData)
	if err != nil {
		return -1, err
	}
	copy(nonce[:], encryptedData) // Get the nonce
	var unencryptedMessage []byte
	unencryptedMessage, ok := box.Open(unencryptedMessage, encryptedData[len(nonce):length], &nonce, r.sharedKey, r.privateKey)
	length = length - box.Overhead - len(nonce)
	log.Println("Unencrypted:" + string(unencryptedMessage))
	if ok {
		copy(message, unencryptedMessage)
		return length, io.EOF
	}
	return length, ErrorDecryption
}

// Write encrypted mesasge with private and shared key.
func (w *SecureWriter) Write(message []byte) (int, error) {
	var encryptedData []byte
	nonce, err := GenerateNonce()
	if err != nil {
		log.Fatal(err)
		return -1, err
	}
	encryptedData = box.Seal(encryptedData[:0], message, nonce, w.sharedKey, w.privateKey)
	return w.writer.Write(append(nonce[:], encryptedData...))
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	return &SecureReader{reader: r, privateKey: priv, sharedKey: pub}
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	return &SecureWriter{writer: w, privateKey: priv, sharedKey: pub}
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	_, privateKey, peerKey := keyExchangeSendFirst(conn)
	return NewSecureReaderWriterCloser(privateKey, peerKey, conn), nil
}

// Don't use this. It's used for the demo only. If this goes wrong, give up here.
func keyExchangeSendLast(transport io.ReadWriteCloser) (*[32]byte, *[32]byte, *[32]byte) {
	publicKey := new([32]byte)
	privateKey := new([32]byte)
	peerKey := new([32]byte)
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		defer transport.Close()
		panic(err)
	}
	_, err = transport.Read(peerKey[:])
	if err != nil {
		defer transport.Close()
		panic(err)
	}
	_, err = transport.Write(publicKey[:])
	if err != nil {
		defer transport.Close()
		panic(err)
	}
	return publicKey, privateKey, peerKey
}

// Don't use this. It's used for the demo only.
func keyExchangeSendFirst(transport io.ReadWriteCloser) (*[32]byte, *[32]byte, *[32]byte) {
	publicKey := new([32]byte)
	privateKey := new([32]byte)
	peerKey := new([32]byte)
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		defer transport.Close()
		panic(err)
	}
	_, err = transport.Write(publicKey[:])
	if err != nil {
		defer transport.Close()
		panic(err)
	}
	_, err = transport.Read(peerKey[:])
	if err != nil {
		defer transport.Close()
		panic(err)
	}
	return publicKey, privateKey, peerKey
}

var clients []net.Conn
var history []string

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	for {
		connect, err := l.Accept()
		if err != nil {
			return err
		}
		go func(transport net.Conn) {
			_, privateKey, peerKey := keyExchangeSendFirst(transport)
			rw := NewSecureReaderWriterCloser(privateKey, peerKey, transport)
			buf := bytes.NewBuffer(make([]byte, bytes.MinRead))
			_, err := buf.ReadFrom(rw)
			if err != nil && err != io.EOF {
				log.Fatal(err)
				defer rw.Close()
				panic(err)
			}
			clients = append(clients, transport)
			log.Printf("Recieved Message\t[%s] from [%s]\n", buf.Bytes(), connect.RemoteAddr())
			history = append(history, string(buf.Bytes()))
			if len(history) > 10 {
				history = history[len(history)-10:]
			}
			for _, oldMessage := range history {
				log.Println("Server sending history " + oldMessage)
				_, err = rw.Write([]byte(oldMessage))
				if err != nil {
					log.Fatal(err)
					defer rw.Close()
					panic(err)
				}
			}

		}(connect)
	}
}

func Client() {
	// Client mode
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <port> <message>", os.Args[0])
	}
	conn, err := Dial("localhost:" + os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write([]byte(os.Args[2])); err != nil {
		log.Fatal(err)
	}
	output := make(chan []byte)
	errors := make(chan error)
	go continousRead(conn, output, errors)
	for {
		select {
		// This case means we recieved data on the connection
		case data := <-output:
			// Do something with the data
			log.Printf("Recieved from Server %s\n", string(data))
		// This case means we got an error and the goroutine has finished
		case err := <-errors:
			// handle our error then exit for loop
			log.Panicln(err)
		}
	}
}

func continousRead(reader io.Reader, output chan []byte, errors chan error) {
	//	buf := bytes.NewBuffer(make([]byte, 2048))
	for {
		// try to read the data

		//		n, err := buf.ReadFrom(reader)
		temp := make([]byte, 2048)
		n, err := reader.Read(temp)
		if err != ErrorDecryption && err != nil {
			errors <- err
		}
		// send data if we read some.
		if n > 0 {
			log.Printf("Bytes read %v\n", n)
			output <- []byte(buf.Bytes())
		}

	}
}
