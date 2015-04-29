// chat-room project chat-room.go
package chatroom

import (
	"crypto/rand"
	"errors"
	"io"
	"log"
	"net"

	"golang.org/x/crypto/nacl/box"
)

const BUFFER_SIZE = 32000

// SecureReaderWriterCloser Combined reader/writer for use with shared keys
type SecureReaderWriterCloser struct {
	reader    *SecureReader
	writer    *SecureWriter
	transport io.ReadWriteCloser
}

type EncryptedMessage struct {
	nonce   [24]byte
	length  int32
	message []byte
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
	if ok {
		copy(message, unencryptedMessage)
		return length, err
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

func makeKeys() (*[32]byte, *[32]byte, *[32]byte) {
	publicKey := new([32]byte)
	privateKey := new([32]byte)
	peerKey := new([32]byte)
	return publicKey, privateKey, peerKey
}

// Don't use this. It's used for the demo only. If this goes wrong, give up here.
func keyExchangeSendLast(transport io.ReadWriteCloser) (*[32]byte, *[32]byte, *[32]byte) {
	publicKey, privateKey, peerKey := makeKeys()
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
	publicKey, privateKey, peerKey := makeKeys()
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

func continousRead(reader io.Reader, output chan []byte, errors chan error) {
	for {
		// try to read the data
		data := make([]byte, BUFFER_SIZE)
		n, err := reader.Read(data)
		if err != io.EOF && err != nil {
			// send an error if it's encountered
			errors <- err
			return
		}
		// send data if we read some.
		if n > 0 {
			output <- data
		}
	}
}
