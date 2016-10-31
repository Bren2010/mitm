// Command mitm intercepts and outputs decrypted TLS connections from the host machine to outside servers. It
// automatically handles the generation of trusted certificate chains.
package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
)

var (
	laddr = flag.String("laddr", "127.0.0.1:443", "Local address to listen on.")
	raddr = flag.String("raddr", "", "Remote address to upstream data to.")
	sni   = flag.String("sni", "", "SNI to accept and offer.")
)

func main() {
	flag.Parse()
	if *laddr == "" || *raddr == "" || *sni == "" {
		log.Println("All flags are mandatory.")
		flag.PrintDefaults()
		os.Exit(1)
	}

	l, rootCert, err := newServer()
	if err != nil {
		log.Fatal(err)
	}
	addTrustedRoot(rootCert)
	defer rmTrustedRoot()

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt)
		<-ch
		l.Close()
	}()

	log.Println("Started.")
	for i := 0; ; i++ {
		client, err := l.Accept()
		if err != nil {
			log.Println(err)
			break
		}

		go handle(i, client)
	}
}

// handle takes a client connection and connection id as input. It dials uptream and proxies between the two.
func handle(id int, client net.Conn) {
	server, err := tls.Dial("tcp", *raddr, &tls.Config{ServerName: *sni})
	if err != nil {
		log.Printf("Failed to accept connection: %v", err)
		client.Close()
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		pipe(fmt.Sprintf("#%v >", id), server, client)
		wg.Done()
	}()
	go func() {
		pipe(fmt.Sprintf("#%v <", id), client, server)
		wg.Done()
	}()

	wg.Wait()

	client.Close()
	server.Close()
	log.Printf("End connection %v.", id)
}

// pipe reads from src and writes to dst. It outputs what it read to stdout, prefixed by prefix.
func pipe(prefix string, dst, src net.Conn) {
	reader := bufio.NewReader(src)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("(Error reading: %v) %v", err, prefix)
			return
		}

		fmt.Printf("%v %s\n", prefix, line)

		_, err = fmt.Fprintln(dst, line)
		if err != nil {
			log.Printf("(Error writing: %v) %v", err, prefix)
			return
		}
	}
}
