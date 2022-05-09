package main

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/reuseport"
)

var cc *CertChain = NewCertChain()
var stcs []*SecurityTrustCert = []*SecurityTrustCert{}

func init() {
	_ = cc.LoadRootPair("cert/root.cert.pem", "cert/root.key.pem")
	_ = cc.LoadInterPair("cert/inter.cert.pem", "cert/inter.key.pem")
	root := cc.GetRootPair()
	inter := cc.GetInterPair()

	err := root.Save("cert/root.cert.pem", "cert/root.key.pem")
	if err != nil {
		panic(err)
	}
	err = inter.Save("cert/inter.cert.pem", "cert/inter.key.pem")
	if err != nil {
		panic(err)
	}

	rootCertFile, _ := filepath.Abs("./cert/root.cert.pem")
	interCertFile, _ := filepath.Abs("./cert/inter.cert.pem")
	rc := NewSecurityTrustCert()
	ic := NewSecurityTrustCert()

	err = rc.AddTrustedCert(rootCertFile)
	if err != nil {
		panic(err)
	}
	stcs = append(stcs, rc)

	err = ic.AddTrustedCert(interCertFile)
	if err != nil {
		log.Println(err)
	}
	stcs = append(stcs, ic)

	setSystemProxy()
}

func main() {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		unsetSystemProxy()
		for _, s := range stcs {
			s.RemoveTrustedCert()
		}
		os.Exit(1)
	}()

	ln, err := reuseport.Listen("tcp4", ":6789")
	if err != nil {
		log.Fatalln(err)
	}

	s := &fasthttp.Server{
		Handler:            connectHandler,
		IdleTimeout:        time.Minute,
		MaxConnsPerIP:      16384,
		MaxRequestsPerConn: 200,
	}

	if err := s.Serve(ln); err != nil {
		log.Fatalln(err)
	}
}

func connectHandler(ctx *fasthttp.RequestCtx) {
	if ctx.IsConnect() {
		log.Printf("Connect Handle: %s %s %s %s\n", ctx.URI().Scheme(), ctx.Method(), ctx.Host(), ctx.Path())
		log.Printf("Connection Established：%s\n", ctx.Host())
		handleConnect(ctx)
		return
	}

	log.Printf("Direct Handle: %s %s %s %s\n", ctx.URI().Scheme(), ctx.Method(), ctx.Host(), ctx.Path())

	if string(ctx.Host()) == "127.0.0.1:6789" {
		ctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
		ctx.SetBodyString("This is a http tunnel proxy, only CONNECT method is allowed.")
	}

	handleProxy(ctx)
}
