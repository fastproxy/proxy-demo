package main

import (
	"log"
	"net"
	"time"

	"github.com/valyala/fasthttp"
)

var cc *CertChain = NewCertChain()

func init() {
	cc.LoadRootPair("cert/ca.cert.pem", "cert/ca.key.pem")
	cc.LoadInterPair("cert/inter.cert.pem", "cert/inter.key.pem")
}

func main() {
	ln, err := net.Listen("tcp", ":6789")
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
	log.Printf("Connect Handle: %s %s %s %s\n", ctx.URI().Scheme(), ctx.Method(), ctx.Host(), ctx.Path())
	if ctx.IsConnect() {
		log.Printf("Connection Established：%s\n", ctx.Host())
		handleConnect(ctx)
		return
	}

	ctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
	ctx.SetBodyString("This is a http tunnel proxy, only CONNECT method is allowed.")
}
