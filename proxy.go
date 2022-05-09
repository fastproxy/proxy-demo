package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

var domainRe = regexp.MustCompile(`^(\w+)\.([\w\.]*)(\:\d+)*$`)

var tlsConfig = &tls.Config{
	ClientAuth:         tls.NoClientCert,
	ClientCAs:          cc.GetCertPool(),
	InsecureSkipVerify: true,
	GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		domain := info.ServerName
		dotCount := strings.Count(domain, ".")
		if dotCount == 0 {
			return nil, fmt.Errorf("invalid domain %s", domain)
		}

		if dotCount > 1 {
			domain = domainRe.ReplaceAllString(info.ServerName, "*.${2}")
		}

		log.Printf("Cert Server Name: %s\n", domain)
		cert, err := cc.GetServerPair(domain)
		if err != nil {
			log.Printf("Generate Cert Error: %s\n", err)
			return nil, err
		}
		log.Printf("Generate Cert Success: %s\n", domain)

		return &tls.Certificate{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  cert.PrivateKey,
			Leaf:        &cert.Certificate,
		}, nil
	},
}

var proxyClient = &fasthttp.Client{
	MaxConnsPerHost:    16384,            // MaxConnsPerHost  default is 512, increase to 16384
	ReadTimeout:        60 * time.Second, // 如果在生产环境启用会出现多次请求现象
	WriteTimeout:       60 * time.Second,
	MaxConnWaitTimeout: 60 * time.Second,
}

var XPS = []byte("X-Proxy-Server")

func ProxyServe(conn net.Conn) (err error) {
	log.Printf("Serve TLS Conn")

	err = fasthttp.ServeConn(tls.Server(conn, tlsConfig), func(ctx *fasthttp.RequestCtx) {
		log.Printf("Proxy Request: %s %s %s %s\n", ctx.URI().Scheme(), ctx.Method(), ctx.Host(), ctx.Path())

		req := &ctx.Request
		resp := &ctx.Response

		proxyResp := fasthttp.AcquireResponse()

		if err := proxyClient.Do(req, proxyResp); err != nil {
			log.Printf("Client request err %s", err)
			return
		}

		log.Printf("Proxy Request Success: %s %d %s\n", req.Host(), proxyResp.StatusCode(), proxyResp.Header.ContentType())

		proxyResp.CopyTo(resp)
		resp.Header.SetBytesK(XPS, "Jedi/0.1")
		fasthttp.ReleaseResponse(proxyResp)
	})

	if err != nil {
		log.Printf("Serve TLS Conn err %s", err)
	}

	return
}
