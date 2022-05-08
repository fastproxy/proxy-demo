package main

import (
	"log"
	"net"
	"time"

	"github.com/valyala/fasthttp"
)

var connectResponse = []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
var errResponse = []byte("HTTP/1.1 500 Internal Server Error\r\n\r\n")

func handleConnect(ctx *fasthttp.RequestCtx) {
	ctx.HijackSetNoResponse(true)
	ctx.Hijack(func(conn net.Conn) {
		log.Printf("Hijacked Connection %s", conn.RemoteAddr())

		// 设置一分钟超时时间
		conn.SetDeadline(time.Now().Add(time.Minute))

		_, err := conn.Write(connectResponse)
		if err != nil {
			log.Printf("Write Connect Response Error: %s", err)
			return
		}

		if err = ProxyServe(conn); err != nil {
			conn.Write(append(errResponse, []byte(err.Error())...))
			log.Printf("Hijacked Connection Error %s : %s.", ctx.RequestURI(), err)
		} else {
			log.Printf("Hijacked Connection Success.")
		}

	})
}
