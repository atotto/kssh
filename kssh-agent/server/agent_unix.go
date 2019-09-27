package server

import (
	"fmt"
	"io"
	"log"
	"net"

	"golang.org/x/crypto/ssh/agent"
)

func Serve(listener net.Listener, kr agent.Agent) (env []string, err error) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return nil, fmt.Errorf("accept: %s", err)
		}
		go func() {
			if err := agent.ServeAgent(kr, conn); err != nil {
				if err != io.EOF {
					log.Printf("serve agent: %s", err)
				}
				return
			}
			conn.Close()
		}()
	}
}
