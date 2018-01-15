// Copyright (c) 2018 The Grumble Authors
// The use of this source code is governed by a BSD-style
// license that can be found in the LICENSE-file.

package web

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	HandshakeTimeout: 20 * time.Second,
	Subprotocols:     []string{"mumble", "binary"},
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type Listener struct {
	sockets chan *conn
	done    chan struct{}
	addr    net.Addr
	closed  int32
	logger  *log.Logger
}

func NewListener(laddr net.Addr, logger *log.Logger) *Listener {
	return &Listener{
		sockets: make(chan *conn),
		done:    make(chan struct{}),
		addr:    laddr,
		logger:  logger,
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	if atomic.LoadInt32(&l.closed) != 0 {
		return nil, fmt.Errorf("accept ws %v: use of closed websocket listener", l.addr)
	}
	select {
	case ws := <-l.sockets:
		return ws, nil
	case <-l.done:
		return nil, fmt.Errorf("accept ws %v: use of closed websocket listener", l.addr)
	}
}

func (l *Listener) Close() error {
	if !atomic.CompareAndSwapInt32(&l.closed, 0, 1) {
		return fmt.Errorf("close ws %v: use of closed websocket listener", l.addr)
	}
	close(l.done)
	return nil
}

func (l *Listener) Addr() net.Addr {
	return l.addr
}

func (l *Listener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if atomic.LoadInt32(&l.closed) != 0 {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	l.logger.Printf("Upgrading web connection from: %v", r.RemoteAddr)
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		l.logger.Printf("Failed upgrade: %v", err)
		return
	}
	l.sockets <- &conn{ws: ws}
}
