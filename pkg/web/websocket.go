// Copyright (c) 2018 The Grumble Authors
// The use of this source code is governed by a BSD-style
// license that can be found in the LICENSE-file.

package web

import (
	"bytes"
	"io"
	"net"
	"time"

	"github.com/gorilla/websocket"
)

type conn struct {
	ws     *websocket.Conn
	msgbuf bytes.Buffer
}

func (c *conn) Read(b []byte) (n int, err error) {
	if c.msgbuf.Len() == 0 {
		_, r, err := c.ws.NextReader()
		if err != nil {
			if _, ok := err.(*websocket.CloseError); ok {
				return 0, io.EOF
			}
			return 0, err
		}
		if _, err := c.msgbuf.ReadFrom(r); err != nil {
			return 0, err
		}
	}
	// Impossible to read over message boundaries - will generate EOF
	return c.msgbuf.Read(b)
}

func (c *conn) Write(b []byte) (n int, err error) {
	return len(b), c.ws.WriteMessage(websocket.BinaryMessage, b)
}

func (c *conn) Close() error {
	return c.ws.Close()
}

func (c *conn) LocalAddr() net.Addr {
	return c.ws.LocalAddr()
}

func (c *conn) RemoteAddr() net.Addr {
	return c.ws.RemoteAddr()
}

func (c *conn) SetDeadline(t time.Time) (err error) {
	if err = c.ws.SetReadDeadline(t); err != nil {
		return err
	}
	return c.ws.SetWriteDeadline(t)
}

func (c *conn) SetReadDeadline(t time.Time) error {
	return c.ws.SetReadDeadline(t)
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	return c.ws.SetWriteDeadline(t)
}
