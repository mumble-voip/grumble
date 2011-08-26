// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

// This file handles public server list registration

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"http"
	"io/ioutil"
	"net"
	"os"
	"url"
	"xml"
)

type Register struct {
	XMLName  xml.Name `xml:"server"`
	//MacHash  string   `xml:"machash"`
	Version  string   `xml:"version"`
	Release  string   `xml:"release"`
	//OS       string   `xml:"os"`
	//OSVer    string   `xml:"osver"`
	//Qt       string   `xml:"qt"`
	//Is64Bit  bool     `xml:"is64bit"`
	//CpuId    string   `xml:"cpuid"`
	//CpuIdExt string   `xml:"cpuidext"`
	//CpuSSE2  bool     `xml:"cpusse2"`
	Name     string   `xml:"name"`
	Host     string   `xml:"host"`
	Password string   `xml:"password"`
	Port     int      `xml:"port"`
	Url      string   `xml:"url"`
	Digest   string   `xml:"digest"`
	Users    int      `xml:"users"`
	Channels int      `xml:"channels"`
	Location string   `xml:"location"`
}

const (
	registerAddr = "mumble.hive.no:443"
	registerUrl  = "https://mumble.hive.no/register.cgi"
)

// Create a persistent HTTP ClientConn to server at addr with TLS configuration cfg.
func newTLSClientAuthConn(addr string, cfg *tls.Config) (c *http.ClientConn, err os.Error) {
	tcpaddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}

	tcpconn, err := net.DialTCP("tcp", nil, tcpaddr)
	if err != nil {
		return nil, err
	}

	tlsconn := tls.Client(tcpconn, cfg)
	if err != nil {
		return nil, err
	}

	return http.NewClientConn(tlsconn, nil), nil
}

// Determines whether a server is public by checking whether the
// config values required for public registration are set.
//
// This function is used to determine whether or not to periodically
// contact the master server list and update this server's metadata.
func (server *Server) IsPublic() bool {
	if len(server.cfg.StringValue("RegisterName")) == 0 {
		return false
	}
	if len(server.cfg.StringValue("RegisterHost")) == 0 {
		return false
	}
	if len(server.cfg.StringValue("RegisterPassword")) == 0 {
		return false
	}
	if len(server.cfg.StringValue("RegisterWebUrl")) == 0 {
		return false
	}
	return true
}

// Perform a public server registration update.
//
// When a Mumble server connects to the master server
// for registration, it connects using its server certificate
// as a client certificate for authentication purposes.
func (server *Server) RegisterPublicServer() {
	if !server.IsPublic() {
		return
	}

	// Fetch the server's certificates and put them in a tls.Config.
	// We need the certificate chain to be able to use it in our client
	// certificate chain to the registration server, and we also need to
	// include a digest of the leaf certiifcate in the registration XML document
	// we send off to the server.
	config := &tls.Config{}
	for _, cert := range server.tlscfg.Certificates {
		config.Certificates = append(config.Certificates, cert)
	}

	hasher := sha1.New()
	hasher.Write(config.Certificates[0].Certificate[0])
	digest := hex.EncodeToString(hasher.Sum())

	// Render registration XML template
	reg := Register{
		Name:     server.cfg.StringValue("RegisterName"),
		Host:     server.cfg.StringValue("RegisterHost"),
		Password: server.cfg.StringValue("RegisterPassword"),
		Url:      server.cfg.StringValue("RegisterWebUrl"),
		Location: server.cfg.StringValue("RegisterLocation"),
		Port:     server.port,
		Digest:   digest,
		Users:    len(server.clients),
		Channels: len(server.Channels),
		Version:  "1.2.4",
		Release:  "Grumble Git",
	}
	buf := bytes.NewBuffer(nil)
	err := xml.Marshal(buf, reg)
	if err != nil {
		server.Printf("register: unable to marshal xml: %v", err)
		return
	}

	// Post registration XML data to server asynchronously in its own goroutine
	go func() {
		// Go's http package does not allow HTTP clients to set their own
		// certificate chain, so we use our own wrapper instead.
		hc, err := newTLSClientAuthConn(registerAddr, config)
		if err != nil {
			server.Printf("register: unable to create https client: %v", err)
			return
		}
		defer hc.Close()

		// The master registration server requires
		// that a Content-Length be specified in incoming HTTP requests.
		// Make sure we don't send a chunked request by hand-crafting it.
		var req http.Request
		req.Method = "POST"
		req.ProtoMajor = 1
		req.ProtoMinor = 1
		req.Close = true
		req.Body = ioutil.NopCloser(buf)
		req.ContentLength = int64(buf.Len())
		req.Header = http.Header{
			"Content-Type": {"text/xml"},
		}

		req.URL, err = url.Parse(registerUrl)
		if err != nil {
			server.Printf("register: error parsing url: %v", err)
			return
		}

		r, err := hc.Do(&req)
		if err != nil && err != http.ErrPersistEOF {
			server.Printf("register: unable to post registration request: %v", err)
			return
		}

		bodyBytes, err := ioutil.ReadAll(r.Body)
		if err == nil {
			registerMsg := string(bodyBytes)
			if r.StatusCode == 200 {
				server.Printf("register: %v", registerMsg)
			} else {
				server.Printf("register: (status %v) %v", r.StatusCode, registerMsg)
			}
		} else {
			server.Printf("register: unable to read post response: %v", err)
			return
		}
	}()
}
