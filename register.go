// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"http"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"template"
)

// This file handles public server list registration

const registerTemplate = `
<server>
 {.section machash}<machash>{machash}</machash>{.end}
 {.section version}<version>{version}</version>{.end}
 {.section release}<release>{release}</release>{.end}
 {.section os}<os>{os}</os>{.end}
 {.section osver}<osver>{osver}</osver>{.end}
 {.section qt}<qt>{qt}</qt>{.end}
 {.section is64bit}<is64bit>{is64bit}</is64bit>{.end}
 {.section cpuid}<cpu_id>{cpuid}</cpu_id>{.end}
 {.section cpuextid}<cpu_extid>{cpu_extid}</cpu_extid>{.end}
 {.section cpusse2}<cpu_sse2>{cpusse2}</cpu_sse2>{.end}
 {.section name}<name>{name}</name>{.end}
 {.section host}<host>{host}</host>{.end}
 {.section password}<password>{password}</password>{.end}
 {.section port}<port>{port}</port>{.end}
 {.section url}<url>{url}</url>{.end}
 {.section digest}<digest>{digest}</digest>{.end}
 {.section users}<users>{users}</users>{.end}
 {.section channels}<channels>{channels}</channels>{.end}
 {.section location}<location>{location}</location>{.end}
</server>
`

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
	if len(server.RegisterName) == 0 {
		return false
	}
	if len(server.RegisterHost) == 0 {
		return false
	}
	if len(server.RegisterPassword) == 0 {
		return false
	}
	if len(server.RegisterWebUrl) == 0 {
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
	buf := bytes.NewBuffer(nil)
	t, err := template.Parse(registerTemplate, nil)
	if err != nil {
		log.Printf("register: unable to parse template: %v", err)
		return
	}
	err = t.Execute(buf, map[string]string{
		"name":     server.RegisterName,
		"host":     server.RegisterHost,
		"password": server.RegisterPassword,
		"url":      server.RegisterWebUrl,
		"location": server.RegisterLocation,
		"port":     strconv.Itoa(server.port),
		"digest":   digest,
		"users":    strconv.Itoa(len(server.clients)),
		"channels": strconv.Itoa(len(server.Channels)),
	})
	if err != nil {
		log.Printf("register: unable to execute template: %v", err)
		return
	}

	// Post registration XML data to server asynchronously in its own goroutine
	go func() {
		// Go's http package does not allow HTTP clients to set their own
		// certificate chain, so we use our own wrapper instead.
		hc, err := newTLSClientAuthConn(registerAddr, config)
		if err != nil {
			log.Printf("register: unable to create https client: %v", err)
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

		req.URL, err = http.ParseURL(registerUrl)
		if err != nil {
			log.Printf("register: error parsing url: %v", err)
			return
		}

		r, err := hc.Do(&req)
		if err != nil && err != http.ErrPersistEOF {
			log.Printf("register: unable to post registration request: %v", err)
			return
		}

		bodyBytes, err := ioutil.ReadAll(r.Body)
		if err == nil {
			registerMsg := string(bodyBytes)
			if r.StatusCode == 200 {
				log.Printf("register: %v", registerMsg)
			} else {
				log.Printf("register: (status %v) %v", r.StatusCode, registerMsg)
			}
		} else {
			log.Printf("register: unable to read post response: %v", err)
			return
		}
	}()
}
