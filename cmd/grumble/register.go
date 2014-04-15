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
	"encoding/xml"
	"io/ioutil"
	"net/http"
)

type Register struct {
	XMLName  xml.Name `xml:"server"`
	Version  string   `xml:"version"`
	Release  string   `xml:"release"`
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

const registerUrl = "https://mumble.hive.no/register.cgi"

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
	digest := hex.EncodeToString(hasher.Sum(nil))

	// Render registration XML template
	reg := Register{
		Name:     server.cfg.StringValue("RegisterName"),
		Host:     server.cfg.StringValue("RegisterHost"),
		Password: server.cfg.StringValue("RegisterPassword"),
		Url:      server.cfg.StringValue("RegisterWebUrl"),
		Location: server.cfg.StringValue("RegisterLocation"),
		Port:     server.CurrentPort(),
		Digest:   digest,
		Users:    len(server.clients),
		Channels: len(server.Channels),
		Version:  "1.2.4",
		Release:  "Grumble Git",
	}
	buf := bytes.NewBuffer(nil)
	err := xml.NewEncoder(buf).Encode(reg)
	if err != nil {
		server.Printf("register: unable to marshal xml: %v", err)
		return
	}

	// Post registration XML data to server asynchronously in its own goroutine
	go func() {
		tr := &http.Transport{
			TLSClientConfig: config,
		}
		client := &http.Client{Transport: tr}
		r, err := client.Post(registerUrl, "text/xml", ioutil.NopCloser(buf))
		if err != nil {
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
