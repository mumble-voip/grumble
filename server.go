// Copyright (c) 2010 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"log"
	"crypto/tls"
	"os"
	"net"
	"bufio"
	"bytes"
	"encoding/binary"
	"container/list"
	"sync"
	"goprotobuf.googlecode.com/hg/proto"
	"mumbleproto"
	"cryptstate"
)

// The default port a Murmur server listens on
const DefaultPort     = 64738
const UDPPacketSize   = 1024

const CeltCompatBitstream   = -2147483638

// Client connection states
const (
	StateClientConnected = iota
	StateServerSentVersion
	StateClientSentVersion
	StateClientAuthenticated
	StateClientDead
)

// A Murmur server instance
type Server struct {
	listener tls.Listener
	address  string
	port     int
	udpconn  *net.UDPConn

	incoming chan *Message
	outgoing chan *Message

	udpsend chan *Message

	// Config-related
	MaxUsers int
	MaxBandwidth uint32

	session uint32

	// A list of all connected clients
	cmutex *sync.RWMutex
	clients *list.List

	// Codec information
	AlphaCodec int32
	BetaCodec int32
	PreferAlphaCodec bool

	root *Channel
}

// A Mumble channel
type Channel struct {
	Id int
	Name string
	Description string
	Temporary bool
	Position int
	Channels *list.List
}

// Allocate a new Murmur instance
func NewServer(addr string, port int) (s *Server, err os.Error) {
	s = new(Server)

	s.address = addr
	s.port = port

	// Create the list of connected clients
	s.cmutex = new(sync.RWMutex)
	s.clients = list.New()

	s.outgoing = make(chan *Message)
	s.incoming = make(chan *Message)
	s.udpsend = make(chan *Message)

	s.MaxBandwidth = 300000
	s.MaxUsers = 10

	// Allocate the root channel

	s.root = &Channel{
		Id: 0,
		Name: "Root",
	}

	go s.handler()
	go s.multiplexer()

	return
}

// Called by the server to initiate a new client connection.
func (server *Server) NewClient(conn net.Conn) (err os.Error) {
	client := new(ClientConnection)

	// Get the address of the connected client
	if addr := conn.RemoteAddr(); addr != nil {
		client.tcpaddr = addr.(*net.TCPAddr)
		log.Stdoutf("client connected: %s", client.tcpaddr.String())
	}

	client.server = server
	client.conn = conn
	client.reader = bufio.NewReader(client.conn)
	client.writer = bufio.NewWriter(client.conn)
	client.state = StateClientConnected

	client.msgchan = make(chan *Message)
	client.udprecv = make(chan []byte)

	// New client connection....
	server.session += 1
	client.Session = server.session

	// Add it to the list of connected clients
	server.cmutex.Lock()
	server.clients.PushBack(client)
	server.cmutex.Unlock()

	go client.receiver()
	go client.udpreceiver()
	go client.sender()

	return
}

// Lookup a client by it's session id. Optimize this by using a map.
func (server *Server) getClientConnection(session uint32) (client *ClientConnection) {
	server.cmutex.RLock()
	defer server.cmutex.RUnlock()

	for x := range server.clients.Iter() {
		user := x.(*ClientConnection)
		if user.Session == session {
			return user
		}
	}

	return nil
}

// This is the synchronous request handler for all incoming messages.
func (server *Server) handler() {
	for {
		msg := <-server.incoming
		client := msg.client

		if client.state == StateClientAuthenticated {
			server.handleIncomingMessage(client, msg)
		} else if client.state == StateClientSentVersion {
			server.handleAuthenticate(client, msg)
		}
	}
}

func (server *Server) handleAuthenticate(client *ClientConnection, msg *Message) {
	// Is this message not an authenticate message? If not, discard it...
	if msg.kind != MessageAuthenticate {
		client.Panic("Unexpected message. Expected Authenticate.")
		return
	}

	auth := &mumbleproto.Authenticate{}
	err := proto.Unmarshal(msg.buf, auth)
	if err != nil {
		client.Panic("Unable to unmarshal Authenticate message.")
		return
	}

	// Did we get a username?
	if auth.Username == nil {
		client.Panic("No username in auth message...")
		return
	}

	client.Username = *auth.Username

	// Setup the cryptstate for the client.
	client.crypt, err = cryptstate.New()
	if err != nil {
		client.Panic(err.String())
		return
	}
	err = client.crypt.GenerateKey()
	if err != nil {
		client.Panic(err.String())
		return
	}

	// Send CryptState information to the client so it can establish an UDP connection
	// (if it wishes)...
	err = client.sendProtoMessage(MessageCryptSetup, &mumbleproto.CryptSetup{
		Key: client.crypt.RawKey[0:],
		ClientNonce: client.crypt.DecryptIV[0:],
		ServerNonce: client.crypt.EncryptIV[0:],
	})
	if err != nil {
		client.Panic(err.String())
	}

	client.codecs = auth.CeltVersions
	server.updateCodecVersions()

	client.sendChannelList()

	client.state = StateClientAuthenticated

	// Broadcast that we, the client, entered a channel...
	err = server.broadcastProtoMessage(MessageUserState, &mumbleproto.UserState{
		Session:    proto.Uint32(client.Session),
		Name:       proto.String(client.Username),
		ChannelId:  proto.Uint32(0),
	})
	if err != nil {
		client.Panic(err.String())
	}

	server.sendUserList(client)

	err = client.sendProtoMessage(MessageServerSync, &mumbleproto.ServerSync{
		Session:        proto.Uint32(client.Session),
		MaxBandwidth:   proto.Uint32(server.MaxBandwidth),
	})
	if err != nil {
		client.Panic(err.String())
		return
	}

	err = client.sendProtoMessage(MessageServerConfig, &mumbleproto.ServerConfig{
		AllowHtml: proto.Bool(true),
		MessageLength: proto.Uint32(1000),
		ImageMessageLength: proto.Uint32(1000),
	})
	if err != nil {
		client.Panic(err.String())
		return
	}

	client.state = StateClientAuthenticated
}

func (server *Server) updateCodecVersions() {
	codecusers := map[int32]int{}
	var winner int32
	var count int

	server.cmutex.RLock()
	defer server.cmutex.RUnlock()

	for x := range server.clients.Iter() {
		client := x.(*ClientConnection)
		for i := 0; i < len(client.codecs); i++ {
			codecusers[client.codecs[i]] += 1
		}
	}

	// result?
	for codec, users := range codecusers {
		if users > count {
			count = users
			winner = codec
		}
	}

	var current int32
	if server.PreferAlphaCodec {
		current = server.AlphaCodec
	} else {
		current = server.BetaCodec
	}

	if winner == current {
		return
	}

	if winner == CeltCompatBitstream {
		server.PreferAlphaCodec = true
	} else {
		server.PreferAlphaCodec = !server.PreferAlphaCodec
	}

	if (server.PreferAlphaCodec) {
		server.AlphaCodec = winner
	} else {
		server.BetaCodec = winner
	}

	err := server.broadcastProtoMessage(MessageCodecVersion, &mumbleproto.CodecVersion{
		Alpha:       proto.Int32(server.AlphaCodec),
		Beta:        proto.Int32(server.BetaCodec),
		PreferAlpha: proto.Bool(server.PreferAlphaCodec),
	})
	if err != nil {
		log.Stdoutf("Unable to broadcast..")
		return
	}

	log.Stdoutf("CELT codec switch %v %v (PreferAlpha %v)", server.AlphaCodec, server.BetaCodec, server.PreferAlphaCodec)

	return
}

func (server *Server) sendUserList(client *ClientConnection) {
	server.cmutex.RLock()
	defer server.cmutex.RUnlock()

	for x := range server.clients.Iter() {
		user := x.(*ClientConnection)
		if user.state != StateClientAuthenticated {
			continue
		}

		err := client.sendProtoMessage(MessageUserState, &mumbleproto.UserState{
			Session:   proto.Uint32(user.Session),
			Name:      proto.String(user.Username),
			ChannelId: proto.Uint32(0),
		})

		log.Stdoutf("Sent One User...")

		if err != nil {
			log.Stdoutf("unable to send!")
			continue
		}
	}

}

func (server *Server) broadcastProtoMessage(kind uint16, msg interface{}) (err os.Error) {
	server.cmutex.RLock()
	defer server.cmutex.RUnlock()

	for x := range server.clients.Iter() {
		client := x.(*ClientConnection)
		if client.state != StateClientAuthenticated {
			continue
		}
		err :=client.sendProtoMessage(kind, msg)
		if err != nil {
			return
		}
	}

	return
}

func (server *Server) handleIncomingMessage(client *ClientConnection, msg *Message) {
	log.Stdoutf("Handle Incoming Message")
	switch msg.kind {
	case MessagePing:
		server.handlePingMessage(msg.client, msg)
	case MessageChannelRemove:
		server.handlePingMessage(msg.client, msg)
	case MessageChannelState:
		server.handleChannelStateMessage(msg.client, msg)
	case MessageUserState:
		server.handleUserStateMessage(msg.client, msg)
	case MessageUserRemove:
		server.handleUserRemoveMessage(msg.client, msg)
	case MessageBanList:
		server.handleBanListMessage(msg.client, msg)
	case MessageTextMessage:
		server.handleTextMessage(msg.client, msg)
	case MessageACL:
		server.handleAclMessage(msg.client, msg)
	case MessageQueryUsers:
		server.handleQueryUsers(msg.client, msg)
	case MessageCryptSetup:
		server.handleCryptSetup(msg.client, msg)
	case MessageContextActionAdd:
		log.Stdoutf("MessageContextActionAdd from client")
	case MessageContextAction:
		log.Stdoutf("MessageContextAction from client")
	case MessageUserList:
		log.Stdoutf("MessageUserList from client")
	case MessageVoiceTarget:
		log.Stdoutf("MessageVoiceTarget from client")
	case MessagePermissionQuery:
		log.Stdoutf("MessagePermissionQuery from client")
	case MessageCodecVersion:
		log.Stdoutf("MessageCodecVersion from client")
	case MessageUserStats:
		server.handleUserStatsMessage(msg.client, msg)
	case MessageRequestBlob:
		log.Stdoutf("MessageRequestBlob from client")
	case MessageServerConfig:
		log.Stdoutf("MessageServerConfig from client")
	}
}

func (server *Server) multiplexer() {
	for {
		_ = <-server.outgoing
		log.Stdoutf("recvd message to multiplex")
	}
}

func (s *Server) SetupUDP() (err os.Error) {
	addr := &net.UDPAddr{
		Port: s.port,
	}
	s.udpconn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return
	}

	return
}

func (s *Server) SendUDP() {
	for {
		msg := <-s.udpsend
		if msg.client != nil {
			// These are to be crypted...
			crypted := make([]byte, len(msg.buf)+4)
			msg.client.crypt.Encrypt(msg.buf, crypted)
			s.udpconn.WriteTo(crypted, msg.client.udpaddr)
		} else if msg.address != nil {
			s.udpconn.WriteTo(msg.buf, msg.address)
		} else {
			// Skipping
		}
	}
}

// Listen for and handle UDP packets.
func (server *Server) ListenUDP() {
	buf := make([]byte, UDPPacketSize)
	for {
		nread, remote, err := server.udpconn.ReadFrom(buf)
		if err != nil {
			// Not much to do here. This is bad, of course. Should we panic this server instance?
			continue
		}

		udpaddr, ok := remote.(*net.UDPAddr)
		if !ok {
			log.Stdoutf("No UDPAddr in read packet. Disabling UDP. (Windows?)")
			return
		}

		// Length 12 is for ping datagrams from the ConnectDialog.
		if nread == 12 {
			readbuf := bytes.NewBuffer(buf)
			var (
				tmp32 uint32
				rand  uint64
			)
			_ = binary.Read(readbuf, binary.BigEndian, &tmp32)
			_ = binary.Read(readbuf, binary.BigEndian, &rand)

			buffer := bytes.NewBuffer(make([]byte, 0, 24))
			_ = binary.Write(buffer, binary.BigEndian, uint32((1<<16)|(2<<8)|2))
			_ = binary.Write(buffer, binary.BigEndian, rand)
			_ = binary.Write(buffer, binary.BigEndian, uint32(server.clients.Len()))
			_ = binary.Write(buffer, binary.BigEndian, uint32(server.MaxUsers))
			_ = binary.Write(buffer, binary.BigEndian, uint32(server.MaxBandwidth))

			server.udpsend <- &Message{
				buf: buffer.Bytes(),
				address: udpaddr,
			}
		} else {
			var match *ClientConnection
			plain := make([]byte, nread-4)
			decrypted := false

			// First, check if any of our clients match the net.UDPAddr...
			server.cmutex.RLock()
			for x := range server.clients.Iter() {
				client := x.(*ClientConnection)
				if client.udpaddr.String() == udpaddr.String() {
					match = client
				}
			}
			server.cmutex.RUnlock()

			// No matching client found. We must try to decrypt...
			if match == nil {
				server.cmutex.RLock()
				for x := range server.clients.Iter() {
					client := x.(*ClientConnection)

					// Try to decrypt.
					err = client.crypt.Decrypt(buf[0:nread], plain[0:])
					if err != nil {
						// Decryption failed. Try another client...
						continue
					}

					// Decryption succeeded.
					decrypted = true

					// If we were able to successfully decrpyt, add
					// the UDPAddr to the ClientConnection struct.
					log.Stdoutf("Client UDP connection established.")
					client.udpaddr = remote.(*net.UDPAddr)
					match = client

					break
				}
				server.cmutex.RUnlock()
			}

			// We were not able to find a client that could decrypt the incoming
			// packet. Log it?
			if match == nil {
				continue
			}

			if !decrypted {
				err = match.crypt.Decrypt(buf[0:nread], plain[0:])
				if err != nil {
					log.Stdoutf("Unable to decrypt from client..")
				}
			}

			match.udp = true
			match.udprecv <- plain
		}
	}
}

// The accept loop of the server.
func (s *Server) ListenAndMurmur() {

	// Setup our UDP listener and spawn our reader and writer goroutines
	s.SetupUDP()
	go s.ListenUDP()
	go s.SendUDP()

	// Create a new listening TLS socket.
	l := NewTLSListener(s.port)
	if l == nil {
		log.Stderrf("Unable to create TLS listener")
		return
	}

	log.Stderrf("Created new Murmur instance on port %v", s.port)

	// The main accept loop. Basically, we block
	// until we get a new client connection, and
	// when we do get a new connection, we spawn
	// a new Go-routine to handle the client.
	for {

		// New client connected
		conn, err := l.Accept()
		if err != nil {
			log.Stderrf("unable to accept()")
		}

		tls, ok := conn.(*tls.Conn)
		if !ok {
			log.Stderrf("Not tls :(")
		}

		// Force the TLS handshake to get going. We'd like
		// this to happen as soon as possible, so we can get
		// at client certificates sooner.
		tls.Handshake()

		// Create a new client connection from our *tls.Conn
		// which wraps net.TCPConn.
		err = s.NewClient(conn)
		if err != nil {
			log.Stderrf("Unable to start new client")
		}

		log.Stdoutf("num clients = %v", s.clients.Len())
	}
}
