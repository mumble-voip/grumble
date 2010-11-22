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
	"sync"
	"goprotobuf.googlecode.com/hg/proto"
	"mumbleproto"
	"cryptstate"
)

// The default port a Murmur server listens on
const DefaultPort = 64738
const UDPPacketSize = 1024

const CeltCompatBitstream = -2147483637

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

	incoming       chan *Message
	udpsend        chan *Message
	voicebroadcast chan *VoiceBroadcast

	// Config-related
	MaxUsers     int
	MaxBandwidth uint32

	// Clients
	session uint32
	clients map[uint32]*Client

	// Host, host/port -> client mapping
	hmutex    sync.Mutex
	hclients  map[string][]*Client
	hpclients map[string]*Client

	// Codec information
	AlphaCodec       int32
	BetaCodec        int32
	PreferAlphaCodec bool

	// Channels
	chanid   int
	root     *Channel
	channels map[int]*Channel

	// ACL cache
	aclcache ACLCache
}

// Allocate a new Murmur instance
func NewServer(addr string, port int) (s *Server, err os.Error) {
	s = new(Server)

	s.address = addr
	s.port = port

	s.clients = make(map[uint32]*Client)

	s.hclients = make(map[string][]*Client)
	s.hpclients = make(map[string]*Client)

	s.incoming = make(chan *Message)
	s.udpsend = make(chan *Message)
	s.voicebroadcast = make(chan *VoiceBroadcast)

	s.MaxBandwidth = 300000
	s.MaxUsers = 10

	s.channels = make(map[int]*Channel)

	s.root = s.NewChannel("Root")
	subChan := s.NewChannel("SubChannel")
	s.root.AddChild(subChan)

	s.aclcache = NewACLCache()

	go s.handler()

	return
}

// Called by the server to initiate a new client connection.
func (server *Server) NewClient(conn net.Conn) (err os.Error) {
	client := new(Client)
	addr := conn.RemoteAddr()
	if addr == nil {
		err = os.NewError("Unable to extract address for client.")
		return
	}

	client.tcpaddr = addr.(*net.TCPAddr)
	client.server = server
	client.conn = conn
	client.reader = bufio.NewReader(client.conn)
	client.writer = bufio.NewWriter(client.conn)
	client.state = StateClientConnected

	client.msgchan = make(chan *Message)
	client.udprecv = make(chan []byte)

	client.UserId = -1

	go client.receiver()
	go client.udpreceiver()
	go client.sender()

	return
}

// Remove a disconnected client from the server's
// internal representation.
func (server *Server) RemoveClient(client *Client) {
	server.hmutex.Lock()
	if client.udpaddr != nil {
		host := client.udpaddr.IP.String()
		oldclients := server.hclients[host]
		newclients := []*Client{}
		for _, hostclient := range oldclients {
			if hostclient != client {
				newclients = append(newclients, hostclient)
			}
		}
		server.hclients[host] = newclients
		server.hpclients[client.udpaddr.String()] = nil, false
	}
	server.hmutex.Unlock()

	server.clients[client.Session] = nil, false

	// Remove client from channel
	channel := client.Channel
	channel.RemoveClient(client)

	err := server.broadcastProtoMessage(MessageUserRemove, &mumbleproto.UserRemove{
		Session: proto.Uint32(client.Session),
	})
	if err != nil {
		// server panic
	}
}

// Add a new channel to the server.
func (server *Server) NewChannel(name string) (channel *Channel) {
	channel = NewChannel(server.chanid, name)
	server.channels[channel.Id] = channel
	server.chanid += 1
	return
}

// Remove a channel from the server.
func (server *Server) RemoveChanel(channel *Channel) {
	if channel.Id == 0 {
		log.Printf("Attempted to remove root channel.")
		return
	}
	server.channels[channel.Id] = nil, false
}

// This is the synchronous handler goroutine.
// Important control channel messages are routed through this Goroutine
// to keep server state synchronized.
func (server *Server) handler() {
	for {
		select {
		// Control channel messages
		case msg := <-server.incoming:
			client := msg.client
			if client.state == StateClientAuthenticated {
				server.handleIncomingMessage(client, msg)
			} else if client.state == StateClientSentVersion {
				server.handleAuthenticate(client, msg)
			}
		// Voice broadcast
		case vb := <-server.voicebroadcast:
			log.Printf("VoiceBroadcast!")
			if vb.target == 0 {
				channel := vb.client.Channel
				for _, client := range channel.clients {
					if client != vb.client {
						client.sendUdp(&Message{
							buf:    vb.buf,
							client: client,
						})
					}
				}
			}
		}
	}
}

// Handle a Authenticate protobuf message.
func (server *Server) handleAuthenticate(client *Client, msg *Message) {
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

	// Send CryptState information to the client so it can establish an UDP connection,
	// if it wishes.
	err = client.sendProtoMessage(MessageCryptSetup, &mumbleproto.CryptSetup{
		Key:         client.crypt.RawKey[0:],
		ClientNonce: client.crypt.DecryptIV[0:],
		ServerNonce: client.crypt.EncryptIV[0:],
	})
	if err != nil {
		client.Panic(err.String())
	}

	// Add the client to the connected list
	server.session += 1
	client.Session = server.session
	server.clients[client.Session] = client

	// Add codecs
	client.codecs = auth.CeltVersions
	if len(client.codecs) == 0 {
		log.Printf("Client %i connected without CELT codecs.", client.Session)
	}
	server.updateCodecVersions()

	err = client.sendProtoMessage(MessageCodecVersion, &mumbleproto.CodecVersion{
		Alpha:       proto.Int32(server.AlphaCodec),
		Beta:        proto.Int32(server.BetaCodec),
		PreferAlpha: proto.Bool(server.PreferAlphaCodec),
	})
	if err != nil {
		client.Panic(err.String())
		return
	}

	client.sendChannelList()
	client.state = StateClientAuthenticated

	// Add the client to the host slice for its host address.
	host := client.tcpaddr.IP.String()
	server.hmutex.Lock()
	server.hclients[host] = append(server.hclients[host], client)
	server.hmutex.Unlock()

	// Broadcast the the user entered a channel
	server.root.AddClient(client)

	if client.Username == "SuperUser" {
		client.UserId = 0
	}

	userstate := &mumbleproto.UserState{
		Session:   proto.Uint32(client.Session),
		Name:      proto.String(client.Username),
		ChannelId: proto.Uint32(0),
	}
	if client.UserId >= 0 {
		userstate.UserId = proto.Uint32(uint32(client.UserId))
	}
	if err := client.sendProtoMessage(MessageUserState, userstate); err != nil {
		client.Panic(err.String())
	}

	server.sendUserList(client)

	sync := &mumbleproto.ServerSync{}
	sync.Session = proto.Uint32(client.Session)
	sync.MaxBandwidth = proto.Uint32(server.MaxBandwidth)
	if client.UserId == 0 {
		sync.Permissions = proto.Uint64(uint64(AllPermissions))
	} else {
		server.HasPermission(client, server.root, EnterPermission)
		perm := server.aclcache.GetPermission(client, server.root)
		if !perm.IsCached() {
			client.Panic("Corrupt ACL cache")
			return
		}
		perm.ClearCacheBit()
		sync.Permissions = proto.Uint64(uint64(perm))
	}
	if err = client.sendProtoMessage(MessageServerSync, sync); err != nil {
		client.Panic(err.String())
		return
	}

	err = client.sendProtoMessage(MessageServerConfig, &mumbleproto.ServerConfig{
		AllowHtml:          proto.Bool(true),
		MessageLength:      proto.Uint32(1000),
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

	for _, client := range server.clients {
		for _, codec := range client.codecs {
			codecusers[codec] += 1
		}
	}

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

	if server.PreferAlphaCodec {
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
		log.Printf("Unable to broadcast.")
		return
	}

	log.Printf("CELT codec switch %v %v (PreferAlpha %v)", server.AlphaCodec, server.BetaCodec, server.PreferAlphaCodec)
	return
}

func (server *Server) sendUserList(client *Client) {
	for _, user := range server.clients {
		if user.state != StateClientAuthenticated {
			continue
		}
		if user == client {
			continue
		}

		err := client.sendProtoMessage(MessageUserState, &mumbleproto.UserState{
			Session:   proto.Uint32(user.Session),
			Name:      proto.String(user.Username),
			ChannelId: proto.Uint32(0),
		})

		if err != nil {
			// Server panic?
			continue
		}
	}

}

// Send a client its permissions for channel.
func (server *Server) sendClientPermissions(client *Client, channel *Channel) {
	// No caching for SuperUser
	if client.UserId == 0 {
		return
	}

	// Update cache
	server.HasPermission(client, channel, EnterPermission)

	perm := server.aclcache.GetPermission(client, channel)
	log.Printf("Permissions = 0x%x", perm)

	// fixme(mkrautz): Cache which permissions we've already sent.
	client.sendProtoMessage(MessagePermissionQuery, &mumbleproto.PermissionQuery{
		ChannelId:   proto.Uint32(uint32(channel.Id)),
		Permissions: proto.Uint32(uint32(perm)),
	})
}

func (server *Server) broadcastProtoMessage(kind uint16, msg interface{}) (err os.Error) {
	for _, client := range server.clients {
		if client.state != StateClientAuthenticated {
			continue
		}
		err := client.sendProtoMessage(kind, msg)
		if err != nil {
			return
		}
	}

	return
}

func (server *Server) handleIncomingMessage(client *Client, msg *Message) {
	log.Printf("Handle Incoming Message")
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
		log.Printf("MessageContextActionAdd from client")
	case MessageContextAction:
		log.Printf("MessageContextAction from client")
	case MessageUserList:
		log.Printf("MessageUserList from client")
	case MessageVoiceTarget:
		log.Printf("MessageVoiceTarget from client")
	case MessagePermissionQuery:
		server.handlePermissionQuery(msg.client, msg)
	case MessageCodecVersion:
		log.Printf("MessageCodecVersion from client")
	case MessageUserStats:
		server.handleUserStatsMessage(msg.client, msg)
	case MessageRequestBlob:
		log.Printf("MessageRequestBlob from client")
	case MessageServerConfig:
		log.Printf("MessageServerConfig from client")
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
		// Encrypted
		if msg.client != nil {
			crypted := make([]byte, len(msg.buf)+4)
			msg.client.crypt.Encrypt(crypted, msg.buf)
			s.udpconn.WriteTo(crypted, msg.client.udpaddr)
			// Non-encrypted
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
			log.Printf("No UDPAddr in read packet. Disabling UDP. (Windows?)")
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
			_ = binary.Write(buffer, binary.BigEndian, uint32(len(server.clients)))
			_ = binary.Write(buffer, binary.BigEndian, uint32(server.MaxUsers))
			_ = binary.Write(buffer, binary.BigEndian, uint32(server.MaxBandwidth))

			server.udpsend <- &Message{
				buf:     buffer.Bytes(),
				address: udpaddr,
			}
		} else {
			var match *Client
			plain := make([]byte, nread-4)

			// Determine which client sent the the packet.  First, we
			// check the map 'hpclients' in the server struct. It maps
			// a hort-post combination to a client.
			//
			// If we don't find any matches, we look in the 'hclients',
			// which maps a host address to a slice of clients.
			server.hmutex.Lock()
			client, ok := server.hpclients[udpaddr.String()]
			if ok {
				err = client.crypt.Decrypt(plain[0:], buf[0:nread])
				if err != nil {
					log.Panicf("Unable to decrypt incoming packet for client %v (host-port matched)", client)
				}
				match = client
			} else {
				host := udpaddr.IP.String()
				hostclients := server.hclients[host]
				for _, client := range hostclients {
					err = client.crypt.Decrypt(plain[0:], buf[0:nread])
					if err != nil {
						continue
					} else {
						match = client
					}
				}
				if match != nil {
					match.udpaddr = udpaddr
					server.hpclients[udpaddr.String()] = match
				}
			}
			server.hmutex.Unlock()

			// No client found.
			if match == nil {
				log.Printf("Sender of UDP packet could not be determined. Packet dropped.")
				continue
			}

			match.udp = true
			match.udprecv <- plain
		}
	}
}

// Clear the ACL cache
func (s *Server) ClearACLCache() {
	s.aclcache = NewACLCache()
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
		log.Printf("Unable to create TLS listener")
		return
	}

	log.Printf("Created new Murmur instance on port %v", s.port)

	// The main accept loop. Basically, we block
	// until we get a new client connection, and
	// when we do get a new connection, we spawn
	// a new Go-routine to handle the client.
	for {
		// New client connected
		conn, err := l.Accept()
		if err != nil {
			log.Printf("Unable to accept() new client.")
		}

		tls, ok := conn.(*tls.Conn)
		if !ok {
			log.Panic("Internal inconsistency error.")
		}

		// Force the TLS handshake to get going. We'd like
		// this to happen as soon as possible, so we can get
		// at client certificates sooner.
		tls.Handshake()

		// Create a new client connection from our *tls.Conn
		// which wraps net.TCPConn.
		err = s.NewClient(conn)
		if err != nil {
			log.Printf("Unable to start new client")
		}

		log.Printf("num clients = %v", len(s.clients))
	}
}
