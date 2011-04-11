// Copyright (c) 2010-2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"log"
	"crypto/tls"
	"crypto/sha1"
	"os"
	"net"
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"goprotobuf.googlecode.com/hg/proto"
	"mumbleproto"
	"cryptstate"
	"hash"
	"rand"
	"strings"
)

// The default port a Murmur server listens on
const DefaultPort = 64738
const UDPPacketSize = 1024

const CeltCompatBitstream = -2147483637
const (
	StateClientConnected = iota
	StateServerSentVersion
	StateClientSentVersion
	StateClientAuthenticated
	StateClientReady
	StateClientDead
)

// A Murmur server instance
type Server struct {
	Id       int64
	listener tls.Listener
	address  string
	port     int
	udpconn  *net.UDPConn

	incoming       chan *Message
	udpsend        chan *Message
	voicebroadcast chan *VoiceBroadcast

	// Signals to the server that a client has been successfully
	// authenticated.
	clientAuthenticated chan *Client

	// Config-related
	MaxUsers     int
	MaxBandwidth uint32

	// Clients
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
	Channels map[int]*Channel

	// Users
	superUserPassword string
	Users             map[uint32]*User
	UserCertMap       map[string]*User
	UserNameMap       map[string]*User

	// ACL cache
	aclcache ACLCache
}

// Allocate a new Murmur instance
func NewServer(id int64, addr string, port int) (s *Server, err os.Error) {
	s = new(Server)

	s.Id = id
	s.address = addr
	s.port = port

	s.clients = make(map[uint32]*Client)
	s.Users = make(map[uint32]*User)
	s.UserCertMap = make(map[string]*User)
	s.UserNameMap = make(map[string]*User)

	s.hclients = make(map[string][]*Client)
	s.hpclients = make(map[string]*Client)

	s.incoming = make(chan *Message)
	s.udpsend = make(chan *Message)
	s.voicebroadcast = make(chan *VoiceBroadcast)
	s.clientAuthenticated = make(chan *Client)

	s.MaxBandwidth = 300000
	s.MaxUsers = 10

	s.Channels = make(map[int]*Channel)
	s.root = s.NewChannel(0, "Root")
	s.aclcache = NewACLCache()

	return
}

// Check whether password matches the set SuperUser password.
func (server *Server) CheckSuperUserPassword(password string) bool {
	parts := strings.Split(server.superUserPassword, "$", -1)
	if len(parts) != 3 {
		return false
	}

	if len(parts[2]) == 0 {
		return false
	}

	var h hash.Hash
	switch parts[0] {
	case "sha1":
		h = sha1.New()
	default:
		// no such hash
		return false
	}

	// salt
	if len(parts[1]) > 0 {
		h.Write([]byte(parts[1]))
	}

	// password
	h.Write([]byte(password))

	sum := hex.EncodeToString(h.Sum())
	if parts[2] == sum {
		return true
	}

	return false
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

	client.user = nil

	go client.receiver()
	go client.udpreceiver()

	client.doneSending = make(chan bool)
	go client.sender()

	return
}

// Remove a disconnected client from the server's
// internal representation.
func (server *Server) RemoveClient(client *Client, kicked bool) {
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
	if channel != nil {
		channel.RemoveClient(client)
	}

	// If the user was not kicked, broadcast a UserRemove message.
	// If the user is disconnect via a kick, the UserRemove message has already been sent
	// at this point.
	if !kicked && client.state > StateClientAuthenticated {
		err := server.broadcastProtoMessage(MessageUserRemove, &mumbleproto.UserRemove{
			Session: proto.Uint32(client.Session),
		})
		if err != nil {
			log.Panic("Unable to broadcast UserRemove message for disconnected client.")
		}
	}
}

// Add an existing channel to the Server. (Do not arbitrarily pick an ID)
func (server *Server) NewChannel(id int, name string) (channel *Channel) {
	_, exists := server.Channels[id]
	if exists {
		// fime(mkrautz): Handle duplicates
		return nil
	}

	channel = NewChannel(id, name)
	server.Channels[id] = channel

	if id > server.chanid {
		server.chanid = id + 1
	}

	return
}

// Add a new channel to the server. Automatically assign it a channel ID.
func (server *Server) AddChannel(name string) (channel *Channel) {
	channel = NewChannel(server.chanid, name)
	server.Channels[channel.Id] = channel
	return
}

// Remove a channel from the server.
func (server *Server) RemoveChanel(channel *Channel) {
	if channel.Id == 0 {
		log.Printf("Attempted to remove root channel.")
		return
	}
	server.Channels[channel.Id] = nil, false
}

// Link two channels
func (server *Server) LinkChannels(channel *Channel, other *Channel) {
	channel.Links[other.Id] = other
	other.Links[channel.Id] = channel
}

// Unlink two channels
func (server *Server) UnlinkChannels(channel *Channel, other *Channel) {
	channel.Links[other.Id] = nil, false
	other.Links[channel.Id] = nil, false
}

// Generate a random, valid session ID.
// The returned session ID is guaranteed not to currently be in use
// on the server, and not to be the zero-value for integers (0).
func (server *Server) GenSessionId() (session uint32) {
	for {
		session = rand.Uint32()

		// The 0 session is disallowed in Grumble. 0 is the zero-value for
		// integer types, and as such, an uninitialized session id could
		// point to a valid client if we allowed the 0 session id.
		if session == 0 {
			continue
		}

		// Is there already a client on the sever with the generated id?
		// Give us a new one, please.
		if _, exists := server.clients[session]; exists {
			continue
		}

		break
	}

	return
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
			server.handleIncomingMessage(client, msg)
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
		// Finish client authentication. Send post-authentication
		// server info.
		case client := <-server.clientAuthenticated:
			server.finishAuthenticate(client)
		}
	}
}

// Handle an Authenticate protobuf message.  This is handled in a separate
// goroutine to allow for remote authenticators that are slow to respond.
//
// Once a user has been authenticated, it will ping the server's handler
// routine, which will call the finishAuthenticate method on Server which
// will send the channel tree, user list, etc. to the client.
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
		client.RejectAuth("InvalidUsername", "Please specify a username to log in")
		return
	}

	client.Username = *auth.Username

	// Extract certhash
	tlsconn, ok := client.conn.(*tls.Conn)
	if !ok {
		client.Panic("Invalid connection")
		return
	}
	state := tlsconn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		hash := sha1.New()
		hash.Write(state.PeerCertificates[0].Raw)
		sum := hash.Sum()
		client.CertHash = hex.EncodeToString(sum)
	}

	if client.Username == "SuperUser" {
		if auth.Password == nil {
			client.RejectAuth("WrongUserPW", "")
			return
		} else {
			if server.CheckSuperUserPassword(*auth.Password) {
				client.superUser = true
			} else {
				client.RejectAuth("WrongUserPW", "")
				return
			}
		}
	} else {
		// First look up registration by name.
		user, exists := server.UserNameMap[client.Username]
		if exists {
			if user.CertHash == client.CertHash {
				client.user = user
			} else {
				client.Panic("Invalid cert hash for user")
				return
			}
		}

		// Name matching didn't do.  Try matching by certificate.
		if client.user == nil {
			user, exists := server.UserCertMap[client.CertHash]
			if exists {
				client.user = user
			}
		}
	}

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

	// Add codecs
	client.codecs = auth.CeltVersions
	if len(client.codecs) == 0 {
		log.Printf("Client %i connected without CELT codecs.", client.Session)
	}

	client.state = StateClientAuthenticated
	server.clientAuthenticated <- client
}

// The last part of authentication runs in the server's synchronous handler.
func (server *Server) finishAuthenticate(client *Client) {
	// If the client succeeded in proving to the server that it should be granted
	// the credentials of a registered user, do some sanity checking to make sure
	// that user isn't already connected.
	//
	// If the user is already connected, try to check whether this new client is
	// connecting from the same IP address. If that's the case, disconnect the
	// previous client and let the new guy in.
	if client.user != nil {
		found := false
		for _, connectedClient := range server.clients {
			if connectedClient.UserId() == client.UserId() {
				found = true
				break
			}
		}
		// The user is already present on the server.
		if found {
			// todo(mkrautz): Do the address checking.
			client.RejectAuth("UsernameInUse", "A client is already connected using those credentials.")
			return
		}

		// No, that user isn't already connected. Move along.
	}

	// Add the client to the connected list
	client.Session = server.GenSessionId()
	server.clients[client.Session] = client

	// First, check whether we need to tell the other connected
	// clients to switch to a codec so the new guy can actually speak.
	server.updateCodecVersions()

	client.sendChannelList()

	// Add the client to the host slice for its host address.
	host := client.tcpaddr.IP.String()
	server.hmutex.Lock()
	server.hclients[host] = append(server.hclients[host], client)
	server.hmutex.Unlock()

	userstate := &mumbleproto.UserState{
		Session:   proto.Uint32(client.Session),
		Name:      proto.String(client.ShownName()),
		ChannelId: proto.Uint32(0),
	}
	if client.IsRegistered() {
		userstate.UserId = proto.Uint32(uint32(client.UserId()))

		if client.user.HasTexture() {
			// Does the client support blobs?
			if client.Version >= 0x10203 {
				userstate.TextureHash = client.user.TextureBlobHashBytes()
			} else {
				buf, err := globalBlobstore.Get(client.user.TextureBlob)
				if err != nil {
					log.Panicf("Blobstore error: %v", err.String())
				}
				userstate.Texture = buf
			}
		}

		if client.user.HasComment() {
			// Does the client support blobs?
			if client.Version >= 0x10203 {
				userstate.CommentHash = client.user.CommentBlobHashBytes()
			} else {
				buf, err := globalBlobstore.Get(client.user.CommentBlob)
				if err != nil {
					log.Panicf("Blobstore error: %v", err.String())
				}
				userstate.Comment = proto.String(string(buf))
			}
		}
	}

	server.userEnterChannel(client, server.root, userstate)
	if err := server.broadcastProtoMessage(MessageUserState, userstate); err != nil {
		// Server panic?
	}

	server.sendUserList(client)

	sync := &mumbleproto.ServerSync{}
	sync.Session = proto.Uint32(client.Session)
	sync.MaxBandwidth = proto.Uint32(server.MaxBandwidth)
	if client.IsSuperUser() {
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
	if err := client.sendProtoMessage(MessageServerSync, sync); err != nil {
		client.Panic(err.String())
		return
	}

	err := client.sendProtoMessage(MessageServerConfig, &mumbleproto.ServerConfig{
		AllowHtml:          proto.Bool(true),
		MessageLength:      proto.Uint32(1000),
		ImageMessageLength: proto.Uint32(1000),
	})
	if err != nil {
		client.Panic(err.String())
		return
	}

	client.state = StateClientReady
	client.clientReady <- true
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
		if users == count && codec > winner {
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

	log.Printf("CELT codec switch %#x %#x (PreferAlpha %v)", uint32(server.AlphaCodec), uint32(server.BetaCodec), server.PreferAlphaCodec)
	return
}

func (server *Server) sendUserList(client *Client) {
	for _, connectedClient := range server.clients {
		if connectedClient.state != StateClientReady {
			continue
		}
		if connectedClient == client {
			continue
		}

		userstate := &mumbleproto.UserState{
			Session:   proto.Uint32(connectedClient.Session),
			Name:      proto.String(connectedClient.ShownName()),
			ChannelId: proto.Uint32(uint32(connectedClient.Channel.Id)),
		}

		if connectedClient.IsRegistered() {
			userstate.UserId = proto.Uint32(uint32(connectedClient.UserId()))

			if connectedClient.user.HasTexture() {
				// Does the client support blobs?
				if client.Version >= 0x10203 {
					userstate.TextureHash = connectedClient.user.TextureBlobHashBytes()
				} else {
					buf, err := globalBlobstore.Get(connectedClient.user.TextureBlob)
					if err != nil {
						log.Panicf("Blobstore error: %v", err.String())
					}
					userstate.Texture = buf
				}
			}

			if connectedClient.user.HasComment() {
				// Does the client support blobs?
				if client.Version >= 0x10203 {
					userstate.CommentHash = connectedClient.user.CommentBlobHashBytes()
				} else {
					buf, err := globalBlobstore.Get(connectedClient.user.CommentBlob)
					if err != nil {
						log.Panicf("Blobstore error: %v", err.String())
					}
					userstate.Comment = proto.String(string(buf))
				}
			}

			if len(connectedClient.user.CertHash) > 0 {
				userstate.Hash = proto.String(connectedClient.user.CertHash)
			}
		}

		if connectedClient.Mute {
			userstate.Mute = proto.Bool(true)
		}
		if connectedClient.Suppress {
			userstate.Suppress = proto.Bool(true)
		}
		if connectedClient.SelfMute {
			userstate.SelfMute = proto.Bool(true)
		}
		if connectedClient.SelfDeaf {
			userstate.SelfDeaf = proto.Bool(true)
		}
		if connectedClient.PrioritySpeaker {
			userstate.PrioritySpeaker = proto.Bool(true)
		}
		if connectedClient.Recording {
			userstate.Recording = proto.Bool(true)
		}
		if connectedClient.PluginContext != nil || len(connectedClient.PluginContext) > 0 {
			userstate.PluginContext = connectedClient.PluginContext
		}
		if len(connectedClient.PluginIdentity) > 0 {
			userstate.PluginIdentity = proto.String(connectedClient.PluginIdentity)
		}

		err := client.sendProtoMessage(MessageUserState, userstate)
		if err != nil {
			// Server panic?
			continue
		}
	}
}

// Send a client its permissions for channel.
func (server *Server) sendClientPermissions(client *Client, channel *Channel) {
	// No caching for SuperUser
	if client.IsSuperUser() {
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

type ClientPredicate func(client *Client) bool

func (server *Server) broadcastProtoMessageWithPredicate(kind uint16, msg interface{}, clientcheck ClientPredicate) (err os.Error) {
	for _, client := range server.clients {
		if !clientcheck(client) {
			continue
		}
		if client.state < StateClientAuthenticated {
			continue
		}
		err := client.sendProtoMessage(kind, msg)
		if err != nil {
			return
		}
	}

	return
}

func (server *Server) broadcastProtoMessage(kind uint16, msg interface{}) (err os.Error) {
	err = server.broadcastProtoMessageWithPredicate(kind, msg, func(client *Client) bool { return true })
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
		server.handleRequestBlob(msg.client, msg)
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

// Helper method for users entering new channels
func (server *Server) userEnterChannel(client *Client, channel *Channel, userstate *mumbleproto.UserState) {
	if client.Channel == channel {
		return
	}

	oldchan := client.Channel
	if oldchan != nil {
		oldchan.RemoveClient(client)
	}
	channel.AddClient(client)

	server.ClearACLCache()
	// fixme(mkrautz): Set LastChannel for user in datastore
	// fixme(mkrautz): Remove channel if temporary

	canspeak := server.HasPermission(client, channel, SpeakPermission)
	if canspeak == client.Suppress {
		client.Suppress = !canspeak
		userstate.Suppress = proto.Bool(client.Suppress)
	}

	server.sendClientPermissions(client, channel)
	if channel.parent != nil {
		server.sendClientPermissions(client, channel.parent)
	}
}

// The accept loop of the server.
func (s *Server) ListenAndMurmur() {
	// Launch the event handler goroutine
	go s.handler()

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
