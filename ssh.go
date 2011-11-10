package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"exp/ssh"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
)

func passwordAuth(username, password string) bool {
	if username == "admin" && password == "admin" {
		return true
	}
	return false
}

type SshCmdReply interface {
	WriteString(s string) (int, error)
}

type SshCmdFunc func(reply SshCmdReply, args []string) error

type SshCmd struct {
	Name        string
	CmdFunc     SshCmdFunc
	Args        string
	Description string
}

func (c SshCmd) Call(reply SshCmdReply, args []string) error {
	return c.CmdFunc(reply, args)
}

var commands = []SshCmd{}

func RegisterSSHCmd(name string, cmdFunc SshCmdFunc, args string, desc string) {
	commands = append(commands, SshCmd{
		Name:        name,
		CmdFunc:     cmdFunc,
		Args:        args,
		Description: desc,
	})
}

func RunSSH() {
	RegisterSSHCmd("help",
		HelpCmd,
		"[cmd]",
		"Shows this help (or help for a given command)")
	RegisterSSHCmd("start",
		StartServerCmd,
		"<id>",
		"Starts the server with the given id")
	RegisterSSHCmd("stop",
		StopServerCmd,
		"<id>",
		"Stops the server with the given id")
	RegisterSSHCmd("supw",
		SetSuperUserPasswordCmd,
		"<id> <password>",
		"Set the SuperUser password for server with the given id")
	RegisterSSHCmd("setconf",
		SetConfCmd,
		"<id> <key> <value>",
		"Set a config value for the server with the given id")
	RegisterSSHCmd("getconf",
		GetConfCmd,
		"<id> <key> <value>",
		"Get a config value for the server with the given id")

	pemBytes, err := ioutil.ReadFile(filepath.Join(Args.DataDir, "key.pem"))
	if err != nil {
		log.Fatal(err)
	}

	cfg := new(ssh.ServerConfig)
	cfg.Rand = rand.Reader
	cfg.PasswordCallback = passwordAuth
	cfg.SetRSAPrivateKey(pemBytes)

	listener, err := ssh.Listen("tcp", Args.SshAddr, cfg)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Listening for SSH connections on '%v'", Args.SshAddr)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Fatalf("ssh: unable to accept incoming connection: %v", err)
			}

			err = conn.Handshake()
			if err == io.EOF {
				continue
			} else if err != nil {
				log.Fatalf("ssh: unable to perform handshake: %v", err)
			}

			go func() {
				for {
					channel, err := conn.Accept()
					if err == io.EOF {
						return
					} else if err != nil {
						log.Fatalf("ssh: unable to accept channel: %v", err)
					}

					go handleChannel(channel)
				}
			}()
		}
	}()
}

func handleChannel(channel ssh.Channel) {
	if channel.ChannelType() == "session" {
		channel.Accept()
		shell := ssh.NewServerShell(channel, "G> ")
		go func() {
			defer channel.Close()
			for {
				line, err := shell.ReadLine()
				if err == io.EOF {
					break
				} else if err != nil {
					log.Printf("ssh: error in reading from channel: %v", err)
					break
				}

				line = strings.TrimSpace(line)
				args := strings.Split(line, " ")

				if len(args) < 1 {
					continue
				}

				if args[0] == "exit" || args[0] == "quit" {
					return
				}

				var cmd *SshCmd
				for i := range commands {
					if commands[i].Name == args[0] {
						cmd = &commands[i]
						break
					}
				}
				if cmd != nil {
					buf := new(bytes.Buffer)
					err = cmd.Call(buf, args)
					if err != nil {
						_, err = shell.Write([]byte(fmt.Sprintf("error: %v\r\n", err.Error())))
						if err != nil {
							return
						}
						continue
					}

					bufBytes := buf.Bytes()
					chunkSize := int(64)
					for len(bufBytes) > 0 {
						if len(bufBytes) < chunkSize {
							chunkSize = len(bufBytes)
						}
						nwritten, err := shell.Write(bufBytes[0:chunkSize])
						if err != nil {
							return
						}
						bufBytes = bufBytes[nwritten:]
					}
				} else {
					_, err = shell.Write([]byte("error: unknown command\r\n"))
				}
			}
		}()
		return
	}

	channel.Reject(ssh.UnknownChannelType, "unknown channel type")
}

func HelpCmd(reply SshCmdReply, args []string) error {
	onlyShow := ""
	didShow := false
	if len(args) > 1 {
		onlyShow = args[1]
	}

	for _, cmd := range commands {
		if cmd.Name == onlyShow || onlyShow == "" {
			reply.WriteString("\r\n")
			reply.WriteString(" " + cmd.Name + " " + cmd.Args + "\r\n")
			reply.WriteString("    " + cmd.Description + "\r\n")
			didShow = true
		}
	}
	if onlyShow != "" && !didShow {
		return errors.New("no such command")
	}
	reply.WriteString("\r\n")

	return nil
}

func StartServerCmd(reply SshCmdReply, args []string) error {
	return errors.New("not implemented")
}

func StopServerCmd(reply SshCmdReply, args []string) error {
	return errors.New("not implemented")
}

func SetSuperUserPasswordCmd(reply SshCmdReply, args []string) error {
	return errors.New("not implemented")
}

func SetConfCmd(reply SshCmdReply, args []string) error {
	return errors.New("not implemented")
}

func GetConfCmd(reply SshCmdReply, args []string) error {
	return errors.New("not implemented")
}
