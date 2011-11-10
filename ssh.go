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
	CmdFunc      SshCmdFunc
	Args         string
	Description  string
}

func (c SshCmd) Call(reply SshCmdReply, args []string) error {
	return c.CmdFunc(reply, args)
}

var cmdMap = map[string]SshCmd{}

func RegisterSSHCmd(name string, cmdFunc SshCmdFunc, args string, desc string) {
	cmdMap[name] = SshCmd{
		CmdFunc: cmdFunc,
		Args: args,
		Description: desc,
	}
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

				if args[0] == "exit" {
					return
				}

				if cmd, ok := cmdMap[args[0]]; ok {
					buf := new(bytes.Buffer)
					err = cmd.Call(buf, args)
					if err != nil {
						_, err = shell.Write([]byte(fmt.Sprintf("error: %v\r\n", err.Error())))
						if err != nil {
							return
						}
						continue
					}

					_, err = shell.Write(buf.Bytes())
					if err != nil {
						return						
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
	if len(args) == 1 {
		for cmdName, cmd := range cmdMap {
			reply.WriteString("\r\n")
			reply.WriteString(" " + cmdName + " " + cmd.Args + "\r\n")
			reply.WriteString("    " + cmd.Description + "\r\n")
		}
	} else if len(args) > 1 {
		cmdName := args[1]
		if cmd, ok := cmdMap[cmdName]; ok {
			reply.WriteString("\r\n")
			reply.WriteString(" " + cmdName + " " + cmd.Args + "\r\n")
			reply.WriteString("    " + cmd.Description + "\r\n")
		} else {
			return errors.New("no such command name")
		}
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