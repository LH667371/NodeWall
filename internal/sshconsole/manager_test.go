package sshconsole

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestCreateRequiresHostKeyConfirmation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &ssh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(signer)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					_ = channel.Reject(ssh.UnknownChannelType, "test")
				}
			}()
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	manager := NewWithKeyPath(filepath.Join(t.TempDir(), "ssh", "id_ed25519"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = manager.Create(ctx, Credentials{
		NodeID: "node-test",
		Host:   "127.0.0.1",
		Port:   uint16(port),
		User:   "root",
	})
	var confirmation *HostKeyConfirmationError
	if !errors.As(err, &confirmation) || confirmation.Fingerprint == "" {
		t.Fatalf("expected host key confirmation, got %v", err)
	}
	created, err := manager.Create(ctx, Credentials{
		NodeID:      "node-test",
		Host:        "127.0.0.1",
		Port:        uint16(port),
		User:        "root",
		Fingerprint: confirmation.Fingerprint,
	})
	if err != nil {
		t.Fatalf("expected confirmed host key to connect, got %v", err)
	}
	_ = manager.Close(created.Info.ID)
	created, err = manager.Create(ctx, Credentials{
		NodeID: "node-test",
		Host:   "127.0.0.1",
		Port:   uint16(port),
		User:   "root",
	})
	if err != nil {
		t.Fatalf("expected persisted host key to skip confirmation, got %v", err)
	}
	_ = manager.Close(created.Info.ID)
}

func TestValidateCredentialsRequiresPasswordAndPort(t *testing.T) {
	if err := validateCredentials(Credentials{NodeID: "node", Host: "127.0.0.1", User: "root"}); err == nil {
		t.Fatal("expected missing port validation error")
	}
	if err := validateCredentials(Credentials{NodeID: "node", Host: "127.0.0.1", Port: 22, User: "root", Password: "x"}); err != nil {
		t.Fatalf("expected valid credentials, got %v", err)
	}
}
