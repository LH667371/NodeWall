package integration

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"nodewall/internal/cli"
	"nodewall/internal/sshactivity"
)

func TestSFTPGuardHelperProcess(t *testing.T) {
	if os.Getenv("NODEWALL_TEST_SFTP_GUARD") != "1" {
		return
	}
	cli.MustRun([]string{"sftp-guard", "--scan-uploads=true", "--audit-transfers=true", "--activity-log=" + os.Getenv("NODEWALL_SFTP_TEST_LOG")})
	os.Exit(0)
}

// This exercises an encrypted SSH subsystem and the actual CLI helper process.
// Authentication uses ephemeral keys; no host sshd service/configuration is touched.
func TestSSHSubsystemUploadGuardEndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.php")
	journal := filepath.Join(dir, "activity.log")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, hostKey, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostKey)
	_, clientKey, _ := ed25519.GenerateKey(rand.Reader)
	clientSigner, _ := ssh.NewSignerFromKey(clientKey)
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if string(key.Marshal()) != string(clientSigner.PublicKey().Marshal()) {
			return nil, errors.New("unknown test key")
		}
		return nil, nil
	}}
	config.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		server, channels, requests, err := ssh.NewServerConn(conn, config)
		if err != nil {
			done <- err
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		for incoming := range channels {
			if incoming.ChannelType() != "session" {
				_ = incoming.Reject(ssh.UnknownChannelType, "session only")
				continue
			}
			channel, requests, err := incoming.Accept()
			if err != nil {
				done <- err
				return
			}
			for request := range requests {
				var subsystem struct{ Name string }
				if request.Type != "subsystem" || ssh.Unmarshal(request.Payload, &subsystem) != nil || subsystem.Name != "sftp" {
					_ = request.Reply(false, nil)
					continue
				}
				_ = request.Reply(true, nil)
				command := exec.Command(os.Args[0], "-test.run=^TestSFTPGuardHelperProcess$")
				command.Env = append(os.Environ(), "NODEWALL_TEST_SFTP_GUARD=1", "NODEWALL_SFTP_TEST_LOG="+journal, "NODEWALL_SSH_SESSION_ID=encrypted-session", "SSH_CONNECTION=127.0.0.1 12345 127.0.0.1 22", "USER=root")
				command.Stdin, command.Stdout, command.Stderr = channel, channel, channel.Stderr()
				err := command.Run()
				code := uint32(0)
				if err != nil {
					code = 1
				}
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{code}))
				_ = channel.Close()
				done <- err
				return
			}
		}
	}()
	client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.PublicKeys(clientSigner)}, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if string(key.Marshal()) != string(hostSigner.PublicKey().Marshal()) {
			return errors.New("test host key mismatch")
		}
		return nil
	}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	files, err := sftp.NewClient(client)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	file, err := files.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("<?php eval(base64_decode($_POST['x'])); ?>")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err == nil {
		t.Fatal("SSH helper accepted malicious file")
	}
	if data, _ := os.ReadFile(path); string(data) != "original" {
		t.Fatal("SSH transfer destroyed original")
	}
	file, err = files.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("checked replacement")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	files.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SFTP helper did not shut down")
	}
	records, err := sshactivity.ReadFiltered(journal, 100, sshactivity.Filter{SessionID: "encrypted-session", Event: "upload_scan"})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].ScanStatus != "clean" || records[1].ScanStatus != "suspicious" {
		t.Fatalf("SSH helper audit is incomplete: %#v", records)
	}
}
