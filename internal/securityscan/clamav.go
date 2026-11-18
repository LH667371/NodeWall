package securityscan

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nodewall/internal/clamav"
)

// SignatureEngineStatus describes the optional external engine separately
// from NodeWall's built-in heuristics. A missing engine is never a clean scan.
type SignatureEngineStatus struct {
	Name         string `json:"name"`
	Status       string `json:"status"`
	Version      string `json:"version,omitempty"`
	FilesScanned uint64 `json:"files_scanned,omitempty"`
	BytesScanned uint64 `json:"bytes_scanned,omitempty"`
	Error        string `json:"error,omitempty"`
	UpdateSource string `json:"update_source,omitempty"`
	UpdateError  string `json:"update_error,omitempty"`
	UpdatedAt    string `json:"updated_at,omitempty"`
}

type clamAVEngine struct {
	socket string
	status SignatureEngineStatus
}

func newClamAVEngine(ctx context.Context, socket string) *clamAVEngine {
	engine := &clamAVEngine{socket: strings.TrimSpace(socket), status: SignatureEngineStatus{Name: "ClamAV", Status: "not-configured"}}
	if clamav.Managed() && engine.socket == clamav.SocketPath() {
		update := clamav.ReadUpdateStatus()
		engine.status.UpdateSource = update.Source
		engine.status.UpdateError = update.Error
		if !update.LastSuccess.IsZero() {
			engine.status.UpdatedAt = update.LastSuccess.Format(time.RFC3339)
		}
	}
	if engine.socket == "" {
		return engine
	}
	if !filepath.IsAbs(engine.socket) {
		engine.fail(errors.New("ClamAV socket must be an absolute local path"))
		return engine
	}
	info, err := os.Stat(engine.socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		engine.fail(errors.New("configured ClamAV socket is unavailable"))
		return engine
	}
	conn, err := engine.connect(ctx)
	if err != nil {
		engine.fail(err)
		return engine
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if _, err = io.WriteString(conn, "zVERSION\x00"); err == nil {
		engine.status.Version, err = readClamAVReply(conn)
	}
	if err != nil || !strings.HasPrefix(engine.status.Version, "ClamAV ") {
		if err == nil {
			err = errors.New("invalid ClamAV version response")
		}
		engine.fail(err)
		return engine
	}
	engine.status.Status = "available"
	return engine
}

func (e *clamAVEngine) connect(ctx context.Context) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", e.socket)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(60 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func readClamAVReply(conn net.Conn) (string, error) {
	reply, err := bufio.NewReader(io.LimitReader(conn, 4097)).ReadString(0)
	if err != nil {
		return "", err
	}
	if len(reply) > 4096 {
		return "", errors.New("ClamAV response exceeds limit")
	}
	return strings.TrimSpace(strings.TrimSuffix(reply, "\x00")), nil
}

func (e *clamAVEngine) fail(err error) {
	e.status.Status = "failed"
	e.status.Error = err.Error()
}

// scan streams the already-open inode, then compares its bytes with the
// heuristic pass. A pathname swap or a changed file cannot inherit a verdict.
func (e *clamAVEngine) scan(ctx context.Context, file *os.File, info os.FileInfo, expectedHash string) (string, error) {
	if e == nil || e.status.Status != "available" {
		return "", nil
	}
	hasher := sha256.New()
	signature, err := e.scanStream(ctx, io.TeeReader(io.NewSectionReader(file, 0, info.Size()), hasher))
	if err != nil {
		return "", err
	}
	current, err := file.Stat()
	if err != nil || current.Size() != info.Size() || !current.ModTime().Equal(info.ModTime()) || hex.EncodeToString(hasher.Sum(nil)) != expectedHash {
		return "", errors.New("file changed during ClamAV scanning")
	}
	return signature, nil
}

// scanSample is used for a bounded, already captured script or startup file.
// Containment still verifies its original inode and hash before acting.
func (e *clamAVEngine) scanSample(ctx context.Context, sample []byte) (string, error) {
	if e == nil || e.status.Status != "available" {
		return "", nil
	}
	return e.scanStream(ctx, bytes.NewReader(sample))
}

func (e *clamAVEngine) scanStream(ctx context.Context, reader io.Reader) (string, error) {
	conn, err := e.connect(ctx)
	if err != nil {
		e.fail(err)
		return "", err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if _, err = io.WriteString(conn, "zINSTREAM\x00"); err != nil {
		e.fail(err)
		return "", err
	}
	buffer := make([]byte, 64<<10)
	var prefix [4]byte
	for {
		if err = ctx.Err(); err != nil {
			e.fail(err)
			return "", err
		}
		n, readErr := reader.Read(buffer)
		if n > 0 {
			e.status.BytesScanned += uint64(n)
			binary.BigEndian.PutUint32(prefix[:], uint32(n))
			if err = writeClamAVBytes(conn, prefix[:]); err == nil {
				err = writeClamAVBytes(conn, buffer[:n])
			}
			if err != nil {
				e.fail(err)
				return "", err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			e.fail(readErr)
			return "", readErr
		}
	}
	binary.BigEndian.PutUint32(prefix[:], 0)
	if err = writeClamAVBytes(conn, prefix[:]); err != nil {
		e.fail(err)
		return "", err
	}
	reply, err := readClamAVReply(conn)
	if err != nil {
		e.fail(err)
		return "", err
	}
	if reply == "stream: OK" {
		e.status.FilesScanned++
		return "", nil
	}
	if strings.HasPrefix(reply, "stream: ") && strings.HasSuffix(reply, " FOUND") {
		signature := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(reply, "stream: "), " FOUND"))
		if signature != "" && len(signature) <= 256 && !strings.ContainsAny(signature, "\r\n\x00") {
			e.status.FilesScanned++
			return signature, nil
		}
	}
	err = fmt.Errorf("ClamAV did not scan file: %s", reply)
	e.fail(err)
	return "", err
}

func writeClamAVBytes(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
