package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/pkg/sftp"
	"github.com/quic-go/webtransport-go"
	"golang.org/x/crypto/ssh"

	"nodewall/internal/models"
	"nodewall/internal/security"
	"nodewall/internal/securityscan"
	"nodewall/internal/service"
	"nodewall/internal/sshconsole"
)

const maxSSHUploadSize = 32 << 20

var sshTerminalUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin == "" {
			return true
		}
		return strings.EqualFold(origin, requestOrigin(r))
	},
}

func requestOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

type sshSessionRequest struct {
	Host        string `json:"host"`
	Port        uint16 `json:"port"`
	User        string `json:"user"`
	Fingerprint string `json:"fingerprint"`
}

type terminalMessage struct {
	Type string `json:"type"`
	Data string `json:"data"`
	Rows uint32 `json:"rows"`
	Cols uint32 `json:"cols"`
}

type terminalOutput struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Code int    `json:"code,omitempty"`
}

type terminalTransport struct {
	ctx       context.Context
	readJSON  func(any) error
	writeJSON func(any) error
}

func (h *ServerHandler) handleSSHSessionCreate(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("node"))
	node, ok := service.FindNode(h.service.ListNodes(r.Context()), nodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	var req sshSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Host == "" && node.SSH != nil {
		req.Host = node.SSH.Host
	}
	if req.Port == 0 && node.SSH != nil {
		req.Port = node.SSH.Port
	}
	if req.User == "" && node.SSH != nil {
		req.User = node.SSH.User
	}
	profile, err := normalizeSSHConnectionProfile(models.SSHConnectionProfile{
		Host: req.Host,
		Port: req.Port,
		// The web console is intentionally root-only. The node's SSH key is
		// provisioned for root and accepting another user here would make the
		// UI appear connected while using credentials that cannot work.
		User: "root",
	}, node)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	owner := ""
	if h.auth != nil && h.auth.enabled {
		current, ok := h.auth.sessionFromRequest(r)
		if !ok || security.NormalizeRole(current.Role) == security.RoleViewer {
			writeError(w, http.StatusForbidden, errors.New("SSH console requires an operator account"))
			return
		}
		owner = current.Username
	}
	session, err := h.sshConsole.Create(r.Context(), sshconsole.Credentials{
		Owner:       owner,
		NodeID:      nodeID,
		Host:        profile.Host,
		Port:        profile.Port,
		User:        profile.User,
		Fingerprint: req.Fingerprint,
	})
	if err != nil {
		var confirmation *sshconsole.HostKeyConfirmationError
		if errors.As(err, &confirmation) {
			writeJSON(w, http.StatusConflict, map[string]any{
				"code":        "SSH_HOST_KEY_CONFIRMATION_REQUIRED",
				"fingerprint": confirmation.Fingerprint,
				"error":       "首次连接需要确认 SSH 主机指纹",
			})
			return
		}
		var mismatch *sshconsole.HostKeyMismatchError
		if errors.As(err, &mismatch) {
			writeJSON(w, http.StatusConflict, map[string]any{
				"code":        "SSH_HOST_KEY_MISMATCH",
				"fingerprint": mismatch.Actual,
				"error":       mismatch.Error(),
			})
			return
		}
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusCreated, session.Info)
}

func (h *ServerHandler) handleSSHPublicKey(w http.ResponseWriter, _ *http.Request) {
	publicKey, err := h.sshConsole.PublicKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"public_key": publicKey})
}

func (h *ServerHandler) handleSSHSessionDelete(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorizedSSHSession(w, r); !ok {
		return
	}
	if err := h.sshConsole.Close(r.PathValue("session")); err != nil && !errors.Is(err, sshconsole.ErrSessionNotFound) {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ServerHandler) handleSSHTerminal(w http.ResponseWriter, r *http.Request) {
	session, ok := h.authorizedSSHSession(w, r)
	if !ok {
		return
	}
	conn, err := sshTerminalUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	h.serveSSHTerminal(terminalTransport{
		ctx:       r.Context(),
		readJSON:  conn.ReadJSON,
		writeJSON: conn.WriteJSON,
	}, session)
}

func (h *ServerHandler) handleSSHWebTransportTerminal(w http.ResponseWriter, r *http.Request, transport *webtransport.Server) {
	session, ok := h.authorizedSSHSession(w, r)
	if !ok {
		return
	}
	webSession, err := transport.Upgrade(w, r)
	if err != nil {
		// A failed WebTransport handshake should leave the WSS endpoint usable.
		http.Error(w, "webtransport unavailable", http.StatusBadRequest)
		return
	}
	stream, err := webSession.AcceptStream(webSession.Context())
	if err != nil {
		_ = webSession.CloseWithError(0, "terminal stream unavailable")
		return
	}
	defer stream.Close()
	defer webSession.CloseWithError(0, "")

	decoder := json.NewDecoder(stream)
	encoder := json.NewEncoder(stream)
	h.serveSSHTerminal(terminalTransport{
		ctx:       webSession.Context(),
		readJSON:  decoder.Decode,
		writeJSON: encoder.Encode,
	}, session)
}

func (h *ServerHandler) serveSSHTerminal(transport terminalTransport, session *sshconsole.Session) {

	sshSession, err := session.Client.NewSession()
	if err != nil {
		_ = transport.writeJSON(terminalOutput{Type: "error", Data: err.Error()})
		return
	}
	defer sshSession.Close()
	if err := sshSession.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		_ = transport.writeJSON(terminalOutput{Type: "error", Data: fmt.Sprintf("request PTY: %v", err)})
		return
	}
	stdin, err := sshSession.StdinPipe()
	if err != nil {
		_ = transport.writeJSON(terminalOutput{Type: "error", Data: err.Error()})
		return
	}
	stdout, err := sshSession.StdoutPipe()
	if err != nil {
		_ = transport.writeJSON(terminalOutput{Type: "error", Data: err.Error()})
		return
	}
	stderr, err := sshSession.StderrPipe()
	if err != nil {
		_ = transport.writeJSON(terminalOutput{Type: "error", Data: err.Error()})
		return
	}
	if err := sshSession.Shell(); err != nil {
		_ = transport.writeJSON(terminalOutput{Type: "error", Data: err.Error()})
		return
	}
	output := make(chan string, 32)
	copyOutput := func(reader io.Reader) {
		buffer := make([]byte, 8192)
		for {
			n, readErr := reader.Read(buffer)
			if n > 0 {
				output <- string(buffer[:n])
			}
			if readErr != nil {
				return
			}
		}
	}
	go copyOutput(stdout)
	go copyOutput(stderr)

	input := make(chan terminalMessage, 8)
	readErr := make(chan error, 1)
	go func() {
		for {
			var message terminalMessage
			if err := transport.readJSON(&message); err != nil {
				readErr <- err
				return
			}
			input <- message
		}
	}()

	waitErr := make(chan error, 1)
	go func() { waitErr <- sshSession.Wait() }()
	for {
		select {
		case data := <-output:
			if err := transport.writeJSON(terminalOutput{Type: "output", Data: data}); err != nil {
				return
			}
		case message := <-input:
			switch message.Type {
			case "input":
				if len(message.Data) <= 64<<10 {
					_, _ = io.WriteString(stdin, message.Data)
				}
			case "resize":
				if message.Rows >= 1 && message.Rows <= 500 && message.Cols >= 1 && message.Cols <= 500 {
					_ = sshSession.WindowChange(int(message.Rows), int(message.Cols))
				}
			}
		case err := <-readErr:
			if err != nil {
				return
			}
		case err := <-waitErr:
			code := 0
			if err != nil {
				code = 1
			}
			_ = transport.writeJSON(terminalOutput{Type: "exit", Code: code})
			return
		case <-transport.ctx.Done():
			return
		}
	}
}

func (h *ServerHandler) handleSSHFiles(w http.ResponseWriter, r *http.Request) {
	session, ok := h.authorizedSSHSession(w, r)
	if !ok {
		return
	}
	sftpClient, err := sftp.NewClient(session.Client)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Errorf("open SFTP: %w", err))
		return
	}
	defer sftpClient.Close()
	switch r.Method {
	case http.MethodGet:
		if r.URL.Query().Get("download") == "1" {
			handleSSHFileDownload(w, r, sftpClient)
			return
		}
		h.handleSSHFileList(w, r, sftpClient)
	case http.MethodPost:
		h.handleSSHFileUpload(w, r, sftpClient)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *ServerHandler) authorizedSSHSession(w http.ResponseWriter, r *http.Request) (*sshconsole.Session, bool) {
	session, err := h.sshConsole.Get(r.PathValue("session"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return nil, false
	}
	if h.auth != nil && h.auth.enabled {
		current, ok := h.auth.sessionFromRequest(r)
		if !ok || security.NormalizeRole(current.Role) == security.RoleViewer || session.Info.Owner != current.Username {
			writeError(w, http.StatusForbidden, errors.New("this SSH session belongs to another account"))
			return nil, false
		}
	}
	return session, true
}

func (h *ServerHandler) handleSSHFileList(w http.ResponseWriter, r *http.Request, client *sftp.Client) {
	remotePath := strings.TrimSpace(r.URL.Query().Get("path"))
	if remotePath == "" {
		remotePath = "."
	}
	// SFTP accepts relative paths such as "." and "..". Resolve them once
	// before returning the listing so the UI has one stable path for each
	// directory and cannot bounce between the home directory and "/".
	resolvedPath, err := client.RealPath(remotePath)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Errorf("resolve remote path: %w", err))
		return
	}
	remotePath = path.Clean(strings.TrimSpace(resolvedPath))
	if remotePath == "." || remotePath == "" {
		remotePath = "/"
	}
	entries, err := client.ReadDir(remotePath)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	items := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		items = append(items, map[string]any{
			"name":        entry.Name(),
			"path":        path.Join(remotePath, entry.Name()),
			"directory":   entry.IsDir(),
			"size":        entry.Size(),
			"mode":        entry.Mode().String(),
			"modified_at": entry.ModTime().UTC(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": remotePath, "entries": items})
}

func (h *ServerHandler) handleSSHFileUpload(w http.ResponseWriter, r *http.Request, client *sftp.Client) {
	r.Body = http.MaxBytesReader(w, r.Body, maxSSHUploadSize+1<<20)
	if err := r.ParseMultipartForm(maxSSHUploadSize + 1<<20); err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, errors.New("上传文件不能超过 32 MB"))
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("上传文件不能为空"))
		return
	}
	defer file.Close()
	if header.Size > maxSSHUploadSize {
		writeError(w, http.StatusRequestEntityTooLarge, errors.New("上传文件不能超过 32 MB"))
		return
	}
	remotePath := strings.TrimSpace(r.FormValue("path"))
	if remotePath == "" {
		remotePath = header.Filename
	}
	if strings.ContainsRune(remotePath, '\x00') || remotePath == "." || remotePath == "/" {
		writeError(w, http.StatusBadRequest, errors.New("上传目标路径无效"))
		return
	}
	tmp, err := os.CreateTemp("", "nodewall-ssh-upload-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := io.Copy(tmp, file); err != nil {
		_ = tmp.Close()
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := tmp.Close(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	report, err := securityscan.New().Scan(r.Context(), tmpPath, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("校验上传文件: %w", err))
		return
	}
	if len(report.Findings) > 0 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error": "上传文件未通过安全校验",
			"scan":  report,
		})
		return
	}
	if report.Truncated || report.FilesScanned != 1 || report.FilesSkipped != 0 || report.ReadErrors != 0 {
		writeError(w, http.StatusUnprocessableEntity, errors.New("上传文件未完整检查，请重新上传"))
		return
	}
	remote, err := client.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	local, err := os.Open(tmpPath)
	if err != nil {
		_ = remote.Close()
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	_, copyErr := io.Copy(remote, local)
	_ = local.Close()
	closeErr := remote.Close()
	if copyErr != nil {
		writeError(w, http.StatusBadGateway, copyErr)
		return
	}
	if closeErr != nil {
		writeError(w, http.StatusBadGateway, closeErr)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"path": remotePath,
		"size": header.Size,
		"scan": report,
	})
}

func handleSSHFileDownload(w http.ResponseWriter, r *http.Request, client *sftp.Client) {
	remotePath := strings.TrimSpace(r.URL.Query().Get("path"))
	if remotePath == "" || remotePath == "." || remotePath == "/" {
		writeError(w, http.StatusBadRequest, errors.New("下载文件路径无效"))
		return
	}
	file, err := client.Open(remotePath)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || stat.IsDir() {
		writeError(w, http.StatusBadRequest, errors.New("目标不是文件"))
		return
	}
	name := path.Base(remotePath)
	name = strings.ReplaceAll(name, "\"", "")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", name))
	w.Header().Set("Content-Length", strconv.FormatInt(stat.Size(), 10))
	_, _ = io.Copy(w, file)
}
