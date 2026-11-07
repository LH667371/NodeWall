// Package sshactivity reads the small, append-only activity journal written by
// the NodeWall SSH ForceCommand wrapper.
package sshactivity

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Record struct {
	ID         string    `json:"id,omitempty"`
	SessionID  string    `json:"session_id,omitempty"`
	ExitCode   *int      `json:"exit_code,omitempty"`
	Bytes      int64     `json:"bytes,omitempty"`
	Detail     string    `json:"detail,omitempty"`
	Truncated  bool      `json:"truncated,omitempty"`
	At         time.Time `json:"at"`
	Event      string    `json:"event"`
	User       string    `json:"user,omitempty"`
	SourceIP   string    `json:"source_ip,omitempty"`
	SourcePort uint16    `json:"source_port,omitempty"`
	Transfer   string    `json:"transfer,omitempty"`
	Action     string    `json:"action,omitempty"`
	Command    string    `json:"command,omitempty"`
	Path       string    `json:"path,omitempty"`
	ScanStatus string    `json:"scan_status,omitempty"`
	Files      int       `json:"files_checked,omitempty"`
	Findings   int       `json:"findings,omitempty"`
}

func Read(path string, limit int) ([]Record, error) {
	return ReadFiltered(path, limit, Filter{})
}

type Filter struct{ SessionID, Event, SourceIP, User string }

func ReadFiltered(path string, limit int, filter Filter) ([]Record, error) {
	if strings.TrimSpace(path) == "" {
		return []Record{}, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	records := make([]Record, 0, limit)
	for i := 0; i < 4 && len(records) < limit; i++ {
		name := path
		if i > 0 {
			name = fmt.Sprintf("%s.%d", path, i)
		}
		file, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		info, err := file.Stat()
		if err != nil {
			file.Close()
			return nil, err
		}
		if !info.Mode().IsRegular() {
			file.Close()
			return nil, errors.New("SSH journal is not a regular file")
		}
		start := max(int64(0), info.Size()-journalLimit)
		data := make([]byte, info.Size()-start)
		_, err = file.ReadAt(data, start)
		file.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if start > 0 {
			if n := bytes.IndexByte(data, '\n'); n >= 0 {
				data = data[n+1:]
			} else {
				continue
			}
		}
		end := bytes.LastIndexByte(data, '\n')
		for end > 0 && len(records) < limit {
			begin := bytes.LastIndexByte(data[:end], '\n') + 1
			if end-begin <= 256<<10 {
				record, ok := ParseLine(string(data[begin:end]))
				if ok && (filter.SessionID == "" || record.SessionID == filter.SessionID) && (filter.Event == "" || record.Event == filter.Event) && (filter.SourceIP == "" || record.SourceIP == filter.SourceIP) && (filter.User == "" || record.User == filter.User) {
					records = append(records, record)
				}
			}
			end = begin - 1
		}
	}
	return records, nil
}

func ParseLine(line string) (Record, bool) {
	if strings.HasPrefix(strings.TrimSpace(line), "{") {
		var record Record
		if json.Unmarshal([]byte(line), &record) != nil || record.At.IsZero() || record.Event == "" {
			return Record{}, false
		}
		return record, true
	}
	fields := make(map[string]string)
	for _, field := range strings.Fields(line) {
		key, value, ok := strings.Cut(field, "=")
		if ok {
			fields[key] = value
		}
	}
	event := strings.TrimSpace(fields["event"])
	if event == "" {
		return Record{}, false
	}
	seconds, err := strconv.ParseInt(fields["ts"], 10, 64)
	if err != nil || seconds <= 0 {
		return Record{}, false
	}
	record := Record{
		SessionID:  fields["session"],
		At:         time.Unix(seconds, 0).UTC(),
		Event:      event,
		User:       fields["user"],
		SourceIP:   fields["source"],
		Transfer:   fields["transfer"],
		Action:     fields["action"],
		ScanStatus: fields["scan"],
	}
	if value, err := strconv.Atoi(fields["exit_code"]); err == nil {
		record.ExitCode = &value
	}
	if value, err := strconv.ParseUint(fields["source_port"], 10, 16); err == nil {
		record.SourcePort = uint16(value)
	}
	if value, err := strconv.Atoi(fields["findings"]); err == nil && value >= 0 {
		record.Findings = value
	}
	if value, err := strconv.Atoi(fields["files"]); err == nil && value >= 0 {
		record.Files = value
	}
	record.Command = decode(fields["command_b64"])
	record.Path = decode(fields["path_b64"])
	return record, true
}

func decode(value string) string {
	if value == "" {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return ""
	}
	return string(decoded)
}
