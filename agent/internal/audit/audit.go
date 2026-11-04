package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Record struct {
	Time      time.Time `json:"time"`
	Actor     string    `json:"actor"`
	Operation string    `json:"operation"`
	Resource  string    `json:"resource"`
	Outcome   string    `json:"outcome"`
	RequestID string    `json:"request_id,omitempty"`
	PrevHash  string    `json:"prev_hash,omitempty"`
	Hash      string    `json:"hash"`
}

type unsignedRecord struct {
	Time      time.Time `json:"time"`
	Actor     string    `json:"actor"`
	Operation string    `json:"operation"`
	Resource  string    `json:"resource"`
	Outcome   string    `json:"outcome"`
	RequestID string    `json:"request_id,omitempty"`
	PrevHash  string    `json:"prev_hash,omitempty"`
}

type Logger struct {
	path string
	mu   sync.Mutex
}

func New(path string) *Logger { return &Logger{path: path} }

func digestRecord(r Record) (string, error) {
	u := unsignedRecord{Time: r.Time, Actor: r.Actor, Operation: r.Operation, Resource: r.Resource, Outcome: r.Outcome, RequestID: r.RequestID, PrevHash: r.PrevHash}
	b, err := json.Marshal(u)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(r.PrevHash))
	_, _ = h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func lastHash(path string) (string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 2<<20)
	last := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			last = line
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if last == "" {
		return "", nil
	}
	var r Record
	if err := json.Unmarshal([]byte(last), &r); err != nil {
		return "", fmt.Errorf("invalid trailing audit record: %w", err)
	}
	return r.Hash, nil
}

func (l *Logger) Write(r Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	r.Time = time.Now().UTC()
	if err := os.MkdirAll(filepath.Dir(l.path), 0750); err != nil {
		return err
	}
	prev, err := lastHash(l.path)
	if err != nil {
		return err
	}
	r.PrevHash = prev
	r.Hash, err = digestRecord(r)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(r)
}

type VerifyResult struct {
	OK       bool   `json:"ok"`
	Records  int    `json:"records"`
	LastHash string `json:"last_hash"`
	Error    string `json:"error,omitempty"`
}

func Verify(path string) VerifyResult {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return VerifyResult{OK: true}
	}
	if err != nil {
		return VerifyResult{OK: false, Error: err.Error()}
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	prev := ""
	count := 0
	for {
		var r Record
		err := dec.Decode(&r)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return VerifyResult{OK: false, Records: count, LastHash: prev, Error: err.Error()}
		}
		count++
		if r.PrevHash != prev {
			return VerifyResult{OK: false, Records: count, LastHash: prev, Error: fmt.Sprintf("record %d previous hash mismatch", count)}
		}
		expected, e := digestRecord(r)
		if e != nil {
			return VerifyResult{OK: false, Records: count, LastHash: prev, Error: e.Error()}
		}
		if r.Hash == "" || r.Hash != expected {
			return VerifyResult{OK: false, Records: count, LastHash: prev, Error: fmt.Sprintf("record %d hash mismatch", count)}
		}
		prev = r.Hash
	}
	return VerifyResult{OK: true, Records: count, LastHash: prev}
}
