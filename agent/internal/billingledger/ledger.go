package billingledger

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var accountRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{1,95}$`)
var currencyRE = regexp.MustCompile(`^[A-Z]{3}$`)

type Line struct {
	Account     string `json:"account"`
	AmountMinor int64  `json:"amount_minor"`
	Memo        string `json:"memo,omitempty"`
}

type Transaction struct {
	ID             string    `json:"id"`
	IdempotencyKey string    `json:"idempotency_key"`
	Currency       string    `json:"currency"`
	Lines          []Line    `json:"lines"`
	CreatedAt      time.Time `json:"created_at"`
	PrevHash       string    `json:"prev_hash,omitempty"`
	Hash           string    `json:"hash"`
}

type Ledger struct {
	mu    sync.Mutex
	path  string
	last  string
	byKey map[string]Transaction
}

func Open(path string) (*Ledger, error) {
	l := &Ledger{path: path, byKey: map[string]Transaction{}}
	if path == "" {
		return l, nil
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	prev := ""
	for scanner.Scan() {
		var tx Transaction
		if err := json.Unmarshal(scanner.Bytes(), &tx); err != nil {
			return nil, fmt.Errorf("invalid ledger record: %w", err)
		}
		if tx.PrevHash != prev {
			return nil, errors.New("ledger hash chain broken")
		}
		expected, err := hashTransaction(tx)
		if err != nil {
			return nil, err
		}
		if tx.Hash != expected {
			return nil, errors.New("ledger record hash mismatch")
		}
		if _, exists := l.byKey[tx.IdempotencyKey]; exists {
			return nil, errors.New("duplicate ledger idempotency key")
		}
		l.byKey[tx.IdempotencyKey] = clone(tx)
		prev = tx.Hash
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	l.last = prev
	return l, nil
}

func clone(tx Transaction) Transaction {
	tx.Lines = append([]Line(nil), tx.Lines...)
	return tx
}

func validate(tx Transaction) error {
	tx.Currency = strings.ToUpper(strings.TrimSpace(tx.Currency))
	if len(tx.IdempotencyKey) < 8 || len(tx.IdempotencyKey) > 160 {
		return errors.New("idempotency key required")
	}
	if !currencyRE.MatchString(tx.Currency) {
		return errors.New("invalid currency")
	}
	if len(tx.Lines) < 2 || len(tx.Lines) > 64 {
		return errors.New("ledger transaction needs 2-64 lines")
	}
	var total int64
	for _, line := range tx.Lines {
		if !accountRE.MatchString(line.Account) {
			return errors.New("invalid ledger account")
		}
		if line.AmountMinor == 0 {
			return errors.New("zero-value ledger line not allowed")
		}
		if len(line.Memo) > 240 || strings.ContainsAny(line.Memo, "\x00\r\n") {
			return errors.New("invalid ledger memo")
		}
		next := total + line.AmountMinor
		if (line.AmountMinor > 0 && next < total) || (line.AmountMinor < 0 && next > total) {
			return errors.New("ledger amount overflow")
		}
		total = next
	}
	if total != 0 {
		return errors.New("double-entry transaction is not balanced")
	}
	return nil
}

func hashTransaction(tx Transaction) (string, error) {
	c := tx
	c.Hash = ""
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func (l *Ledger) appendLocked(tx Transaction) error {
	if l.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0750); err != nil {
		return err
	}
	b, err := json.Marshal(tx)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func (l *Ledger) Post(tx Transaction) (Transaction, error) {
	tx.Currency = strings.ToUpper(strings.TrimSpace(tx.Currency))
	if err := validate(tx); err != nil {
		return Transaction{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if existing, ok := l.byKey[tx.IdempotencyKey]; ok {
		return clone(existing), nil
	}
	tx.ID = fmt.Sprintf("txn_%d", time.Now().UTC().UnixNano())
	tx.CreatedAt = time.Now().UTC()
	tx.PrevHash = l.last
	hash, err := hashTransaction(tx)
	if err != nil {
		return Transaction{}, err
	}
	tx.Hash = hash
	if err := l.appendLocked(tx); err != nil {
		return Transaction{}, err
	}
	l.last = tx.Hash
	l.byKey[tx.IdempotencyKey] = clone(tx)
	return clone(tx), nil
}

func (l *Ledger) Verify() error {
	if l.path == "" {
		return nil
	}
	_, err := Open(l.path)
	return err
}
