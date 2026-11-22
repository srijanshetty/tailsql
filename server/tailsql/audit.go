// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailsql

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"
)

// An auditEntry is one line of the audit log, recording who ran a query and
// what happened to it.
type auditEntry struct {
	Time time.Time `json:"time"`

	// Who is the caller's Tailscale login name, or the node name for a tagged
	// node. It is empty if the server is not checking Tailscale identities
	// (for example, when run with --local).
	Who           string `json:"who"`
	Node          string `json:"node,omitempty"` // the caller's Tailscale node name
	Authenticated bool   `json:"authenticated"`  // whether Who was verified by Tailscale

	Source string `json:"source"`
	Query  string `json:"query"`

	// Review is the outcome of the review hook: "off" (no hook), "skipped"
	// (named or meta-query), "allowed", "needs_confirmation", "confirmed"
	// (warning overridden by the caller), "denied", or "error".
	Review       string `json:"review"`
	ReviewReason string `json:"review_reason,omitempty"`

	// Outcome is "ok" if the query ran, "blocked" if review stopped it, or
	// "error" if it failed.
	Outcome   string `json:"outcome"`
	Error     string `json:"error,omitempty"`
	Rows      int    `json:"rows"`
	ElapsedMS int64  `json:"elapsed_ms"`
}

// auditLog appends audit entries to a file as JSON lines.
// A nil *auditLog discards entries.
type auditLog struct {
	mu sync.Mutex
	f  *os.File
}

func openAuditLog(path string) (*auditLog, error) {
	f, err := os.OpenFile(os.ExpandEnv(path), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	return &auditLog{f: f}, nil
}

func (a *auditLog) write(e *auditEntry) error {
	if a == nil {
		return nil
	}
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err = a.f.Write(data)
	return err
}

func (a *auditLog) close() error {
	if a == nil {
		return nil
	}
	return a.f.Close()
}

// callerIdentity describes the Tailscale identity of the caller of a request.
type callerIdentity struct {
	Who           string // login name, or node name for a tagged node
	Node          string // node name
	Authenticated bool
}

type identityKey struct{}

func withIdentity(ctx context.Context, id callerIdentity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

func identityFrom(ctx context.Context) callerIdentity {
	id, _ := ctx.Value(identityKey{}).(callerIdentity)
	return id
}

// finishAudit fills in the outcome of e from the result of a query and writes
// it to the audit log, if one is configured.
func (s *Server) finishAudit(e *auditEntry, res *dbResult, err error, blocked bool) {
	if s.audit == nil {
		return
	}
	switch {
	case blocked:
		e.Outcome = "blocked"
	case err == nil || errors.Is(err, errTooManyRows):
		e.Outcome = "ok"
	default:
		e.Outcome = "error"
	}
	if err != nil && !errors.Is(err, errTooManyRows) {
		e.Error = err.Error()
	}
	if res != nil {
		e.Rows = len(res.Rows)
		e.ElapsedMS = res.Elapsed.Milliseconds()
	}
	if werr := s.audit.write(e); werr != nil {
		s.logf("[tailsql] WARNING: error writing audit log: %v", werr)
	}
}
