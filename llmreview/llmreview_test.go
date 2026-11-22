// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package llmreview_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tailscale/tailsql/llmreview"
	"github.com/tailscale/tailsql/server/tailsql"
)

// fakeProvider returns a canned reply and counts calls.
type fakeProvider struct {
	reply string
	err   error
	calls int
}

func (f *fakeProvider) Complete(context.Context, string, string, map[string]any) (string, error) {
	f.calls++
	return f.reply, f.err
}

func TestReviewer(t *testing.T) {
	ctx := context.Background()
	q := tailsql.Query{Source: "main", Query: "select 1"}
	logf := t.Logf

	tests := []struct {
		name     string
		reply    string
		err      error
		wantErr  string // "" means approved
		wantWarn bool   // expect a tailsql.ReviewWarning
	}{
		{"Allow", `{"decision": "allow", "reason": "read-only"}`, nil, "", false},
		{"Deny", `{"decision": "deny", "reason": "drops a table"}`, nil, "drops a table", false},
		{"Warn", `{"decision": "warn", "reason": "UPDATE has no WHERE clause"}`, nil, "UPDATE has no WHERE clause", true},
		{"CaseInsensitive", `{"decision": "ALLOW", "reason": "ok"}`, nil, "", false},
		{"UnknownDecisionDenies", `{"decision": "maybe", "reason": "hmm"}`, nil, "hmm", false},
		{"Fenced", "```json\n{\"decision\": \"allow\", \"reason\": \"ok\"}\n```", nil, "", false},
		{"OldFormatFailsClosed", `{"safe": true, "reason": "ok"}`, nil, "unavailable", false},
		{"Garbage", `sure, looks fine`, nil, "unavailable", false},
		{"Declined", "", llmreview.ErrDeclined, "declined", false},
		{"ProviderError", "", errors.New("connection refused"), "unavailable", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := llmreview.New(llmreview.Options{
				Provider: &fakeProvider{reply: tc.reply, err: tc.err},
				Logf:     logf,
			})
			err := r.Review(ctx, "user", q)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("Review: got %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Review: got %v, want error containing %q", err, tc.wantErr)
			}
			var warn tailsql.ReviewWarning
			if got := errors.As(err, &warn); got != tc.wantWarn {
				t.Errorf("Review: got warning=%v, want %v (err=%v)", got, tc.wantWarn, err)
			}
		})
	}

	t.Run("Cache", func(t *testing.T) {
		fp := &fakeProvider{reply: `{"decision": "deny", "reason": "no"}`}
		r := llmreview.New(llmreview.Options{Provider: fp, Logf: logf})
		for range 3 {
			r.Review(ctx, "user", q)
		}
		r.Review(ctx, "user", tailsql.Query{Source: "other", Query: q.Query})
		if fp.calls != 2 {
			t.Errorf("Provider calls: got %d, want 2", fp.calls)
		}
	})

	t.Run("NoCacheOnError", func(t *testing.T) {
		fp := &fakeProvider{err: errors.New("boom")}
		r := llmreview.New(llmreview.Options{Provider: fp, Logf: logf})
		r.Review(ctx, "user", q)
		r.Review(ctx, "user", q)
		if fp.calls != 2 {
			t.Errorf("Provider calls: got %d, want 2", fp.calls)
		}
	})
}

func TestOpenAI(t *testing.T) {
	var gotAuth string
	var gotReq map[string]any
	reply := `{"choices":[{"message":{"content":"{\"decision\":\"deny\",\"reason\":\"drops a table\"}"},"finish_reason":"stop"}]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.Error(w, "wrong path "+r.URL.Path, http.StatusNotFound)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&gotReq)
		w.Write([]byte(reply))
	}))
	defer srv.Close()

	ctx := context.Background()
	q := tailsql.Query{Source: "main", Query: "drop table users"}

	t.Run("OpenAI", func(t *testing.T) {
		p := llmreview.NewOpenAI(llmreview.OpenAIOptions{
			Model: "test-model", BaseURL: srv.URL + "/v1/", APIKey: "sk-test",
		})
		err := llmreview.New(llmreview.Options{Provider: p, Logf: t.Logf}).Review(ctx, "user", q)
		if err == nil || err.Error() != "drops a table" {
			t.Errorf("Review: got %v, want %q", err, "drops a table")
		}
		if gotAuth != "Bearer sk-test" {
			t.Errorf("Authorization: got %q, want bearer token", gotAuth)
		}
		if gotReq["model"] != "test-model" {
			t.Errorf("Model: got %v, want test-model", gotReq["model"])
		}
		if rf, _ := gotReq["response_format"].(map[string]any); rf["type"] != "json_schema" {
			t.Errorf("response_format: got %v, want json_schema", gotReq["response_format"])
		}
	})

	t.Run("Aperture", func(t *testing.T) {
		t.Setenv("OPENAI_API_KEY", "should-not-be-sent")
		p := llmreview.NewAperture(srv.URL, "test-model")
		err := llmreview.New(llmreview.Options{Provider: p, Logf: t.Logf}).Review(ctx, "user", q)
		if err == nil || err.Error() != "drops a table" {
			t.Errorf("Review: got %v, want %q", err, "drops a table")
		}
		if gotAuth != "" {
			t.Errorf("Authorization: got %q, want none", gotAuth)
		}
	})

	t.Run("Refusal", func(t *testing.T) {
		reply = `{"choices":[{"message":{"content":null,"refusal":"no"},"finish_reason":"stop"}]}`
		p := llmreview.NewAperture(srv.URL, "test-model")
		err := llmreview.New(llmreview.Options{Provider: p, Logf: t.Logf}).Review(ctx, "user", q)
		if err == nil || !strings.Contains(err.Error(), "declined") {
			t.Errorf("Review: got %v, want declined", err)
		}
	})

	t.Run("HTTPError", func(t *testing.T) {
		p := llmreview.NewOpenAI(llmreview.OpenAIOptions{Model: "m", BaseURL: srv.URL + "/wrong"})
		err := llmreview.New(llmreview.Options{Provider: p, Logf: t.Logf}).Review(ctx, "user", q)
		if err == nil || !strings.Contains(err.Error(), "unavailable") {
			t.Errorf("Review: got %v, want review failure", err)
		}
	})
}

// policyProvider records the system prompt it was given.
type policyProvider struct{ system string }

func (p *policyProvider) Complete(_ context.Context, system, _ string, _ map[string]any) (string, error) {
	p.system = system
	return `{"decision": "allow", "reason": "ok"}`, nil
}

func TestPolicySelection(t *testing.T) {
	q := tailsql.Query{Source: "main", Query: "select 1"}
	for _, tc := range []struct {
		name string
		opts llmreview.Options
		want string
	}{
		{"Default", llmreview.Options{}, llmreview.DefaultPolicy},
		{"AllowWrites", llmreview.Options{AllowWrites: true}, llmreview.WritePolicy},
		{"Custom", llmreview.Options{AllowWrites: true, Policy: "custom policy"}, "custom policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := new(policyProvider)
			tc.opts.Provider = p
			tc.opts.Logf = t.Logf
			llmreview.New(tc.opts).Review(context.Background(), "user", q)
			if !strings.Contains(p.system, tc.want) {
				t.Errorf("System prompt does not contain the expected policy %q", tc.name)
			}
		})
	}
}
