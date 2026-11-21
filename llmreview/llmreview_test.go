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
		name    string
		reply   string
		err     error
		wantErr string // "" means approved
	}{
		{"Safe", `{"safe": true, "reason": "read-only"}`, nil, ""},
		{"Unsafe", `{"safe": false, "reason": "deletes rows"}`, nil, "deletes rows"},
		{"Fenced", "```json\n{\"safe\": true, \"reason\": \"ok\"}\n```", nil, ""},
		{"MissingSafe", `{"reason": "ok"}`, nil, "unavailable"},
		{"Garbage", `sure, looks fine`, nil, "unavailable"},
		{"Declined", "", llmreview.ErrDeclined, "declined"},
		{"ProviderError", "", errors.New("connection refused"), "unavailable"},
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
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Review: got %v, want error containing %q", err, tc.wantErr)
			}
		})
	}

	t.Run("Cache", func(t *testing.T) {
		fp := &fakeProvider{reply: `{"safe": false, "reason": "no"}`}
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
	reply := `{"choices":[{"message":{"content":"{\"safe\":false,\"reason\":\"drops a table\"}"},"finish_reason":"stop"}]}`

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
