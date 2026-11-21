// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package llmreview

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// DefaultOpenAIBaseURL is the base URL used when OpenAIOptions.BaseURL is
// empty.
const DefaultOpenAIBaseURL = "https://api.openai.com/v1"

// OpenAIOptions configure an OpenAI-compatible provider.
type OpenAIOptions struct {
	// The model to use (required), for example "gpt-5.5". For gateways and
	// self-hosted servers, use whatever name the server expects.
	Model string

	// The API base URL, including the version path. The provider sends
	// requests to BaseURL + "/chat/completions". If empty,
	// DefaultOpenAIBaseURL is used.
	BaseURL string

	// The API key to send as a bearer token. If empty, the OPENAI_API_KEY
	// environment variable is used if set; otherwise no Authorization header
	// is sent (as for Aperture or a local server).
	APIKey string

	// If true, do not ask the server to enforce the JSON schema. Set this for
	// servers that reject the "json_schema" response format; the reviewer
	// still instructs the model to reply in JSON and parses it leniently.
	NoSchema bool

	// The HTTP client to use. If nil, http.DefaultClient is used.
	HTTPClient *http.Client
}

// OpenAI is a Provider that uses an OpenAI-compatible Chat Completions API.
// This covers OpenAI itself, Tailscale Aperture, and servers such as Ollama,
// vLLM, and LiteLLM.
type OpenAI struct {
	opts OpenAIOptions
}

// NewOpenAI constructs an OpenAI-compatible provider.
func NewOpenAI(opts OpenAIOptions) *OpenAI {
	if opts.BaseURL == "" {
		opts.BaseURL = DefaultOpenAIBaseURL
	}
	opts.BaseURL = strings.TrimSuffix(opts.BaseURL, "/")
	if opts.APIKey == "" {
		opts.APIKey = os.Getenv("OPENAI_API_KEY")
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = http.DefaultClient
	}
	return &OpenAI{opts: opts}
}

// NewAperture constructs a provider that reaches models through Tailscale
// Aperture's OpenAI-compatible endpoint. The host is the Aperture address on
// the tailnet, for example "http://ai". Aperture identifies the caller by its
// Tailscale identity, so no API key is sent.
func NewAperture(host, model string) *OpenAI {
	return &OpenAI{opts: OpenAIOptions{
		Model:      model,
		BaseURL:    strings.TrimSuffix(host, "/") + "/v1",
		HTTPClient: http.DefaultClient,
	}}
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model          string         `json:"model"`
	Messages       []chatMessage  `json:"messages"`
	ResponseFormat map[string]any `json:"response_format,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content *string `json:"content"`
			Refusal *string `json:"refusal"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
}

// Complete implements Provider.
func (o *OpenAI) Complete(ctx context.Context, system, user string, schema map[string]any) (string, error) {
	if o.opts.Model == "" {
		return "", errors.New("no model specified")
	}
	req := chatRequest{
		Model: o.opts.Model,
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
	}
	if !o.opts.NoSchema {
		req.ResponseFormat = map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name":   "verdict",
				"strict": true,
				"schema": schema,
			},
		}
	}
	body, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.opts.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	hreq.Header.Set("Content-Type", "application/json")
	if o.opts.APIKey != "" {
		hreq.Header.Set("Authorization", "Bearer "+o.opts.APIKey)
	}

	hrsp, err := o.opts.HTTPClient.Do(hreq)
	if err != nil {
		return "", err
	}
	defer hrsp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(hrsp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if hrsp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("chat completions: %s: %s", hrsp.Status, bytes.TrimSpace(data))
	}

	var rsp chatResponse
	if err := json.Unmarshal(data, &rsp); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if len(rsp.Choices) == 0 {
		return "", errors.New("response has no choices")
	}
	c := rsp.Choices[0]
	if c.Message.Refusal != nil && *c.Message.Refusal != "" {
		return "", ErrDeclined
	}
	if c.FinishReason != "stop" {
		return "", fmt.Errorf("unexpected finish reason %q", c.FinishReason)
	}
	if c.Message.Content == nil {
		return "", errors.New("response has no content")
	}
	return *c.Message.Content, nil
}
