// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package llmreview

import (
	"context"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
)

// DefaultAnthropicModel is the Claude model used when AnthropicOptions.Model
// is empty.
const DefaultAnthropicModel = "claude-opus-5-5"

// AnthropicOptions configure an Anthropic provider. A zero value is ready for
// use and reads credentials from the environment (for example
// ANTHROPIC_API_KEY).
type AnthropicOptions struct {
	// The Claude model to use. If empty, DefaultAnthropicModel is used.
	Model string

	// If set, send requests to this base URL instead of the Anthropic API, for
	// example a gateway that serves the Anthropic Messages API. The client
	// appends "/v1/messages".
	BaseURL string

	// If set, use this API key instead of reading one from the environment.
	APIKey string

	// Additional options for the Anthropic client.
	ClientOptions []option.RequestOption
}

// Anthropic is a Provider that uses the Anthropic Messages API.
type Anthropic struct {
	client anthropic.Client
	model  string
	direct bool // talking to the Anthropic API rather than a gateway
}

// NewAnthropic constructs an Anthropic provider.
func NewAnthropic(opts AnthropicOptions) *Anthropic {
	var copts []option.RequestOption
	if opts.BaseURL != "" {
		copts = append(copts, option.WithBaseURL(opts.BaseURL))
	}
	if opts.APIKey != "" {
		copts = append(copts, option.WithAPIKey(opts.APIKey))
	}
	copts = append(copts, opts.ClientOptions...)
	model := opts.Model
	if model == "" {
		model = DefaultAnthropicModel
	}
	return &Anthropic{
		client: anthropic.NewClient(copts...),
		model:  model,
		direct: opts.BaseURL == "",
	}
}

// Complete implements Provider.
func (a *Anthropic) Complete(ctx context.Context, system, user string, schema map[string]any) (string, error) {
	params := anthropic.BetaMessageNewParams{
		Model:     anthropic.Model(a.model),
		MaxTokens: 16000,
		System:    []anthropic.BetaTextBlockParam{{Text: system}},
		Messages: []anthropic.BetaMessageParam{
			anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(user)),
		},
		OutputConfig: anthropic.BetaOutputConfigParam{
			Format: anthropic.BetaJSONOutputFormatParam{Schema: schema},
		},
	}
	if a.direct {
		// When talking to the Anthropic API directly, set the effort explicitly
		// and, if a safety classifier declines the request, let the API re-serve
		// it on a fallback model. Gateways may not pass these through.
		params.OutputConfig.Effort = anthropic.BetaOutputConfigEffortMedium
		params.Betas = []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01}
		params.Fallbacks = anthropic.BetaFallbacksParamOfDefault()
	}
	resp, err := a.client.Beta.Messages.New(ctx, params)
	if err != nil {
		return "", err
	}
	switch resp.StopReason {
	case anthropic.BetaStopReasonRefusal:
		return "", ErrDeclined
	case anthropic.BetaStopReasonEndTurn:
		// OK
	default:
		return "", fmt.Errorf("unexpected stop reason %q", resp.StopReason)
	}

	var text strings.Builder
	for _, block := range resp.Content {
		if tb, ok := block.AsAny().(anthropic.BetaTextBlock); ok {
			text.WriteString(tb.Text)
		}
	}
	return text.String(), nil
}
