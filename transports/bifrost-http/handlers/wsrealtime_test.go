package handlers

import (
	"context"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

// stubRealtimeUpstream is an in-memory provider connection.
type stubRealtimeUpstream struct{ closed bool }

func (u *stubRealtimeUpstream) ReadMessage() (int, []byte, error) { return 0, nil, nil }
func (u *stubRealtimeUpstream) WriteMessage(int, []byte) error    { return nil }
func (u *stubRealtimeUpstream) Close() error                      { u.closed = true; return nil }

// connectorRealtimeProvider owns its realtime transport; the websocket methods must not be used.
type connectorRealtimeProvider struct {
	schemas.RealtimeProvider
	upstream *stubRealtimeUpstream
	model    string
	intent   string
}

func (p *connectorRealtimeProvider) ConnectRealtime(_ *schemas.BifrostContext, _ schemas.Key, model, intent string) (schemas.RealtimeUpstream, *schemas.BifrostError) {
	p.model, p.intent = model, intent
	return p.upstream, nil
}

func (p *connectorRealtimeProvider) RealtimeWebSocketURL(schemas.Key, string, string) (string, *schemas.BifrostError) {
	panic("a RealtimeConnector provider must not be dialed as a websocket")
}

// TestOpenRealtimeUpstreamPrefersProviderConnector pins that providers with their own realtime
// transport (Bedrock Nova Sonic) are connected through it instead of the websocket pool, which
// this handler deliberately leaves nil.
func TestOpenRealtimeUpstreamPrefersProviderConnector(t *testing.T) {
	provider := &connectorRealtimeProvider{upstream: &stubRealtimeUpstream{}}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	defer ctx.Cancel()

	upstream, release, bifrostErr := (&WSRealtimeHandler{}).openRealtimeUpstream(ctx, provider, schemas.Bedrock, schemas.Key{}, "amazon.nova-2-sonic-v1:0", "")
	if bifrostErr != nil {
		t.Fatalf("unexpected error: %+v", bifrostErr)
	}
	if upstream != provider.upstream || provider.model != "amazon.nova-2-sonic-v1:0" {
		t.Fatalf("connector was not used: upstream=%v model=%q", upstream, provider.model)
	}
	release()
	if !provider.upstream.closed {
		t.Fatal("release must close the provider connection")
	}
}
