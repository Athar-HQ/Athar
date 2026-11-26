package probe

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/Athar-HQ/Athar/cli/internal/rule"
)

// drip starts a server that sends one byte every 50 ms for up to 8 seconds.
func drip(t *testing.T) (string, int) {
	t.Helper()
	return listen(t, func(c net.Conn) {
		for end := time.Now().Add(8 * time.Second); time.Now().Before(end); {
			if _, err := c.Write([]byte("x")); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
}

// silent starts a server that accepts connections and sends nothing.
func silent(t *testing.T) (string, int) {
	t.Helper()
	return listen(t, func(c net.Conn) {
		c.SetDeadline(time.Now().Add(8 * time.Second))
		c.Read(make([]byte, 1))
	})
}

// A server that drips bytes must not hold the banner read past the banner
// wait plus bannerTail, the timeout or the context.
func TestBannerDrip(t *testing.T) {
	host, port := drip(t)
	for _, tt := range []struct {
		name            string
		banner, timeout time.Duration
		ctx             time.Duration // 0: no deadline
		want            time.Duration // when the read must end
	}{
		{"tail", 100 * time.Millisecond, 5 * time.Second, 0, 100*time.Millisecond + bannerTail},
		{"timeout", 300 * time.Millisecond, 600 * time.Millisecond, 0, 600 * time.Millisecond},
		{"context", 300 * time.Millisecond, 5 * time.Second, 400 * time.Millisecond, 400 * time.Millisecond},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.ctx > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.ctx)
				defer cancel()
			}
			p := &Prober{Timeout: tt.timeout, BannerWait: tt.banner, Needs: Needs{Banner: true}}
			start := time.Now()
			svc := p.Probe(ctx, host, port)
			took := time.Since(start)
			if took > tt.want+time.Second {
				t.Errorf("probe took %v, want about %v", took.Round(time.Millisecond), tt.want)
			}
			if svc == nil {
				t.Fatal("port reported closed")
			}
			if b, _ := svc.Fields["service.banner"].(string); b == "" || b != string(bytes.Repeat([]byte("x"), len(b))) {
				t.Errorf("service.banner = %q, want the bytes dripped so far", b)
			}
		})
	}
}

// A rule's read.timeout_ms may shorten a TCP probe's read but not extend it
// past the operator's timeout.
func TestCustomReadTimeout(t *testing.T) {
	host, port := silent(t)
	for _, tt := range []struct {
		name      string
		timeout   time.Duration
		timeoutMs int
		want      time.Duration
	}{
		{"longer than the timeout", 500 * time.Millisecond, 6000, 500 * time.Millisecond},
		{"overflowing", 500 * time.Millisecond, int(^uint(0) >> 1), 500 * time.Millisecond},
		{"shorter than the timeout", 3 * time.Second, 100, 100 * time.Millisecond},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pr := rule.Probe{Protocol: "tcp", Read: &rule.ReadLimits{TimeoutMs: tt.timeoutMs}}
			p := &Prober{Timeout: tt.timeout, Custom: []CustomProbe{{Key: ProbeKey(pr), Probe: pr}}}
			start := time.Now()
			svc := p.Probe(context.Background(), host, port)
			took := time.Since(start)
			if svc == nil {
				t.Fatal("port reported closed")
			}
			if took < tt.want-50*time.Millisecond || took > tt.want+time.Second {
				t.Errorf("probe took %v, want about %v", took.Round(time.Millisecond), tt.want)
			}
		})
	}
}

// A rule's read.max_bytes can't raise what a TCP probe keeps above maxBanner.
func TestCustomReadMaxBytes(t *testing.T) {
	host, port := listen(t, func(c net.Conn) {
		c.Write(bytes.Repeat([]byte("x"), 4*maxBanner))
	})
	pr := rule.Probe{Protocol: "tcp", Read: &rule.ReadLimits{MaxBytes: 1 << 30}}
	p := &Prober{Timeout: time.Second, Custom: []CustomProbe{{Key: ProbeKey(pr), Probe: pr}}}
	svc := p.Probe(context.Background(), host, port)
	if svc == nil {
		t.Fatal("port reported closed")
	}
	if b, _ := svc.Custom[ProbeKey(pr)]["service.banner"].(string); len(b) == 0 || len(b) > maxBanner {
		t.Errorf("kept %d bytes, want 1 to %d", len(b), maxBanner)
	}
}
