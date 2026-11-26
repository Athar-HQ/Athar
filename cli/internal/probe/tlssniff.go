package probe

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// maxSniff is how much of a server's answer sniffConn keeps: enough for a
// ServerHello and a certificate chain.
const maxSniff = 64 << 10

// sniffConn keeps the first bytes read from the peer. crypto/tls gives no
// details when a handshake fails, so the prober reads them from these bytes.
type sniffConn struct {
	net.Conn
	buf []byte
}

func (c *sniffConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if room := maxSniff - len(c.buf); room > 0 {
		c.buf = append(c.buf, p[:min(n, room)]...)
	}
	return n, err
}

// TLS record types and handshake message types.
const (
	recordAlert        = 21
	recordHandshake    = 22
	handshakeHello     = 2
	handshakeCertChain = 11
)

// sniffTLS reads the start of a server's answer to a ClientHello. ok says
// that it is TLS: a ServerHello or an alert. leaf is the server's certificate
// if it was sent in the clear, as TLS 1.2 and older do.
func sniffTLS(b []byte) (ok bool, leaf []byte) {
	if len(b) < 7 || b[1] != 3 || b[2] > 4 {
		return false, nil
	}
	if b[0] == recordAlert {
		return b[3] == 0 && b[4] == 2, nil
	}
	if b[0] != recordHandshake || b[5] != handshakeHello {
		return false, nil
	}
	// Join the handshake records up to the first other record: from there on
	// the handshake is encrypted.
	var hs []byte
	for len(b) >= 5 && b[0] == recordHandshake {
		n := int(b[3])<<8 | int(b[4])
		if len(b) < 5+n {
			break
		}
		hs = append(hs, b[5:5+n]...)
		b = b[5+n:]
	}
	for len(hs) >= 4 {
		typ, n := hs[0], int(hs[1])<<16|int(hs[2])<<8|int(hs[3])
		if len(hs) < 4+n {
			break
		}
		// A certificate list: its length, then each certificate with its own.
		if msg := hs[4 : 4+n]; typ == handshakeCertChain && len(msg) >= 6 {
			if n := int(msg[3])<<16 | int(msg[4])<<8 | int(msg[5]); n > 0 && len(msg) >= 6+n {
				leaf = msg[6 : 6+n]
			}
			break
		}
		hs = hs[4+n:]
	}
	return true, leaf
}

// leafTLS12 repeats a failed handshake with TLS 1.2 at most, where the server
// sends its certificate in the clear, and returns that certificate.
func (p *Prober) leafTLS12(ctx context.Context, svc *Service) []byte {
	conn, err := p.dial(ctx, svc.IP, svc.Port)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.Timeout))
	cfg := p.tlsConfig(svc.Host)
	cfg.MaxVersion = tls.VersionTLS12
	sc := &sniffConn{Conn: conn}
	tls.Client(sc, cfg).HandshakeContext(ctx)
	_, leaf := sniffTLS(sc.buf)
	return leaf
}
