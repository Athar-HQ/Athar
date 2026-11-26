// As in cli/cmd/athar: crypto/x509 takes negative serial numbers.
//
//go:debug x509negativeserial=1

package probe

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// certWithSerial returns a self-signed certificate whose serial number has
// the given DER content bytes. crypto/x509 writes no negative or padded
// serials, so a generated certificate is patched and signed again.
func certWithSerial(t *testing.T, serial [8]byte) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	placeholder := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	tmpl := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(placeholder),
		Subject:      pkix.Name{CommonName: "sloppy.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		TBS asn1.RawValue
		Alg asn1.RawValue
		Sig asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &c); err != nil {
		t.Fatal(err)
	}
	tbs := bytes.Replace(c.TBS.FullBytes, append([]byte{2, 8}, placeholder...), append([]byte{2, 8}, serial[:]...), 1)
	if bytes.Equal(tbs, c.TBS.FullBytes) {
		t.Fatal("serial not found in the certificate")
	}
	sum := sha256.Sum256(tbs)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	c.TBS = asn1.RawValue{FullBytes: tbs}
	c.Sig = asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}
	if der, err = asn1.Marshal(c); err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsPanel serves panelHandler over TLS with the given certificate.
func tlsPanel(t *testing.T, cert tls.Certificate, minVersion, maxVersion uint16) (string, int) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVersion,
		MaxVersion:   maxVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: panelHandler(), ErrorLog: log.New(io.Discard, "", 0)}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port
}

// A certificate with a negative serial number, which crypto/x509 rejects by
// default, must not hide the service: it is TLS, and the page is read.
func TestProbeTLSNegativeSerial(t *testing.T) {
	cert := certWithSerial(t, [8]byte{0x81, 2, 3, 4, 5, 6, 7, 8})
	host, port := tlsPanel(t, cert, 0, 0)

	svc := testProber(Needs{TLS: true, HTTP: true}).Probe(context.Background(), host, port)
	if svc == nil || !svc.TLS {
		t.Fatalf("expected a TLS service, got %+v", svc)
	}
	for k, want := range map[string]any{
		"tls.cert.serial":      "-7efdfcfbfaf9f8f8",
		"tls.cert.subject.cn":  "sloppy.example",
		"tls.cert.sha256":      sha256Hex(cert.Certificate[0]),
		"tls.cert.sha1":        sha1Hex(cert.Certificate[0]),
		"tls.cert.self_signed": true,
		"http.status_code":     200,
		"http.title":           "NKW — Autonomous Penetration Testing Console",
	} {
		if svc.Fields[k] != want {
			t.Errorf("%s = %#v, want %#v", k, svc.Fields[k], want)
		}
	}
}

// A certificate crypto/x509 can't parse at all (here: a padded serial) ends
// the handshake. The service is still TLS and gets no plaintext request; the
// certificate hashes are read from the handshake where TLS 1.2 shows them.
func TestProbeTLSUnparsableCertificate(t *testing.T) {
	cert := certWithSerial(t, [8]byte{0, 2, 3, 4, 5, 6, 7, 8})
	if _, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
		t.Fatal("the test certificate parses")
	}
	for _, tt := range []struct {
		name     string
		min, max uint16
		hashes   bool
	}{
		{"tls12", 0, tls.VersionTLS12, true},
		{"tls12 and tls13", 0, 0, true},
		{"tls13", tls.VersionTLS13, 0, false}, // the certificate is encrypted
	} {
		t.Run(tt.name, func(t *testing.T) {
			host, port := tlsPanel(t, cert, tt.min, tt.max)
			svc := testProber(Needs{TLS: true, HTTP: true, Favicon: true}).Probe(context.Background(), host, port)
			if svc == nil || !svc.TLS {
				t.Fatalf("expected a TLS service, got %+v", svc)
			}
			want := map[string]any{"service.port": port, "service.transport": "tcp"}
			if tt.hashes {
				want["tls.cert.sha256"] = sha256Hex(cert.Certificate[0])
				want["tls.cert.sha1"] = sha1Hex(cert.Certificate[0])
			}
			if len(svc.Fields) != len(want) {
				t.Errorf("fields = %#v, want %#v", svc.Fields, want)
			}
			for k, v := range want {
				if svc.Fields[k] != v {
					t.Errorf("%s = %#v, want %#v", k, svc.Fields[k], v)
				}
			}
		})
	}
}

// The same when only a later certificate of the chain can't be parsed: the
// service's own certificate is still read.
func TestProbeTLSUnparsableChain(t *testing.T) {
	cert := certWithSerial(t, [8]byte{9, 2, 3, 4, 5, 6, 7, 8})
	cert.Certificate = append(cert.Certificate, certWithSerial(t, [8]byte{0, 2, 3, 4, 5, 6, 7, 8}).Certificate[0])
	host, port := tlsPanel(t, cert, 0, 0)

	svc := testProber(Needs{TLS: true, HTTP: true}).Probe(context.Background(), host, port)
	if svc == nil || !svc.TLS {
		t.Fatalf("expected a TLS service, got %+v", svc)
	}
	for k, want := range map[string]any{
		"tls.cert.serial":     "902030405060708",
		"tls.cert.subject.cn": "sloppy.example",
		"tls.cert.sha256":     sha256Hex(cert.Certificate[0]),
		"http.status_code":    nil,
	} {
		if svc.Fields[k] != want {
			t.Errorf("%s = %#v, want %#v", k, svc.Fields[k], want)
		}
	}
}

// A peer that answers the ClientHello with a TLS alert speaks TLS. It is not
// probed in plaintext.
func TestProbeTLSAlert(t *testing.T) {
	var plaintext atomic.Bool
	host, port := listen(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		if bytes.HasPrefix(buf[:n], []byte("GET ")) {
			plaintext.Store(true)
			return
		}
		c.Write([]byte{21, 3, 3, 0, 2, 2, 40}) // fatal handshake_failure
	})
	svc := testProber(Needs{TLS: true, HTTP: true}).Probe(context.Background(), host, port)
	if svc == nil || !svc.TLS {
		t.Fatalf("expected a TLS service, got %+v", svc)
	}
	if plaintext.Load() {
		t.Error("plaintext HTTP sent to a TLS service")
	}
}
