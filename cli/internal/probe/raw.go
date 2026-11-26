package probe

import (
	"bufio"
	"net"

	"github.com/Athar-HQ/Athar/cli/internal/eval"
)

// HTTPFields returns the fields the scanner derives from one HTTP response,
// given as received: status line, header lines and body. Rule tests use it
// for their raw responses. The bytes are served on an in-memory connection
// and read by the code that reads a live service, so both give the same
// fields.
func HTTPFields(raw []byte) (eval.Fields, error) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		br := bufio.NewReader(server)
		for { // read the request away
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		server.Write(raw)
	}()
	resp, err := httpExchange(client, "raw", "GET", "/", nil, "athar")
	if err != nil {
		return nil, err
	}
	f := eval.Fields{}
	resp.fields(f)
	return f, nil
}
