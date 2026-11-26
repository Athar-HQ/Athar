package rule

import "strings"

// RawResponse returns a test's raw HTTP response as the bytes a server sent
// (spec section 9). The head is everything up to and including the first
// empty line. A head without a CR was written with YAML line ends: every LF
// in it is read as CRLF, and the empty line is added if the text ends before
// it. A head with a CR, and the body in every case, are taken byte for byte.
func RawResponse(raw string) []byte {
	head, body, ended := raw, "", false
	for i := 0; i < len(raw); {
		n := strings.IndexByte(raw[i:], '\n')
		if n < 0 {
			break
		}
		if line := raw[i : i+n]; line == "" || line == "\r" {
			head, body, ended = raw[:i+n+1], raw[i+n+1:], true
			break
		}
		i += n + 1
	}
	if head == "" || strings.Contains(head, "\r") {
		return []byte(raw)
	}
	head = strings.ReplaceAll(head, "\n", "\r\n")
	if !ended {
		if !strings.HasSuffix(head, "\r\n") {
			head += "\r\n"
		}
		head += "\r\n"
	}
	return []byte(head + body)
}
