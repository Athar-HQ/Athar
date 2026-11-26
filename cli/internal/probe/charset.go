package probe

import (
	"bytes"
	"mime"
	"strings"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/htmlindex"
)

// decodeBody returns the body as UTF-8 text (spec section 5). The charset is
// the one the response declares: in the Content-Type header, else in a
// <meta> tag at the start of the page, else with a UTF-16 byte order mark.
// It is never guessed from the content. A body that declares UTF-8, nothing,
// or only labels without a decoder is returned as received.
func decodeBody(contentType string, body []byte) []byte {
	var enc encoding.Encoding
	if _, params, err := mime.ParseMediaType(contentType); err == nil {
		enc = charsetByLabel(params["charset"])
	}
	if enc == nil {
		enc = metaCharset(body)
	}
	if enc == nil {
		switch {
		case bytes.HasPrefix(body, []byte("\xfe\xff")):
			enc = charsetByLabel("utf-16be")
		case bytes.HasPrefix(body, []byte("\xff\xfe")):
			enc = charsetByLabel("utf-16le")
		}
	}
	if enc == nil || charsetName(enc) == "utf-8" {
		return body
	}
	text, err := enc.NewDecoder().Bytes(body)
	if err != nil {
		return body
	}
	return text
}

// charsetByLabel returns the encoding an HTML encoding label names, or nil
// if the label is unknown or names an encoding that has no decoder (the
// standard's "replacement" encoding, for labels such as iso-2022-kr).
func charsetByLabel(label string) encoding.Encoding {
	enc, err := htmlindex.Get(label)
	if err != nil || charsetName(enc) == "replacement" {
		return nil
	}
	return enc
}

func charsetName(enc encoding.Encoding) string {
	name, _ := htmlindex.Name(enc)
	return name
}

// metaCharset is the HTML standard's prescan: it returns the encoding of the
// first <meta charset> or <meta http-equiv="Content-Type" content="...;
// charset=..."> in the first 1024 bytes that names a known encoding, or nil.
func metaCharset(body []byte) encoding.Encoding {
	b := body[:min(len(body), 1024)]
	for i := 0; i < len(b); i++ {
		if b[i] != '<' {
			continue
		}
		rest := b[i:]
		switch {
		case bytes.HasPrefix(rest, []byte("<!--")):
			end := bytes.Index(rest[2:], []byte("-->"))
			if end < 0 {
				return nil
			}
			i += 2 + end + 2
		case len(rest) > 5 && bytes.EqualFold(rest[:5], []byte("<meta")) && (htmlSpace(rest[5]) || rest[5] == '/'):
			var label string
			var pragma, needPragma, known bool
			seen := map[string]bool{}
			i += 5
			for {
				var name, value string
				if name, value, i = htmlAttribute(b, i); name == "" {
					break
				}
				if seen[name] {
					continue
				}
				seen[name] = true
				switch name {
				case "http-equiv":
					pragma = value == "content-type"
				case "content":
					if c := contentCharset(value); c != "" && !known {
						label, needPragma, known = c, true, true
					}
				case "charset":
					label, needPragma, known = value, false, true
				}
			}
			if i < 0 {
				return nil
			}
			if !known || (needPragma && !pragma) {
				continue
			}
			if enc := charsetByLabel(label); enc != nil {
				switch charsetName(enc) {
				case "utf-16be", "utf-16le": // the tag was readable, so the page is not UTF-16
					enc = charsetByLabel("utf-8")
				case "x-user-defined":
					enc = charsetByLabel("windows-1252")
				}
				return enc
			}
		case len(rest) > 1 && (asciiLetter(rest[1]) || (rest[1] == '/' && len(rest) > 2 && asciiLetter(rest[2]))):
			for i < len(b) && !htmlSpace(b[i]) && b[i] != '>' {
				i++
			}
			for name := "x"; name != ""; {
				name, _, i = htmlAttribute(b, i)
			}
			if i < 0 {
				return nil
			}
		case len(rest) > 1 && (rest[1] == '!' || rest[1] == '/' || rest[1] == '?'):
			end := bytes.IndexByte(rest, '>')
			if end < 0 {
				return nil
			}
			i += end
		}
	}
	return nil
}

// htmlAttribute is the prescan's "get an attribute": it reads one attribute
// of a tag at b[i:] and returns its lowercased name and value and the
// position after it. Without another attribute the name is "", and i is at
// the tag's '>' or, if the input ended first, -1.
func htmlAttribute(b []byte, i int) (name, value string, next int) {
	if i < 0 {
		return "", "", -1
	}
	for i < len(b) && (htmlSpace(b[i]) || b[i] == '/') {
		i++
	}
	if i < len(b) && b[i] == '>' {
		return "", "", i
	}
	var n, v []byte
	for ; ; i++ {
		switch {
		case i >= len(b):
			return "", "", -1
		case b[i] == '=' && len(n) > 0, htmlSpace(b[i]):
		case b[i] == '/', b[i] == '>':
			return string(n), "", i
		default:
			n = append(n, lower(b[i]))
			continue
		}
		break
	}
	for i < len(b) && htmlSpace(b[i]) {
		i++
	}
	if i >= len(b) {
		return "", "", -1
	}
	if b[i] != '=' {
		return string(n), "", i
	}
	for i++; i < len(b) && htmlSpace(b[i]); i++ {
	}
	if i >= len(b) {
		return "", "", -1
	}
	switch q := b[i]; q {
	case '"', '\'':
		for i++; i < len(b); i++ {
			if b[i] == q {
				return string(n), string(v), i + 1
			}
			v = append(v, lower(b[i]))
		}
		return "", "", -1
	case '>':
		return string(n), "", i
	}
	for ; i < len(b); i++ {
		if htmlSpace(b[i]) || b[i] == '>' {
			return string(n), string(v), i
		}
		v = append(v, lower(b[i]))
	}
	return "", "", -1
}

// contentCharset reads the charset out of a lowercased meta content value
// such as "text/html; charset=gbk", as the HTML standard does, or returns "".
func contentCharset(s string) string {
	for {
		i := strings.Index(s, "charset")
		if i < 0 {
			return ""
		}
		s = strings.TrimLeft(s[i+len("charset"):], "\t\n\f\r ")
		if !strings.HasPrefix(s, "=") {
			continue
		}
		s = strings.TrimLeft(s[1:], "\t\n\f\r ")
		if s != "" && (s[0] == '"' || s[0] == '\'') {
			end := strings.IndexByte(s[1:], s[0])
			if end < 0 {
				return ""
			}
			return s[1 : 1+end]
		}
		if end := strings.IndexAny(s, "\t\n\f\r ;"); end >= 0 {
			s = s[:end]
		}
		return s
	}
}

func htmlSpace(c byte) bool {
	return c == '\t' || c == '\n' || c == '\f' || c == '\r' || c == ' '
}

func asciiLetter(c byte) bool { return 'a' <= lower(c) && lower(c) <= 'z' }

func lower(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
