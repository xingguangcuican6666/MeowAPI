/*
Copyright (C) 2026 xingguangcuican6666

This file is part of MeowAPI, which is licensed under the GNU Affero General
Public License v3.0.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package abi

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// HTTP/1.1 framing, for a module that dials a provider through the kernel's socket.
//
// This file exists because of what a module does NOT have. The kernel hands it a byte
// pipe: SyscallNetDial returns an FD, SyscallNetWrite and SyscallNetRead move bytes, and
// one Read is one Read syscall on the socket with no buffering and no partial-message
// assembly. There is no net/http reachable from a module - a module that imported it
// itself would get a TLS client outside every control in knet and invisible to the egress
// ledger - and no HTTP framing anywhere else in the build. So the framing is here, as
// pure functions over byte slices, in the package a component is allowed to import.
//
// It is deliberately not a client. There is no dial, no goroutine, no deadline, no
// retry: those belong to the socket the kernel owns, and a second implementation of them
// here would be a second place for a timeout to be wrong. What is here is the two things
// a caller cannot reasonably write per vendor: an unambiguous request encoding that
// refuses to emit an injection, and an incremental reader that turns arbitrary chunks
// into a status, headers and a decoded body.
//
// Nothing vendor-specific is in this file, and that is a rule rather than an omission.
// A provider's request and response shapes belong to the adapter component, because a
// vendor changes a schema without this kernel changing, and a type here would put that
// schema in a package every module recompiles against - which is the invalidation this
// package exists to prevent.

// ErrHTTPHeaderInjection is returned when a caller supplies a method, path, header name or
// header value that would let it write a second message into one connection.
//
// It is a named sentinel because the caller has to be able to tell it from every other
// refusal: an injection is a bug in the adapter's own construction of a request, while a
// malformed response is a problem with the peer. The two want different handling, and one
// of them wants an operator.
//
// No error text in this file carries the offending value. These errors reach a module's
// log line and from there the kernel console, and a console line is text an operator
// trusts - echoing the bytes an attacker chose is how that trust is spent.
var ErrHTTPHeaderInjection = errors.New("abi: a request field would inject a second message")

// ErrHTTPMalformed is returned when a peer's response is not HTTP/1.1 as this file reads
// it. It says nothing about which byte was wrong, for the reason ErrHTTPHeaderInjection
// gives.
var ErrHTTPMalformed = errors.New("abi: the response is not well-formed HTTP/1.1")

// ErrHTTPTooLarge is returned when a response exceeds a ceiling: the caller's on the
// body, this file's on the head. It is distinct from ErrHTTPMalformed because it is not
// the peer's fault: a deployment limits response size, and a limit reached is a decision
// rather than a defect.
var ErrHTTPTooLarge = errors.New("abi: the response exceeds a ceiling")

// There is deliberately no ErrHTTPIncomplete. "Need more bytes" is not an error, and a
// sentinel that means "nothing is wrong" is a trap: the natural caller writes
// `if err := resp.Feed(b); err != nil { return err }`, which then aborts every response
// that arrives in more than one chunk - over SyscallNetRead, every response. Feed returns
// nil when it consumed what it was given and wants more, and HeadComplete and Complete
// are the questions to ask instead.

// maxHTTPHeaderLineLen bounds one header line, and one chunk-size or trailer line. A peer
// that never sends a newline must not make a reader allocate without bound, and 8 KiB is
// what Go's own server uses as its per-line default rather than a number chosen here.
const maxHTTPHeaderLineLen = 8 << 10

// maxHTTPHeadBytes bounds the whole head: the status line, every field, and the trailer
// section of a chunked body. It is a different resource from the per-line bound and both
// are needed, because a peer that sends ten thousand one-byte lines stays inside
// maxHTTPHeaderLineLen on every line while growing the head without limit.
const maxHTTPHeadBytes = 64 << 10

// maxHTTPInformational bounds how many 1xx responses one reader skips before the final
// one. A peer could otherwise keep this reader parsing forever, which costs no memory
// once the head is discarded and so is invisible to every other bound here.
const maxHTTPInformational = 8

// HTTPHeader is one header field. The collection is a slice rather than a map, and the
// reason is a property a map cannot have: repeated fields are legal and ordered, and
// `Set-Cookie` is the common case. A map also cannot preserve the caller's order, which
// matters for a signature that covers the header set.
type HTTPHeader struct {
	Name  string
	Value string
}

// HTTPRequest is one outbound request, as data. Header is applied in the order given,
// after the required fields this file emits, so a caller's duplicate cannot land before
// the framework's own.
type HTTPRequest struct {
	Method string
	// Path is the request target. It must start with "/" - an absolute form would let a
	// caller address a different origin through a proxy, which is not a request this
	// stack's allowlist was reviewed against.
	Path string
	// Host is the authority. It is written as the `Host:` field unless the caller supplied
	// one in Header, in which case that one is used and the two must agree.
	Host string
	// Header carries caller-supplied fields. Names are emitted in the order given.
	Header []HTTPHeader
	// Body, when non-nil, is written verbatim after the headers.
	Body []byte
}

// Encode renders the request to the bytes to hand to SyscallNetWrite.
//
// Every field is checked for the one thing that turns a request into two: a CR or LF
// where the protocol does not allow one. A header value containing a newline is the
// classic request-smuggling primitive - the peer parses the remainder as a second
// request, and on a connection a pool later reuses, that second request is attributed to
// whoever draws the socket next. Checking the method, the path and the host too is not
// thoroughness for its own sake: each is written to the wire in a position where a
// newline would begin a new line of the message.
func (r HTTPRequest) Encode() ([]byte, error) {
	if r.Method == "" {
		return nil, fmt.Errorf("%w: a request needs a method", ErrHTTPHeaderInjection)
	}
	if err := httpToken(r.Method); err != nil {
		return nil, fmt.Errorf("%w: the method is not a token", ErrHTTPHeaderInjection)
	}
	if !strings.HasPrefix(r.Path, "/") {
		return nil, fmt.Errorf("%w: the path must be an absolute path starting with %q",
			ErrHTTPHeaderInjection, "/")
	}
	// A space ends the request-target, so "/a b" is not one target with a space in it:
	// the peer reads "/a" as the target and "b" where the version belongs, which is a
	// second message's worth of positions written into one line.
	if strings.Contains(r.Path, " ") {
		return nil, fmt.Errorf("%w: the path contains a space, which ends the request target",
			ErrHTTPHeaderInjection)
	}
	if err := httpNoCtl(r.Path); err != nil {
		return nil, fmt.Errorf("%w: the path contains a control character", ErrHTTPHeaderInjection)
	}
	if err := httpNoCtl(r.Host); err != nil {
		return nil, fmt.Errorf("%w: the host contains a control character", ErrHTTPHeaderInjection)
	}
	if r.Host == "" {
		// Refused rather than emitted without a Host field. RFC 7230 5.4 requires one from a
		// client, and a peer that does not require it would treat the request as HTTP/1.0 -
		// a downgrade of the very connection the kernel just validated a certificate
		// against. A caller dialing through SyscallNetDial always knows the host: it is the
		// one it declared.
		return nil, fmt.Errorf("%w: a request needs a host", ErrHTTPHeaderInjection)
	}
	if strings.ContainsAny(r.Host, " /") {
		return nil, fmt.Errorf("%w: the host must be an authority without a space or a path",
			ErrHTTPHeaderInjection)
	}

	// One pass over the caller's fields collects the three that decide the message's
	// shape, because each of them is a way to make two parsers disagree about where this
	// request ends - and a disagreement about that, on a connection the kernel's pool
	// later hands to another module, is the smuggling primitive this file exists to
	// refuse. The framework's own fields are written first, so a caller's duplicate
	// cannot precede them.
	frame, err := httpFrameOf(r.Host, r.Header)
	if err != nil {
		return nil, err
	}
	if err := frame.check(len(r.Body)); err != nil {
		return nil, err
	}

	var b strings.Builder
	b.Grow(len(r.Path) + len(r.Host) + len(r.Body) + 128)
	b.WriteString(r.Method)
	b.WriteByte(' ')
	b.WriteString(r.Path)
	b.WriteString(" HTTP/1.1\r\n")

	if !frame.hostSupplied {
		b.WriteString("Host: ")
		b.WriteString(r.Host)
		b.WriteString("\r\n")
	}
	for _, h := range r.Header {
		if err := httpHeader(h); err != nil {
			return nil, err
		}
		b.WriteString(h.Name)
		b.WriteString(": ")
		b.WriteString(h.Value)
		b.WriteString("\r\n")
	}

	// Content-Length is the caller's to set, and it is not inferred here. Inferring it
	// would be convenient and wrong for the case that matters: a request whose body is
	// streamed by the caller in pieces does not know its length when the head is written,
	// and a framework that guessed would emit a length the body does not have. What is
	// checked instead is the one shape that always hangs, in httpFrame.check.
	b.WriteString("\r\n")
	b.Write(r.Body)
	return []byte(b.String()), nil
}

// httpFrame is what one pass over the caller's fields decides about the message's shape.
type httpFrame struct {
	// hostSupplied records that the caller wrote its own Host field, which suppresses
	// the one Encode would otherwise emit for r.Host.
	hostSupplied bool
	// length is the declared Content-Length, or -1 when the caller declared none.
	length int64
	// chunked records a Transfer-Encoding naming chunked.
	chunked bool
}

// httpFrameOf collects the framing fields. It refuses a shape whose meaning two
// conforming parsers could read differently, and it is a separate pass rather than a
// check inside the write loop because the decision has to be made before any byte is
// committed: a half-written head cannot be taken back.
func httpFrameOf(host string, hs []HTTPHeader) (httpFrame, error) {
	f := httpFrame{length: -1}
	var sawLength, sawEncoding bool
	for _, h := range hs {
		switch {
		case strings.EqualFold(h.Name, "Host"):
			if f.hostSupplied {
				return f, fmt.Errorf("%w: two Host fields", ErrHTTPHeaderInjection)
			}
			f.hostSupplied = true
			// A caller-supplied Host must agree with the authority this request names,
			// because two disagreeing Host fields is a smuggling primitive in its own
			// right: a proxy and an origin that pick different ones route the same bytes
			// to different places.
			if !strings.EqualFold(strings.TrimSpace(h.Value), strings.TrimSpace(host)) {
				return f, fmt.Errorf("%w: the declared host and the Host field disagree",
					ErrHTTPHeaderInjection)
			}
		case strings.EqualFold(h.Name, "Content-Length"):
			if sawLength {
				// Refused even when the two values agree. A duplicate field is not
				// something a caller means to send, and a framework that quietly accepted
				// the pair would be the reason a later edit that made them differ still
				// produced a request somebody parsed.
				return f, fmt.Errorf("%w: two Content-Length fields", ErrHTTPHeaderInjection)
			}
			sawLength = true
			n, err := strconv.ParseInt(strings.TrimSpace(h.Value), 10, 64)
			if err != nil || n < 0 {
				return f, fmt.Errorf("%w: Content-Length is not a non-negative integer",
					ErrHTTPHeaderInjection)
			}
			f.length = n
		case strings.EqualFold(h.Name, "Transfer-Encoding"):
			if sawEncoding {
				return f, fmt.Errorf("%w: two Transfer-Encoding fields", ErrHTTPHeaderInjection)
			}
			sawEncoding = true
			// Parsed as a list of codings rather than searched for a substring, and the list
			// is validated in full. "chunked, " is a field whose value is not a list of
			// codings, and accepting it would mean emitting a Transfer-Encoding the peer has
			// to guess at while this file believes the body is chunk-framed.
			chunked, reason := httpCodings(h.Value)
			if reason != "" {
				return f, fmt.Errorf("%w: %s", ErrHTTPHeaderInjection, reason)
			}
			f.chunked = chunked
		}
	}
	return f, nil
}

// httpCodings reads a Transfer-Encoding value and reports whether chunked is the coding
// that frames this message.
//
// It returns a reason rather than an error because the two callers owe different answers to
// the same malformed value: a module that WROTE one is at fault (ErrHTTPHeaderInjection) and
// a peer that SENT one is not (ErrHTTPMalformed). Two sentinels over one rule, so the rule
// cannot drift between the request and the response side - which is the drift that matters
// here, since a value one side accepts and the other refuses is a value two parsers
// disagree about.
//
// The two rules are RFC 7230's: every element of the list is a token, so an empty element
// is not a coding, and chunked has to be the outermost coding because it frames the message
// and a coding after it would mean the bytes this reader de-chunks are framed again by
// something neither side implements.
func httpCodings(value string) (chunked bool, reason string) {
	parts := strings.Split(value, ",")
	for i, part := range parts {
		tok := strings.TrimSpace(part)
		if !httpIsToken(tok) {
			return false, "a transfer coding is not a token"
		}
		if !strings.EqualFold(tok, "chunked") {
			continue
		}
		if i != len(parts)-1 {
			return false, "chunked is not the last transfer coding"
		}
		chunked = true
	}
	return chunked, ""
}

// check is the framing decision, taken once the head's fields are known and the length of
// the body written with it is known. Each refusal is a request that one peer would read as
// two, so the reason is stated in terms of what the peer does rather than of what rule the
// caller broke.
func (f httpFrame) check(bodyLen int) error {
	if f.chunked && f.length >= 0 {
		// RFC 7230 3.3.3 tells a recipient to let Transfer-Encoding win, and tells it to
		// consider closing the connection because the sender may have been attempting to
		// smuggle. This file takes the second half of that advice as the first: a request
		// carrying both is refused rather than emitted with a rule about which wins,
		// because an intermediary between here and the vendor is free to pick the other
		// one, and the two then disagree about where this body ends.
		return fmt.Errorf("%w: Content-Length and Transfer-Encoding together", ErrHTTPHeaderInjection)
	}
	if bodyLen > 0 && f.length < 0 && !f.chunked {
		// The shape that always hangs. The peer reads a request with no body and then
		// waits on a connection nothing closes; the vendor times out and the adapter
		// reports a network error, which is a worse diagnosis than this one.
		return fmt.Errorf("%w: a body requires Content-Length or Transfer-Encoding",
			ErrHTTPMalformed)
	}
	if f.length >= 0 && f.length < int64(bodyLen) {
		// The declared length is SHORTER than the bytes this call writes after the blank
		// line. The peer reads f.length bytes as this request's body and then parses the
		// surplus as the start of a second request on a connection the pool may hand to
		// another module. A length LONGER than the body is legal and is the streaming case:
		// the caller writes the rest through further SyscallNetWrite calls.
		return fmt.Errorf("%w: Content-Length is shorter than the body written with it",
			ErrHTTPHeaderInjection)
	}
	return nil
}

// SetContentLength sets the Content-Length field to the length of a body the caller has
// in hand, replacing a value already there.
//
// It exists so a caller never writes the number by hand. The failure it prevents is the
// one no test catches until production: a body edited after the length was computed, or a
// length computed in bytes from a string whose length was measured in runes. It replaces
// rather than appends because a caller that recomputes after an edit would otherwise
// leave both fields, and Encode refuses a duplicate.
func (r *HTTPRequest) SetContentLength(n int) {
	for i := range r.Header {
		if strings.EqualFold(r.Header[i].Name, "Content-Length") {
			r.Header[i].Value = strconv.Itoa(n)
			return
		}
	}
	r.Header = append(r.Header, HTTPHeader{Name: "Content-Length", Value: strconv.Itoa(n)})
}

// SetContentLengthOf is SetContentLength for a body already built, and it is the form to
// prefer: it measures the bytes it is declaring rather than trusting a number passed
// beside them.
func (r *HTTPRequest) SetContentLengthOf(body []byte) { r.SetContentLength(len(body)) }

// httpHeader validates one field. The name must be a token and the value must contain no
// control character; both refusals exist because each is written to the wire verbatim.
func httpHeader(h HTTPHeader) error {
	if h.Name == "" {
		return fmt.Errorf("%w: a header field has no name", ErrHTTPHeaderInjection)
	}
	if err := httpToken(h.Name); err != nil {
		return fmt.Errorf("%w: a header name is not a token", ErrHTTPHeaderInjection)
	}
	// A tab is legal inside a field value per RFC 7230 and is allowed. Everything below
	// 0x20 other than tab, plus DEL, is not, and CR LF are the two that matter.
	for i := 0; i < len(h.Value); i++ {
		if c := h.Value[i]; (c < 0x20 && c != '\t') || c == 0x7f {
			return fmt.Errorf("%w: a header value contains a control character", ErrHTTPHeaderInjection)
		}
	}
	return nil
}

// httpNoCtl refuses any control character, for the fields where even a tab is not allowed.
func httpNoCtl(s string) error {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			return fmt.Errorf("%w: a control character", ErrHTTPHeaderInjection)
		}
	}
	return nil
}

// httpIsToken reports whether s is an RFC 7230 token. It is a closed character class
// rather than a "no space" check because the tchar set is what the parser on the other
// end accepts, and this file's job is to emit only what a conforming parser reads.
//
// It is a predicate, and the two callers wrap it with different sentinels: a token this
// file was asked to WRITE is the caller's fault (ErrHTTPHeaderInjection), and one this
// file READ is the peer's (ErrHTTPMalformed). One character class and two error values,
// because the two want different handling and conflating them would tell an operator that
// a vendor's malformed response was a bug in the adapter.
func httpIsToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// httpToken is httpIsToken's caller-side refusal.
func httpToken(s string) error {
	if !httpIsToken(s) {
		if s == "" {
			return fmt.Errorf("%w: empty", ErrHTTPHeaderInjection)
		}
		return fmt.Errorf("%w: a character outside the token set", ErrHTTPHeaderInjection)
	}
	return nil
}

// HTTPResponse is a parsed response head, plus the decoder state needed to read its body.
//
// A caller creates one with NewHTTPResponseReader, feeds it whatever SyscallNetRead
// returned, and asks whether the head is complete. Once it is, Status, Header and the body
// decoder are available. The type is deliberately not safe for concurrent use: a response
// belongs to one request on one socket, and a mutex here would suggest a sharing model
// this file does not have.
//
// The loop a caller writes is the loop the kernel's read syscall forces:
//
//	resp, err := abi.NewHTTPResponseReader(1 << 20)
//	for !resp.Complete() {
//	    b, err := ctx.SyscallNetRead(fd, 16<<10)
//	    if len(b) > 0 {
//	        if ferr := resp.Feed(b); ferr != nil {
//	            return ferr
//	        }
//	    }
//	    if err != nil {
//	        if errors.Is(err, abi.ErrNetPeerClosed) {
//	            resp.Close()
//	            break
//	        }
//	        return err
//	    }
//	}
//
// Feed is a separate call from Close, and not Close taking the last buffer, because the
// read loop has to handle a syscall that returns bytes AND an error in one call. The
// kernel's NetRead is shaped that way by contract even though measured today no transport
// it offers produces it - a FIN surfaces on the read after the one that returned the data.
// A loop written against the contract stays correct if that ever changes; one that assumed
// bytes and errors are mutually exclusive would drop the bytes.
type HTTPResponse struct {
	// Status is the numeric status code, and zero until the status line has been parsed.
	// Zero is not a usable "not parsed yet" marker on its own, because the grammar allows a
	// peer to send "000" - which is why sawStatus is a separate field rather than a test of
	// this one. Nothing in this file branches on Status being zero.
	Status int
	// Reason is the reason phrase, which RFC 7230 says may be empty and which no caller
	// should branch on. It is here because a human reads it in a log line.
	Reason string
	// Header is the parsed fields, in the order received. Trailer fields are NOT appended
	// here: a trailer naming a field the head already carried would change what Values
	// returns to a caller that reads headers after the body, which is a way for the peer
	// to make one answer depend on when it was asked.
	Header []HTTPHeader

	// buf holds bytes fed but not yet consumed by the parser.
	buf []byte
	// headBytes counts the head bytes consumed so far, so a peer that sends many short
	// complete lines is bounded by the same ceiling as one that sends no newline at all.
	headBytes int
	// headDone is set once the blank line ended the head.
	headDone bool
	// sawStatus records that a status line has been parsed, which is what tells the head
	// parser whether the next line is a status line or a field. It is not derived from
	// Status being non-zero, because a peer may send a status code of 000 and the two
	// questions - "have I read a status line" and "what status did it name" - then have
	// different answers.
	sawStatus bool
	// sawTE records a Transfer-Encoding field, to refuse a second one.
	sawTE bool
	// chunked is set when the response used Transfer-Encoding: chunked.
	chunked bool
	// length is the Content-Length, or -1 when the body is delimited by closing.
	length int64
	// remaining is how many body bytes are still expected when length >= 0.
	remaining int64
	// body holds the decoded bytes the caller has not taken.
	body []byte
	// bodyDone is set when the body is complete: length satisfied, the chunk terminator
	// seen, or the caller signalled the connection closed.
	bodyDone bool
	// chunkLeft is how many bytes of the current chunk are still to come.
	chunkLeft int64
	// awaitChunkCRLF records that a chunk's data is complete and its trailing CRLF has not
	// been consumed yet. chunkLeft cannot carry that state: zero means both "no chunk in
	// progress" and "this chunk is finished", and the second one has a terminator still to
	// eat. Without the flag a reader fed one byte at a time treats the pending CRLF as a
	// size line, and the empty line it reads is refused as an empty chunk size - which is a
	// correct refusal of a parse that should never have started.
	awaitChunkCRLF bool
	// chunkTrailer is set while reading the trailer section after the last chunk.
	chunkTrailer bool
	// infoSkipped counts the 1xx responses discarded before the final one.
	infoSkipped int
	// closed records that the caller signalled the end of the connection.
	closed bool
	// truncated records that the connection ended before the framing's own terminator, so
	// a caller can tell "the peer sent a short body" from "the body is complete".
	truncated bool
	// err latches the first refusal. Without it a caller that keeps reading after an
	// error would re-parse the same buffer and could get a different answer - a ceiling
	// hit on one Feed and a clean parse on the next, because the bytes that exceeded it
	// were consumed by the failed attempt.
	err error
	// maxBody is the caller's ceiling on the decoded body bytes this reader holds at once.
	// It is stored at construction and never reassigned, so a caller cannot raise its own
	// limit partway through a response by calling Feed again with a bigger number.
	maxBody int64
}

// NewHTTPResponseReader returns a reader for one response with a ceiling on the body bytes
// it holds at once.
//
// maxBody is required and must be positive. A zero would mean "no limit", and a limit of
// none is how a peer that never closes exhausts a module's heap one read at a time - the
// kernel bounds one READ, not a response, so the total is the caller's to bound and the
// caller has no way to know the right number without being made to choose.
//
// The ceiling counts what the reader is holding, not everything the response will ever
// contain, and that is what makes a long stream work: TakeBody drains, so a server-sent
// event stream of any length runs under a modest ceiling, while a caller that never
// drains is bounded no matter how much the peer sends.
func NewHTTPResponseReader(maxBody int64) (*HTTPResponse, error) {
	if maxBody <= 0 {
		return nil, fmt.Errorf("%w: a body ceiling is required and must be positive", ErrHTTPTooLarge)
	}
	return &HTTPResponse{length: -1, maxBody: maxBody}, nil
}

// Feed gives the reader the bytes one SyscallNetRead returned.
//
// It returns nil when the bytes were consumed and more are needed, which is the ordinary
// case and not an error: a response arriving in pieces is every response over this
// syscall, since one Read is one read syscall with no buffering behind it. Ask
// HeadComplete and Complete rather than treating a nil error as "finished".
//
// Once it has returned an error it keeps returning that same error and consumes nothing,
// so a caller's read loop can return on the first failure without first checking whether
// the reader is still usable. Feeding after Close is refused for the same reason and with
// the same latch: the connection has ended, so no byte arriving afterwards belongs to this
// response, and accepting one would let a caller that reuses a closed reader silently
// parse a second response into a first response's status and headers.
//
// Feeding after Complete is refused too. Nothing parses it any more, so accepting it would
// mean buffering bytes with no bound: the body ceiling counts decoded body, the head bound
// counts head lines, and a reader that is finished is counted by neither. The bytes a
// caller actually wants at that point are already in Pending, which is where the next
// response starts from.
func (r *HTTPResponse) Feed(p []byte) error {
	if r.err != nil {
		return r.err
	}
	if r.closed {
		r.err = fmt.Errorf("%w: the connection ended, so no further bytes belong to it",
			ErrHTTPMalformed)
		return r.err
	}
	if r.Complete() {
		r.err = fmt.Errorf("%w: the response is complete, so no further bytes belong to it; "+
			"what remains is in Pending", ErrHTTPMalformed)
		return r.err
	}
	if len(p) > 0 {
		r.buf = append(r.buf, p...)
	}
	if !r.headDone {
		if err := r.parseHead(); err != nil {
			r.err = err
			return err
		}
	}
	if r.headDone && !r.bodyDone {
		if err := r.parseBody(); err != nil {
			r.err = err
			return err
		}
	}
	return nil
}

// httpCRLF is the only line terminator this reader accepts.
//
// A bare LF is refused rather than tolerated, and RFC 7230 3.5 permits a recipient to
// tolerate it. The reason is that tolerance is only safe for the LAST parser of some
// bytes, and this one is not always that: a deployment behind an intercepting proxy has
// two parsers reading the same stream, and a proxy that splits on LF while this reader
// waits for CRLF is the classic desynchronization - the two then disagree about where one
// message ends and the next begins. Accepting only CRLF means there is one reading of any
// byte sequence this reader accepts.
var httpCRLF = []byte("\r\n")

// httpCutLine splits buf at the first CRLF, returning the line without it and the rest.
func httpCutLine(buf []byte) (line, rest []byte, ok bool) {
	i := bytes.Index(buf, httpCRLF)
	if i < 0 {
		return nil, nil, false
	}
	return buf[:i], buf[i+len(httpCRLF):], true
}

// httpLineOK refuses a line holding a bare CR or LF. httpCutLine only ever splits on the
// pair, so a line containing either one is a line the peer terminated differently from
// the way this reader reads terminators, and accepting it would mean two readings of the
// same bytes.
func httpLineOK(line []byte) bool {
	return bytes.IndexByte(line, '\n') < 0 && bytes.IndexByte(line, '\r') < 0
}

// parseHead consumes the status line and every field up to the blank line. It is a loop
// rather than a single pass because a 1xx response ends at a blank line that is not the
// end of the head the caller wants, and because the loop can return partway through and
// resume on the next Feed: what has been consumed lives in the struct, not in locals.
func (r *HTTPResponse) parseHead() error {
	for {
		line, rest, ok := httpCutLine(r.buf)
		if !ok {
			return r.boundHead()
		}
		if !httpLineOK(line) {
			return fmt.Errorf("%w: a line is not terminated by CRLF", ErrHTTPMalformed)
		}
		r.buf = rest
		r.headBytes += len(line) + len(httpCRLF)
		if r.headBytes > maxHTTPHeadBytes {
			return fmt.Errorf("%w: the head exceeds %d bytes", ErrHTTPTooLarge, maxHTTPHeadBytes)
		}

		if !r.sawStatus {
			if err := r.parseStatusLine(line); err != nil {
				return err
			}
			r.sawStatus = true
			continue
		}
		if len(line) == 0 {
			if r.Status >= 100 && r.Status < 200 {
				// An informational response is discarded, and the count is bounded because
				// a peer could otherwise keep this reader parsing forever. That costs no
				// memory once the head is gone, so no other ceiling here would see it.
				r.infoSkipped++
				if r.infoSkipped > maxHTTPInformational {
					return fmt.Errorf("%w: more than %d informational responses",
						ErrHTTPTooLarge, maxHTTPInformational)
				}
				r.resetHead()
				continue
			}
			if err := r.decideFraming(); err != nil {
				return err
			}
			r.headDone = true
			return nil
		}
		if line[0] == ' ' || line[0] == '\t' {
			// Obsolete line folding. Refused rather than joined with a space: a folded
			// value is a value whose meaning depends on the reader agreeing about the
			// fold, and this file emits none, so a peer sending one is either ancient or
			// constructing a value it expects to be reinterpreted.
			return fmt.Errorf("%w: an obsolete line folding", ErrHTTPMalformed)
		}
		if err := r.parseField(line); err != nil {
			return err
		}
	}
}

// boundHead is the "no complete line yet" branch, and it still has to bound what a peer
// can make this reader hold: an unterminated line grows buf by every Feed, so the head's
// ceiling has to be checked against what is buffered as well as against what was consumed.
//
// It also refuses what it can already tell is wrong. A bare LF sitting before any CRLF
// will never become a CRLF-terminated line, and without this the reader would wait for a
// line that cannot arrive until the caller's read deadline fires - a stall reported as a
// timeout, which points at the vendor instead of at the framing. A CR at the very end is
// not treated as bare, because it may be the first half of a CRLF split across two reads.
func (r *HTTPResponse) boundHead() error {
	if r.headBytes+len(r.buf) > maxHTTPHeadBytes {
		return fmt.Errorf("%w: the head exceeds %d bytes", ErrHTTPTooLarge, maxHTTPHeadBytes)
	}
	crlf := bytes.Index(r.buf, httpCRLF)
	lf := bytes.IndexByte(r.buf, '\n')
	if lf >= 0 && (crlf < 0 || lf < crlf) {
		return fmt.Errorf("%w: a line is not terminated by CRLF", ErrHTTPMalformed)
	}
	if cr := bytes.IndexByte(r.buf, '\r'); cr >= 0 && cr < len(r.buf)-1 && (crlf < 0 || cr != crlf) {
		return fmt.Errorf("%w: a line is not terminated by CRLF", ErrHTTPMalformed)
	}
	return nil
}

// resetHead clears the per-head state so the next head in the buffer is parsed fresh.
// headBytes is deliberately NOT reset: it bounds what one reader has been made to parse in
// total, and resetting it per informational response would let a peer send maxHTTPHeadBytes
// eight times rather than once.
func (r *HTTPResponse) resetHead() {
	r.Status = 0
	r.Reason = ""
	r.Header = nil
	r.length = -1
	r.sawStatus = false
	r.sawTE = false
	r.chunked = false
}

// parseStatusLine reads "HTTP/1.1 200 OK".
//
// The version is checked against the two this reader can frame. An "HTTP/2" line means
// ALPN negotiated something other than what the kernel pins, and refusing it names that
// instead of producing a status parsed out of a frame header nobody here understands.
func (r *HTTPResponse) parseStatusLine(line []byte) error {
	s := string(line)
	sp := strings.IndexByte(s, ' ')
	if sp < 0 {
		return fmt.Errorf("%w: the status line has no status code", ErrHTTPMalformed)
	}
	if v := s[:sp]; v != "HTTP/1.1" && v != "HTTP/1.0" {
		return fmt.Errorf("%w: the status line does not name HTTP/1.1 or HTTP/1.0", ErrHTTPMalformed)
	}
	rest := s[sp+1:]
	if len(rest) < 3 {
		return fmt.Errorf("%w: the status line has no status code", ErrHTTPMalformed)
	}
	code := rest[:3]
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return fmt.Errorf("%w: the status code is not three digits", ErrHTTPMalformed)
		}
	}
	n, err := strconv.Atoi(code)
	if err != nil {
		return fmt.Errorf("%w: the status code is not a number", ErrHTTPMalformed)
	}
	// The reason phrase is optional in practice and the space before it is not, so the two
	// spellings accepted are "200 OK" and "200". Anything else means the code did not end
	// where a code ends.
	after := rest[3:]
	switch {
	case after == "":
	case after[0] == ' ':
		// The phrase is validated rather than taken verbatim. RFC 7230 3.1.2 allows HTAB, SP,
		// VCHAR and obs-text in it, and a C0 control or DEL is outside that class. The field
		// reaches a log line, so accepting a control character here would hand every caller a
		// peer-chosen string it has to escape before printing, and a caller that does not
		// would render a forged line into the kernel console.
		if err := httpReasonOK(after[1:]); err != nil {
			return err
		}
		r.Reason = after[1:]
	default:
		return fmt.Errorf("%w: the status code is not followed by a space", ErrHTTPMalformed)
	}
	r.Status = n
	return nil
}

// httpReasonOK accepts the reason-phrase class RFC 7230 defines: HTAB, SP, VCHAR and
// obs-text. It is a separate check from the field-value one because the classes differ - a
// field value forbids HTAB inside a token position but a reason phrase allows it anywhere.
func httpReasonOK(s string) error {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\t', c == ' ':
		case c >= 0x21 && c <= 0x7e:
		case c >= 0x80:
		default:
			return fmt.Errorf("%w: the reason phrase contains a control character", ErrHTTPMalformed)
		}
	}
	return nil
}

// parseField reads one "Name: value" line. The value keeps no leading or trailing
// whitespace, which is what RFC 7230 says a field-value is; interior whitespace and tabs
// are kept verbatim.
func (r *HTTPResponse) parseField(line []byte) error {
	i := bytes.IndexByte(line, ':')
	if i <= 0 {
		return fmt.Errorf("%w: a header line has no colon", ErrHTTPMalformed)
	}
	name := string(line[:i])
	if !httpIsToken(name) {
		return fmt.Errorf("%w: a header name is not a token", ErrHTTPMalformed)
	}
	value := strings.Trim(string(line[i+1:]), " \t")
	for j := 0; j < len(value); j++ {
		if c := value[j]; (c < 0x20 && c != '\t') || c == 0x7f {
			return fmt.Errorf("%w: a header value contains a control character", ErrHTTPMalformed)
		}
	}

	switch {
	case strings.EqualFold(name, "Content-Length"):
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < 0 {
			return fmt.Errorf("%w: Content-Length is not a non-negative integer", ErrHTTPMalformed)
		}
		// Duplicates that agree are accepted, because RFC 7230 3.3.2 says a recipient may
		// treat a repeated identical length as one, and refusing it would break a peer for
		// a shape the protocol permits. Duplicates that disagree are refused: that is the
		// CL.CL ambiguity, and there is no reading of it that is safe to pick.
		if r.length >= 0 && r.length != n {
			return fmt.Errorf("%w: two Content-Length fields that disagree", ErrHTTPMalformed)
		}
		r.length = n
	case strings.EqualFold(name, "Transfer-Encoding"):
		if r.sawTE {
			return fmt.Errorf("%w: two Transfer-Encoding fields", ErrHTTPMalformed)
		}
		r.sawTE = true
		// The same rule the request side applies, through the same function, so a value one
		// side accepts the other refuses cannot happen. The sentinel differs because the peer
		// is not at fault for its own malformed response.
		chunked, reason := httpCodings(value)
		if reason != "" {
			return fmt.Errorf("%w: %s", ErrHTTPMalformed, reason)
		}
		r.chunked = chunked
	}
	r.Header = append(r.Header, HTTPHeader{Name: name, Value: value})
	return nil
}

// decideFraming picks the body's delimiter once the head is complete. It is one function
// because the decision is the part that has to be exactly right: getting it wrong is not
// a parse error, it is reading the next response's head as this response's body.
func (r *HTTPResponse) decideFraming() error {
	// 204 and 304 never carry a body, and a Content-Length on one is a peer that does not
	// know what it is saying. The status decides, not the field.
	if r.Status == 204 || r.Status == 304 {
		r.length = 0
		r.remaining = 0
		r.bodyDone = true
		return nil
	}
	if r.chunked && r.length >= 0 {
		// CL.TE. RFC 7230 3.3.3 says a recipient that receives both must treat it as an
		// error and close the connection, because senders do not agree about which wins
		// and the disagreement is the smuggling primitive. Close rather than release: the
		// kernel's pool is keyed on this module's pid, so a dirty socket comes back to the
		// same module and its next response reads as the tail of this one.
		return fmt.Errorf("%w: Content-Length and Transfer-Encoding together", ErrHTTPMalformed)
	}
	if r.chunked {
		return nil
	}
	if r.length >= 0 {
		r.remaining = r.length
		if r.remaining == 0 {
			r.bodyDone = true
		}
		return nil
	}
	// Neither framing field: the body runs to the end of the connection, which is HTTP/1.0
	// behaviour and is still what a vendor does when it streams without a length. The
	// caller MUST call Close when the kernel reports the peer closed, or this response
	// never completes.
	r.length = -1
	return nil
}

// parseBody dispatches to the decoder the framing decision chose.
func (r *HTTPResponse) parseBody() error {
	switch {
	case r.chunked:
		return r.parseChunked()
	case r.length >= 0:
		return r.parseLength()
	default:
		return r.parseUntilClose()
	}
}

// parseLength copies out of buf until the declared length is satisfied.
func (r *HTTPResponse) parseLength() error {
	n := int64(len(r.buf))
	if n > r.remaining {
		n = r.remaining
	}
	if n > 0 {
		if err := r.appendBody(r.buf[:n]); err != nil {
			return err
		}
		r.buf = r.buf[n:]
		r.remaining -= n
	}
	if r.remaining == 0 {
		r.bodyDone = true
	}
	return nil
}

// parseUntilClose accumulates everything, because nothing else delimits the body.
func (r *HTTPResponse) parseUntilClose() error {
	if len(r.buf) == 0 {
		return nil
	}
	if err := r.appendBody(r.buf); err != nil {
		return err
	}
	// Cleared rather than sliced forward: a close-delimited body can be long, and holding
	// the front of the array for bytes already handed to the caller would keep the whole
	// allocation alive.
	r.buf = nil
	return nil
}

// parseChunked decodes chunk framing: a size line, that many bytes, a CRLF, and a final
// zero-size chunk followed by trailers and a blank line.
//
// Content coding is deliberately not touched. A response carrying Content-Encoding: gzip
// is de-chunked and handed over compressed, which is what the field says and what a caller
// that asked for it expects; decompressing here would mean a second implementation of
// every coding a vendor might use, in the package every module recompiles against.
func (r *HTTPResponse) parseChunked() error {
	for {
		// The terminator of a chunk whose data is already consumed. This branch is first and
		// is its own state, because chunkLeft == 0 cannot distinguish "no chunk in progress"
		// from "this chunk is finished and its CRLF is still to come". A reader fed one byte
		// at a time hits the second state with a buffer holding only the CR, and without a
		// flag it would fall through to the size-line branch and refuse the pending CRLF as
		// an empty chunk size - a correct refusal of a parse that should never have started.
		if r.awaitChunkCRLF {
			if len(r.buf) < len(httpCRLF) {
				return nil
			}
			// Its absence means the size line and the data did not agree, which is the framing
			// this decoder exists to get right.
			if !bytes.HasPrefix(r.buf, httpCRLF) {
				return fmt.Errorf("%w: a chunk is not followed by CRLF", ErrHTTPMalformed)
			}
			r.buf = r.buf[len(httpCRLF):]
			r.awaitChunkCRLF = false
			continue
		}
		if r.chunkLeft > 0 {
			n := int64(len(r.buf))
			if n > r.chunkLeft {
				n = r.chunkLeft
			}
			if n > 0 {
				if err := r.appendBody(r.buf[:n]); err != nil {
					return err
				}
				r.buf = r.buf[n:]
				r.chunkLeft -= n
			}
			if r.chunkLeft > 0 {
				return nil
			}
			r.awaitChunkCRLF = true
			continue
		}

		line, rest, ok := httpCutLine(r.buf)
		if !ok {
			// A size line is short, and this is where maxHTTPHeaderLineLen earns its keep:
			// the head's total bound no longer applies once the head is over, so without a
			// per-line bound here a peer that never sends a newline would grow buf for the
			// rest of the response.
			if len(r.buf) > maxHTTPHeaderLineLen {
				return fmt.Errorf("%w: a chunk line exceeds %d bytes",
					ErrHTTPTooLarge, maxHTTPHeaderLineLen)
			}
			return nil
		}
		if !httpLineOK(line) {
			return fmt.Errorf("%w: a chunk line is not terminated by CRLF", ErrHTTPMalformed)
		}
		r.buf = rest

		if r.chunkTrailer {
			if len(line) == 0 {
				r.bodyDone = true
				return nil
			}
			// Trailer fields are shape-checked and then dropped rather than stored, for the
			// reason the Header field's comment gives.
			if line[0] == ' ' || line[0] == '\t' {
				return fmt.Errorf("%w: an obsolete line folding", ErrHTTPMalformed)
			}
			i := bytes.IndexByte(line, ':')
			if i <= 0 || !httpIsToken(string(line[:i])) {
				return fmt.Errorf("%w: a trailer line is not a header field", ErrHTTPMalformed)
			}
			continue
		}

		size, err := httpChunkSize(line)
		if err != nil {
			return err
		}
		if size == 0 {
			r.chunkTrailer = true
			continue
		}
		r.chunkLeft = size
	}
}

// httpChunkSize reads a chunk-size line: hex digits, an optional semicolon and extensions
// this reader ignores. The extension is parsed past rather than validated, because its
// grammar belongs to whatever extension defined it and the framing does not depend on it.
func httpChunkSize(line []byte) (int64, error) {
	s := string(line)
	if i := strings.IndexByte(s, ';'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("%w: a chunk size is empty", ErrHTTPMalformed)
	}
	n, err := strconv.ParseInt(s, 16, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%w: a chunk size is not hexadecimal", ErrHTTPMalformed)
	}
	return n, nil
}

// appendBody is the one path by which decoded bytes reach the caller, and so the one place
// the ceiling is enforced. Enforcing it at each decoder instead would be three copies of a
// bound, and a fourth decoder added later would be a fourth place to forget it.
func (r *HTTPResponse) appendBody(p []byte) error {
	if int64(len(r.body))+int64(len(p)) > r.maxBody {
		return fmt.Errorf("%w: holding %d bytes against a ceiling of %d",
			ErrHTTPTooLarge, len(r.body), r.maxBody)
	}
	r.body = append(r.body, p...)
	return nil
}

// Lookup returns the first value for one field, case-insensitively. It is a method on the
// response rather than a free function so the lookup rule lives beside the parse that
// populates it: RFC 7230 field names are case-insensitive, and OpenAI, Anthropic and
// Google do not agree on casing.
func (r *HTTPResponse) Lookup(name string) (string, bool) {
	for _, h := range r.Header {
		if strings.EqualFold(h.Name, name) {
			return h.Value, true
		}
	}
	return "", false
}

// Values returns every value for one field, in order.
func (r *HTTPResponse) Values(name string) []string {
	var out []string
	for _, h := range r.Header {
		if strings.EqualFold(h.Name, name) {
			out = append(out, h.Value)
		}
	}
	return out
}

// Complete reports whether the head and the body have both been fully read. A response
// whose connection ended early is not complete, and Truncated says so.
func (r *HTTPResponse) Complete() bool { return r.headDone && r.bodyDone }

// HeadComplete reports whether the status line and headers have been read.
func (r *HTTPResponse) HeadComplete() bool { return r.headDone }

// Truncated reports whether the connection ended before the framing's own terminator did:
// a Content-Length that was not satisfied, or a chunked body with no zero-size chunk. It
// is separate from Complete because the two answer different questions and a caller that
// only asked the first would treat a short body as a whole one - which for a JSON response
// means parsing a prefix, and for a signature means verifying less than was sent.
func (r *HTTPResponse) Truncated() bool { return r.truncated }

// ExpectNoBody declares that no body follows the head, which is what RFC 7230 4.3 says of
// a response to HEAD and of 204 and 304.
//
// 204 and 304 need no declaration - the reader decides from the status, which is the only
// signal it has. HEAD does, because the response to a HEAD carries the Content-Length the
// body WOULD have had and then no body, so a reader that trusted the field would wait for
// bytes the peer correctly does not send, and the caller would get a read timeout rather
// than an answer.
//
// It may be called before or after the head is parsed. If bytes do follow anyway, nothing
// is hidden: they stay in Pending, so the caller still sees the socket is dirty and closes
// it rather than releasing it to the pool. The declaration saves a wait; it does not move
// any boundary.
func (r *HTTPResponse) ExpectNoBody() {
	if r.err != nil {
		return
	}
	r.bodyDone = true
}

// Body returns the decoded bytes the caller has not taken. Before the body is complete
// this is a partial result, which is what a streaming caller wants; a caller reading a
// Content-Length response should check Complete before treating it as the whole answer.
func (r *HTTPResponse) Body() []byte { return r.body }

// TakeBody returns the decoded bytes and forgets them, so the next call returns only what
// arrived since. It is what a streaming caller uses, and draining is what lets a long
// server-sent event stream run under a modest ceiling: maxBody bounds what the reader
// holds, and a reader that is drained holds nothing.
func (r *HTTPResponse) TakeBody() []byte {
	b := r.body
	r.body = nil
	return b
}

// Pending returns the bytes that were fed but belong to no part of this response.
//
// Once Complete reports true, those bytes are the start of the NEXT message on this
// connection, and that is the answer to "may I release this socket back to the pool": a
// non-empty Pending means the socket is dirty and must be closed with SyscallNetClose
// rather than returned with SyscallNetRelease. The pool is keyed on the module's own pid,
// so the bytes do not reach another module - they come back to this one, where its next
// response would read them as a status line. Before the response is complete this returns
// nil, because bytes held mid-parse are decoder state and not a message.
func (r *HTTPResponse) Pending() []byte {
	if !r.Complete() {
		return nil
	}
	return r.buf
}

// Close signals that the connection ended. A caller MUST call it when SyscallNetRead
// reports the peer closed - which is abi.ErrNetPeerClosed, and not a zero-length read with
// no error - because a close-delimited response has no other terminator and would never
// complete without it.
//
// Closing early does not make a short body look complete. When the framing named a
// terminator that never arrived, Close records Truncated instead of setting the response
// complete, so a caller that loops on Complete stops and can say what went wrong rather
// than handing a prefix of a response to whoever asked for the response.
func (r *HTTPResponse) Close() {
	r.closed = true
	switch {
	case !r.headDone:
		r.truncated = true
	case r.bodyDone:
		// Already complete; nothing to decide.
	case r.chunked || r.length >= 0:
		r.truncated = true
	default:
		r.bodyDone = true
	}
}
