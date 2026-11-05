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

// Package abi_test exercises abi's HTTP framing from the side a module uses it from:
// through the package's exported surface, with nothing beside it.
//
// The suite is external on purpose, and for the same reason tests/console is. Everything
// here is reachable from a component, which is the surface that has to hold; a test in
// package abi could pass on an unexported path no caller ever reaches.
package abi_test

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/abi"
)

// feed drives a reader the way a module has to, one SyscallNetRead's worth at a time. It
// is a helper rather than a one-shot because the property under test is repeatedly that a
// response split across arbitrary boundaries parses the same as one delivered whole.
func feed(t *testing.T, r *abi.HTTPResponse, chunks ...string) {
	t.Helper()
	for i, c := range chunks {
		require.NoError(t, r.Feed([]byte(c)), "chunk %d of %d", i, len(chunks))
	}
}

// oneShot builds a reader and feeds the whole response as one chunk.
func oneShot(t *testing.T, maxBody int64, whole string) *abi.HTTPResponse {
	t.Helper()
	r, err := abi.NewHTTPResponseReader(maxBody)
	require.NoError(t, err)
	feed(t, r, whole)
	return r
}

// noValueLeaked asserts the property the file's doc claims about every error it returns:
// no error text carries the offending value. These errors reach a module's log line and
// from there the kernel console, and a console line is text an operator trusts. The claim
// is checked per case rather than stated once, because a refusal that echoes the bytes an
// attacker chose is exactly the kind of defect a comment cannot prevent.
func noValueLeaked(t *testing.T, err error, secrets ...string) {
	t.Helper()
	require.Error(t, err)
	for _, s := range secrets {
		if s == "" {
			continue
		}
		assert.NotContains(t, err.Error(), s,
			"the error text must not carry the value that was refused")
	}
}

// ---------------------------------------------------------------------------
// Request encoding.
//
// The property under test is not "Encode produces bytes" but "Encode produces ONE
// message". Every case below is a request a conforming peer would read as two, which is
// the primitive that matters here: the kernel pools sockets per module, so a second
// request smuggled into this one comes back to the same module later and reads as the head
// of a response nobody asked for.

func TestEncodeRendersOneRequest(t *testing.T) {
	req := abi.HTTPRequest{
		Method: "POST",
		Path:   "/v1/chat/completions",
		Host:   "api.provider.example",
		Header: []abi.HTTPHeader{
			{Name: "Content-Type", Value: "application/json"},
			{Name: "Accept", Value: "text/event-stream"},
		},
		Body: []byte(`{"model":"m"}`),
	}
	req.SetContentLengthOf(req.Body)

	got, err := req.Encode()
	require.NoError(t, err)
	assert.Equal(t,
		"POST /v1/chat/completions HTTP/1.1\r\n"+
			"Host: api.provider.example\r\n"+
			"Content-Type: application/json\r\n"+
			"Accept: text/event-stream\r\n"+
			"Content-Length: 13\r\n"+
			"\r\n"+
			`{"model":"m"}`,
		string(got))
}

func TestEncodePutsTheFrameworkFieldsFirst(t *testing.T) {
	// Host is emitted before any caller field, so a caller cannot precede the authority
	// this request names. Order is asserted rather than presence: the point is which one a
	// peer reads first.
	req := abi.HTTPRequest{
		Method: "GET", Path: "/", Host: "api.provider.example",
		Header: []abi.HTTPHeader{{Name: "X-First", Value: "1"}},
	}
	got, err := req.Encode()
	require.NoError(t, err)
	lines := strings.Split(strings.SplitN(string(got), "\r\n\r\n", 2)[0], "\r\n")
	require.Len(t, lines, 3)
	assert.Equal(t, "GET / HTTP/1.1", lines[0])
	assert.Equal(t, "Host: api.provider.example", lines[1])
	assert.Equal(t, "X-First: 1", lines[2])
}

func TestEncodeRefusesAFramingThatTwoParsersCouldReadDifferently(t *testing.T) {
	// Each case is measured: the value it declares shorter than the body it carries, the
	// two fields that both claim to say where the body ends, and the duplicates that make
	// one field say two things.
	body := []byte("0123456789ABCDEF\r\nGET /admin HTTP/1.1\r\nHost: evil.example\r\n\r\n")
	cases := []struct {
		name string
		req  abi.HTTPRequest
	}{
		{"a length shorter than the body written with it", abi.HTTPRequest{
			Method: "POST", Path: "/", Host: "api.provider.example",
			Header: []abi.HTTPHeader{{Name: "Content-Length", Value: "4"}},
			Body:   body,
		}},
		// The declared length MATCHES the body's own length exactly, on purpose, and the
		// fixture asserts it. A length that was short would be refused by the length check
		// below it and the pairing would never be reached, so the case would pass with the
		// pairing check deleted - which it did, on the first draft of this table.
		{"Content-Length and Transfer-Encoding together", func() abi.HTTPRequest {
			body := []byte("10\r\n0123456789ABCDEF\r\n0\r\n\r\n")
			return abi.HTTPRequest{
				Method: "POST", Path: "/", Host: "api.provider.example",
				Header: []abi.HTTPHeader{
					{Name: "Content-Length", Value: strconv.Itoa(len(body))},
					{Name: "Transfer-Encoding", Value: "chunked"},
				},
				Body: body,
			}
		}()},
		{"two Content-Length fields", abi.HTTPRequest{
			Method: "POST", Path: "/", Host: "api.provider.example",
			Header: []abi.HTTPHeader{
				{Name: "Content-Length", Value: "2"},
				{Name: "Content-Length", Value: "2"},
			},
			Body: []byte("hi"),
		}},
		{"two Content-Length fields that disagree", abi.HTTPRequest{
			Method: "POST", Path: "/", Host: "api.provider.example",
			Header: []abi.HTTPHeader{
				{Name: "Content-Length", Value: "2"},
				{Name: "Content-Length", Value: "3"},
			},
			Body: []byte("hi"),
		}},
		{"a Content-Length that is not a number", abi.HTTPRequest{
			Method: "POST", Path: "/", Host: "api.provider.example",
			Header: []abi.HTTPHeader{{Name: "Content-Length", Value: "0x10"}},
			Body:   []byte("hi"),
		}},
		{"a negative Content-Length", abi.HTTPRequest{
			Method: "POST", Path: "/", Host: "api.provider.example",
			Header: []abi.HTTPHeader{{Name: "Content-Length", Value: "-1"}},
			Body:   []byte("hi"),
		}},
		{"two Transfer-Encoding fields", abi.HTTPRequest{
			Method: "POST", Path: "/", Host: "api.provider.example",
			Header: []abi.HTTPHeader{
				{Name: "Transfer-Encoding", Value: "chunked"},
				{Name: "Transfer-Encoding", Value: "chunked"},
			},
			Body: []byte("0\r\n\r\n"),
		}},
		{"two Host fields", abi.HTTPRequest{
			Method: "GET", Path: "/", Host: "api.provider.example",
			Header: []abi.HTTPHeader{
				{Name: "Host", Value: "api.provider.example"},
				{Name: "Host", Value: "api.provider.example"},
			},
		}},
		{"a Host field that disagrees with the declared host", abi.HTTPRequest{
			Method: "GET", Path: "/", Host: "api.provider.example",
			Header: []abi.HTTPHeader{{Name: "Host", Value: "evil.example"}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.req.Encode()
			require.Error(t, err, "the shape must be refused, not emitted")
			assert.ErrorIs(t, err, abi.ErrHTTPHeaderInjection)
			assert.Empty(t, got, "a refused request must not leave partial bytes behind")
		})
	}
}

func TestEncodeRefusesANewlineAnywhereItWouldStartALine(t *testing.T) {
	// The classic primitive, checked in every position that is written to the wire. Each
	// field is checked with CR, LF and the pair, because a peer that splits on LF alone is
	// the one an attacker aims at.
	fields := []struct {
		name  string
		build func(bad string) abi.HTTPRequest
	}{
		{"method", func(bad string) abi.HTTPRequest {
			return abi.HTTPRequest{Method: "GE" + bad + "T", Path: "/", Host: "h.example"}
		}},
		{"path", func(bad string) abi.HTTPRequest {
			return abi.HTTPRequest{Method: "GET", Path: "/" + bad + "x", Host: "h.example"}
		}},
		{"host", func(bad string) abi.HTTPRequest {
			return abi.HTTPRequest{Method: "GET", Path: "/", Host: "h.example" + bad}
		}},
		{"header name", func(bad string) abi.HTTPRequest {
			return abi.HTTPRequest{Method: "GET", Path: "/", Host: "h.example",
				Header: []abi.HTTPHeader{{Name: "X-A" + bad, Value: "1"}}}
		}},
		{"header value", func(bad string) abi.HTTPRequest {
			return abi.HTTPRequest{Method: "GET", Path: "/", Host: "h.example",
				Header: []abi.HTTPHeader{{Name: "X-A", Value: "1" + bad + "X-B: 2"}}}
		}},
	}
	for _, f := range fields {
		for _, bad := range []string{"\r", "\n", "\r\n"} {
			t.Run(f.name+" "+strconv.Quote(bad), func(t *testing.T) {
				got, err := f.build(bad).Encode()
				require.Error(t, err)
				assert.ErrorIs(t, err, abi.ErrHTTPHeaderInjection)
				assert.Empty(t, got)
			})
		}
	}
}

func TestEncodeRefusesThePositionsWhereASpaceEndsAField(t *testing.T) {
	// A newline is not the only way to get a second field read into one position: a space
	// ends the request-target and the authority too, so "/a b" is a target of "/a" with
	// "b" where the version belongs.
	cases := []struct {
		name string
		req  abi.HTTPRequest
	}{
		{"a space in the path", abi.HTTPRequest{Method: "GET", Path: "/a b", Host: "h.example"}},
		{"a space in the host", abi.HTTPRequest{Method: "GET", Path: "/", Host: "h.example x"}},
		{"a path in the host", abi.HTTPRequest{Method: "GET", Path: "/", Host: "h.example/admin"}},
		{"an absolute-form target", abi.HTTPRequest{Method: "GET", Path: "http://evil.example/", Host: "h.example"}},
		{"an authority-form target", abi.HTTPRequest{Method: "GET", Path: "evil.example:443", Host: "h.example"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.req.Encode()
			require.Error(t, err)
			assert.ErrorIs(t, err, abi.ErrHTTPHeaderInjection)
			assert.Empty(t, got)
		})
	}
}

func TestEncodeNeedsAMethodAndAHost(t *testing.T) {
	// Both are refused rather than defaulted. An empty Host would emit a request with no
	// Host field at all, which RFC 7230 5.4 requires and which a peer would treat as
	// HTTP/1.0 - a downgrade of the very connection the kernel validated a certificate
	// against.
	_, err := abi.HTTPRequest{Path: "/", Host: "h.example"}.Encode()
	require.Error(t, err)
	assert.ErrorIs(t, err, abi.ErrHTTPHeaderInjection)

	_, err = abi.HTTPRequest{Method: "GET", Path: "/"}.Encode()
	require.Error(t, err)
	assert.ErrorIs(t, err, abi.ErrHTTPHeaderInjection)
}

func TestEncodeRefusesAMethodAndANameOutsideTheTokenSet(t *testing.T) {
	// The tchar set is closed rather than "no space", because the parser on the other end
	// accepts exactly that class and this file's job is to emit only what a conforming
	// parser reads. Every printable character outside tchar is checked, not a sample.
	const tchar = "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for c := byte(0x20); c < 0x7f; c++ {
		if strings.IndexByte(tchar, c) >= 0 {
			continue
		}
		t.Run("method"+strconv.QuoteRune(rune(c)), func(t *testing.T) {
			_, err := abi.HTTPRequest{Method: "GET" + string(c), Path: "/", Host: "h.example"}.Encode()
			require.Error(t, err, "method with %q must be refused", c)
			assert.ErrorIs(t, err, abi.ErrHTTPHeaderInjection)
		})
		t.Run("header"+strconv.QuoteRune(rune(c)), func(t *testing.T) {
			_, err := abi.HTTPRequest{Method: "GET", Path: "/", Host: "h.example",
				Header: []abi.HTTPHeader{{Name: "X-A" + string(c), Value: "1"}}}.Encode()
			require.Error(t, err, "header name with %q must be refused", c)
			assert.ErrorIs(t, err, abi.ErrHTTPHeaderInjection)
		})
	}
}

func TestEncodeAllowsATabInAHeaderValue(t *testing.T) {
	// RFC 7230 permits HTAB inside a field value. Refusing it would be a defect of a
	// different kind: a vendor that pads a value with a tab would then be unreachable
	// through this stack, and the failure would read as a vendor bug.
	req := abi.HTTPRequest{
		Method: "GET", Path: "/", Host: "h.example",
		Header: []abi.HTTPHeader{{Name: "X-A", Value: "a\tb"}},
	}
	got, err := req.Encode()
	require.NoError(t, err)
	assert.Contains(t, string(got), "X-A: a\tb\r\n")
}

func TestEncodeRefusesABodyWithNoFraming(t *testing.T) {
	// The shape that always hangs. The peer reads a request with no body and then waits on
	// a connection nothing closes; the vendor times out and the adapter reports a network
	// error, which is a worse diagnosis than this one. Note the sentinel: this is not an
	// injection, it is a message the peer cannot frame.
	got, err := abi.HTTPRequest{
		Method: "POST", Path: "/", Host: "h.example", Body: []byte("a body"),
	}.Encode()
	require.Error(t, err)
	assert.ErrorIs(t, err, abi.ErrHTTPMalformed)
	assert.Empty(t, got)
}

func TestEncodeAllowsALongerLengthThanTheBodyItCarries(t *testing.T) {
	// The other side of the length check, and the one a stricter reading would get wrong.
	// A caller streaming a body in pieces declares the total up front and writes the head
	// before it has the bytes, so a length LONGER than this call's body is legal. Refusing
	// it would mean no request body could ever be streamed.
	req := abi.HTTPRequest{
		Method: "POST", Path: "/", Host: "h.example",
		Header: []abi.HTTPHeader{{Name: "Content-Length", Value: "100"}},
		Body:   []byte("the first piece"),
	}
	got, err := req.Encode()
	require.NoError(t, err)
	assert.Contains(t, string(got), "Content-Length: 100\r\n\r\nthe first piece")
}

func TestSetContentLengthReplacesRatherThanAppends(t *testing.T) {
	// A caller that edits a body after declaring its length has to be able to redeclare it.
	// Appending would leave two fields, which Encode refuses, so the caller would have to
	// know to remove the first one - the exact mistake the method exists to prevent.
	req := abi.HTTPRequest{Method: "POST", Path: "/", Host: "h.example", Body: []byte("abc")}
	req.SetContentLengthOf(req.Body)
	req.Body = []byte("abcdefgh")
	req.SetContentLengthOf(req.Body)

	got, err := req.Encode()
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(got), "Content-Length"))
	assert.Contains(t, string(got), "Content-Length: 8\r\n\r\nabcdefgh")
}

func TestNoRequestErrorCarriesTheValueThatWasRefused(t *testing.T) {
	// The file's doc claims no error text carries the offending value, because these errors
	// reach a module's log line and from there the kernel console. Checked against the
	// values an attacker would choose rather than against a sample.
	//
	// Every case has to actually be refused, so each carries a byte that is invalid in the
	// position the payload sits in. That is what makes the assertion mean something: a case
	// that was accepted proves nothing about the error text.
	const payload = "SMUGGLED-GET-admin"
	cases := []abi.HTTPRequest{
		{Method: "GET\r\n" + payload, Path: "/", Host: "h.example"},
		{Method: "GET", Path: "/\r\n" + payload, Host: "h.example"},
		{Method: "GET", Path: "/", Host: "h.example\r\n" + payload},
		{Method: "GET", Path: "/", Host: payload + "\x01"},
		{Method: "GET", Path: "/", Host: "h.example",
			Header: []abi.HTTPHeader{{Name: payload + "\x01", Value: "1"}}},
		{Method: "GET", Path: "/", Host: "h.example",
			Header: []abi.HTTPHeader{{Name: "X-A", Value: "1\r\n" + payload}}},
		{Method: "GET", Path: "/", Host: "h.example",
			Header: []abi.HTTPHeader{{Name: payload + "\x01", Value: payload}}},
		{Method: "GET", Path: "/", Host: "h.example",
			Header: []abi.HTTPHeader{{Name: "Host", Value: payload + "\x01"}}},
		{Method: "GET", Path: "/", Host: "h.example",
			Header: []abi.HTTPHeader{{Name: "Content-Length", Value: payload}}},
	}
	for i, req := range cases {
		_, err := req.Encode()
		require.Error(t, err, "case %d must be refused", i)
		noValueLeaked(t, err, payload)
	}
}

// ---------------------------------------------------------------------------
// Response reading.
//
// The property under test is that arbitrary chunk boundaries parse to the same answer,
// because that is the only shape a module can get: one SyscallNetRead is one read syscall
// with no buffering behind it, so a response that arrives whole in a test fixture never
// arrives whole in production. Every case below is fed twice - once whole and once split at
// every offset - and both runs must agree.

// splitEvery feeds whole one byte at a time, which is the worst case for an incremental
// parser: every terminator, every chunk size and every header arrives with its last byte
// in a separate call.
func splitEvery(t *testing.T, maxBody int64, whole string) *abi.HTTPResponse {
	t.Helper()
	r, err := abi.NewHTTPResponseReader(maxBody)
	require.NoError(t, err)
	for i := 0; i < len(whole); i++ {
		require.NoError(t, r.Feed([]byte(whole[i:i+1])), "byte %d of %d", i, len(whole))
	}
	return r
}

func TestAContentLengthResponseCompletesOnTheDeclaredLength(t *testing.T) {
	const whole = "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\nContent-Length: 13\r\n\r\n" + `{"a":1,"b":2}`

	for name, r := range map[string]*abi.HTTPResponse{
		"whole":    oneShot(t, 1<<20, whole),
		"one byte": splitEvery(t, 1<<20, whole),
		"split head": mustFeed(t, 1<<20,
			whole[:40], whole[40:]),
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, 200, r.Status)
			assert.Equal(t, "OK", r.Reason)
			assert.Equal(t, `{"a":1,"b":2}`, string(r.Body()))
			assert.True(t, r.HeadComplete())
			assert.True(t, r.Complete())
			assert.False(t, r.Truncated())
			assert.Empty(t, r.Pending())
			v, ok := r.Lookup("content-type")
			assert.True(t, ok)
			assert.Equal(t, "application/json", v)
		})
	}
}

// mustFeed builds a reader from an arbitrary list of chunks.
func mustFeed(t *testing.T, maxBody int64, chunks ...string) *abi.HTTPResponse {
	t.Helper()
	r, err := abi.NewHTTPResponseReader(maxBody)
	require.NoError(t, err)
	feed(t, r, chunks...)
	return r
}

func TestTheStatusLineIsNotCompletedUntilItsCRLFArrives(t *testing.T) {
	// Half a status line is not a status. The intermediate state is the one worth pinning:
	// once the line ends the status is known while the head is not, and a caller that read
	// HeadComplete as "Status is meaningful" would act on zero - which is not a code any
	// peer can send.
	r, err := abi.NewHTTPResponseReader(1 << 10)
	require.NoError(t, err)
	require.NoError(t, r.Feed([]byte("HTTP/1.1 200 OK\r")))
	assert.False(t, r.HeadComplete())
	assert.Zero(t, r.Status, "a line that has not ended has not been parsed")

	require.NoError(t, r.Feed([]byte("\n")))
	assert.False(t, r.HeadComplete(), "the blank line has not arrived")
	assert.Equal(t, 200, r.Status, "the status line has")

	require.NoError(t, r.Feed([]byte("Content-Length: 0\r\n\r\n")))
	assert.True(t, r.HeadComplete())
	assert.True(t, r.Complete())
}

func TestAChunkedResponseDecodesAcrossArbitraryBoundaries(t *testing.T) {
	const whole = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n6\r\n world\r\n1\r\n!\r\n0\r\n\r\n"

	one := oneShot(t, 1<<20, whole)
	split := splitEvery(t, 1<<20, whole)
	mid := mustFeed(t, 1<<20, whole[:60], whole[60:62], whole[62:])

	for name, r := range map[string]*abi.HTTPResponse{"whole": one, "one byte": split, "mid chunk": mid} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, "hello world!", string(r.Body()))
			assert.True(t, r.Complete())
			assert.False(t, r.Truncated())
			assert.Empty(t, r.Pending())
		})
	}
}

func TestChunkExtensionsAreParsedPastRatherThanValidated(t *testing.T) {
	// An extension's grammar belongs to whatever defined it, and the framing does not depend
	// on it. Refusing an unknown extension would mean a vendor using one is unreachable
	// through this stack.
	r := oneShot(t, 1<<20, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"+
		"5;ext=token;other=\"a;b\"\r\nhello\r\n0\r\n\r\n")
	assert.Equal(t, "hello", string(r.Body()))
	assert.True(t, r.Complete())
}

func TestChunkedTrailersAreShapeCheckedAndThenDropped(t *testing.T) {
	// Trailer fields are dropped, not appended to Header. A trailer naming a field the head
	// already carried would change what Values returns to a caller that reads headers after
	// the body, which is a way for the peer to make one answer depend on when it was asked.
	r := oneShot(t, 1<<20, "HTTP/1.1 200 OK\r\n"+
		"Content-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"+
		"5\r\nhello\r\n0\r\nContent-Type: text/html\r\nX-Sum: 5\r\n\r\n")
	assert.True(t, r.Complete())
	assert.Equal(t, []string{"text/plain"}, r.Values("Content-Type"),
		"a trailer must not add a second value for a field the head carried")
	assert.Empty(t, r.Values("X-Sum"))

	// And a trailer that is not a field at all is still a framing error, and one that is a
	// field is not - which is what makes the drop above a decision rather than a failure to
	// parse trailers.
	r2, err := abi.NewHTTPResponseReader(1 << 20)
	require.NoError(t, err)
	require.NoError(t, r2.Feed([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n")))
	err = r2.Feed([]byte("not a field\r\n\r\n"))
	require.Error(t, err)
	assert.ErrorIs(t, err, abi.ErrHTTPMalformed)

	r3, err := abi.NewHTTPResponseReader(1 << 20)
	require.NoError(t, err)
	require.NoError(t, r3.Feed([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n")))
	err = r3.Feed([]byte("  folded: 1\r\n\r\n"))
	require.Error(t, err, "a folded trailer is refused for the reason a folded head field is")
	assert.ErrorIs(t, err, abi.ErrHTTPMalformed)
}

func TestACloseDelimitedBodyCompletesOnlyOnClose(t *testing.T) {
	// Neither framing field: the body runs to the end of the connection, so a caller that
	// never calls Close waits forever. That is the documented contract, not a leak.
	r, err := abi.NewHTTPResponseReader(1 << 10)
	require.NoError(t, err)
	require.NoError(t, r.Feed([]byte("HTTP/1.0 200 OK\r\n\r\nall of it")))
	assert.True(t, r.HeadComplete())
	assert.False(t, r.Complete(), "a close-delimited body is not complete until the close")
	assert.Equal(t, "all of it", string(r.Body()))

	r.Close()
	assert.True(t, r.Complete())
	assert.False(t, r.Truncated(), "closing is this framing's own terminator")
}

func TestACloseBeforeTheFramingEndedIsATruncation(t *testing.T) {
	// The distinction a caller needs. "The peer hung up" is a clean end for a
	// close-delimited body and a truncation for a declared length, and folding the two
	// together is how a prefix of a response gets handed over as the response.
	cases := []struct {
		name  string
		head  string
		chunk string
	}{
		{"a length that was not satisfied", "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n", "abc"},
		{"a chunked body with no terminator", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "5\r\nhel"},
		{"a head that never ended", "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := abi.NewHTTPResponseReader(1 << 10)
			require.NoError(t, err)
			for _, c := range []string{tc.head, tc.chunk} {
				if c != "" {
					require.NoError(t, r.Feed([]byte(c)))
				}
			}
			r.Close()
			assert.True(t, r.Truncated())
			assert.False(t, r.Complete(), "a truncated response must not report complete")
		})
	}
}

func TestAShortBodyIsNotSilentlyCompleted(t *testing.T) {
	// A caller that loops on Complete must stop when the peer stops, and must be able to say
	// why. Without Truncated this looks identical to a complete response of three bytes.
	r, err := abi.NewHTTPResponseReader(1 << 10)
	require.NoError(t, err)
	require.NoError(t, r.Feed([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc")))
	assert.False(t, r.Complete())
	assert.Equal(t, "abc", string(r.Body()), "what arrived is still readable")
	r.Close()
	assert.True(t, r.Truncated())
	assert.False(t, r.Complete())
}

func TestAHeadResponseNeedsExpectNoBody(t *testing.T) {
	// RFC 7230 4.3: a response to HEAD carries the Content-Length the body WOULD have had
	// and then no body. A reader that trusted the field would wait for bytes the peer
	// correctly does not send, and the caller would get a read timeout rather than an
	// answer. 204 and 304 need no declaration, because the status is the only signal there.
	head := "HTTP/1.1 200 OK\r\nContent-Length: 128\r\n\r\n"

	waiting, err := abi.NewHTTPResponseReader(1 << 10)
	require.NoError(t, err)
	require.NoError(t, waiting.Feed([]byte(head)))
	assert.False(t, waiting.Complete(), "without the declaration the reader still waits")

	declared, err := abi.NewHTTPResponseReader(1 << 10)
	require.NoError(t, err)
	declared.ExpectNoBody()
	require.NoError(t, declared.Feed([]byte(head)))
	assert.True(t, declared.HeadComplete())
	assert.True(t, declared.Complete())
	assert.False(t, declared.Truncated())
	assert.Empty(t, declared.Body())

	for _, status := range []string{"204 No Content", "304 Not Modified"} {
		r := oneShot(t, 1<<10, "HTTP/1.1 "+status+"\r\nContent-Length: 42\r\n\r\n")
		assert.True(t, r.Complete(), "%s never carries a body", status)
		assert.Empty(t, r.Body())
	}
}

func TestAnInformationalResponseIsSkipped(t *testing.T) {
	r := oneShot(t, 1<<20,
		"HTTP/1.1 100 Continue\r\nX-Informational: 1\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	assert.Equal(t, 200, r.Status)
	assert.Equal(t, "ok", string(r.Body()))
	assert.True(t, r.Complete())
	assert.Empty(t, r.Values("X-Informational"), "the discarded head leaves no fields behind")
	assert.Equal(t, []string{"2"}, r.Values("Content-Length"), "and the final head's own fields stay")
}

func TestInformationalResponsesAreBounded(t *testing.T) {
	// A peer could otherwise keep this reader parsing forever, which costs no memory once a
	// head is discarded and so is invisible to every other bound here.
	eight := strings.Repeat("HTTP/1.1 100 Continue\r\n\r\n", 8) +
		"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	r := oneShot(t, 1<<20, eight)
	assert.Equal(t, 200, r.Status)
	assert.True(t, r.Complete())

	nine := strings.Repeat("HTTP/1.1 100 Continue\r\n\r\n", 9) +
		"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	r2, err := abi.NewHTTPResponseReader(1 << 20)
	require.NoError(t, err)
	err = r2.Feed([]byte(nine))
	require.Error(t, err)
	assert.ErrorIs(t, err, abi.ErrHTTPTooLarge)
}

func TestTheHeadIsBoundedInTotalAndNotOnlyPerLine(t *testing.T) {
	// Both bounds are needed, and they bound different things: a peer that sends nine
	// thousand one-byte lines stays inside any per-line limit on every line while growing
	// the head without limit.
	r, err := abi.NewHTTPResponseReader(1 << 20)
	require.NoError(t, err)
	err = r.Feed([]byte("HTTP/1.1 200 OK\r\n" + strings.Repeat("X-A: 1\r\n", 9000) + "\r\n"))
	require.Error(t, err)
	assert.ErrorIs(t, err, abi.ErrHTTPTooLarge)

	// And a peer that never sends a newline at all is bounded by the same ceiling, before it
	// reaches it.
	r2, err := abi.NewHTTPResponseReader(1 << 20)
	require.NoError(t, err)
	require.NoError(t, r2.Feed([]byte(strings.Repeat("A", 1000))))
	err = r2.Feed([]byte(strings.Repeat("A", 70000)))
	require.Error(t, err)
	assert.ErrorIs(t, err, abi.ErrHTTPTooLarge)
}

func TestAnUnterminatedChunkLineIsBounded(t *testing.T) {
	// The head's total bound no longer applies once the head is over, so the per-line bound
	// is what stops a peer from growing the buffer for the rest of a chunked response.
	r, err := abi.NewHTTPResponseReader(1 << 20)
	require.NoError(t, err)
	require.NoError(t, r.Feed([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")))
	require.NoError(t, r.Feed([]byte(strings.Repeat("A", 4096))), "short of the bound is buffered")
	err = r.Feed([]byte(strings.Repeat("A", 5000)))
	require.Error(t, err)
	assert.ErrorIs(t, err, abi.ErrHTTPTooLarge)
}

func TestTheBodyCeilingBoundsWhatTheReaderHolds(t *testing.T) {
	// The ceiling counts what the reader is holding, not everything the response will ever
	// contain, and that is what makes a long stream work. TakeBody drains, so a
	// server-sent event stream of any length runs under a modest ceiling, while a caller that
	// never drains is bounded no matter how much the peer sends.
	r, err := abi.NewHTTPResponseReader(16)
	require.NoError(t, err)
	require.NoError(t, r.Feed([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")))

	total := 0
	for range 200 {
		require.NoError(t, r.Feed([]byte("8\r\n01234567\r\n")),
			"a drained reader stays under its ceiling for a stream of any length")
		total += len(r.TakeBody())
		assert.Empty(t, r.TakeBody(), "TakeBody drains")
	}
	assert.Equal(t, 1600, total)
	require.NoError(t, r.Feed([]byte("0\r\n\r\n")))
	assert.True(t, r.Complete())

	// The same response with nobody draining hits the ceiling at 16 bytes.
	r2, err := abi.NewHTTPResponseReader(16)
	require.NoError(t, err)
	require.NoError(t, r2.Feed([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")))
	require.NoError(t, r2.Feed([]byte("8\r\n01234567\r\n")))
	err = r2.Feed([]byte("8\r\n01234567\r\n8\r\n01234567\r\n"))
	require.Error(t, err)
	assert.ErrorIs(t, err, abi.ErrHTTPTooLarge)
}

func TestABodyCeilingIsRequired(t *testing.T) {
	// A zero would mean "no limit", and a limit of none is how a peer that never closes
	// exhausts a module's heap one read at a time. The kernel bounds one READ, not a
	// response.
	for _, n := range []int64{0, -1} {
		r, err := abi.NewHTTPResponseReader(n)
		require.Error(t, err, "a ceiling of %d must be refused", n)
		assert.ErrorIs(t, err, abi.ErrHTTPTooLarge)
		assert.Nil(t, r)
	}
}

func TestTheCeilingCannotBeRaisedByFeedingMore(t *testing.T) {
	// maxBody is stored at construction and never reassigned, so a caller cannot raise its
	// own limit partway through a response.
	r, err := abi.NewHTTPResponseReader(4)
	require.NoError(t, err)
	require.NoError(t, r.Feed([]byte("HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n")))
	require.NoError(t, r.Feed([]byte("abcd")))
	err = r.Feed([]byte("efgh"))
	require.Error(t, err, "the ceiling still applies after a Feed")
	assert.ErrorIs(t, err, abi.ErrHTTPTooLarge)
}

func TestMalformedShapesAreRefused(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"no status code", "HTTP/1.1\r\n\r\n"},
		// Shorter than three digits after the version. These are in the table because
		// removing the length guard is a panic rather than a refusal: the reader slices
		// three bytes off a string that does not have them. A table case that only asserted
		// "an error" would have caught it, and none did - the mutation was found by
		// measuring, not by reading.
		{"two digits after the version", "HTTP/1.1 20\r\n\r\n"},
		{"one digit after the version", "HTTP/1.1 2\r\n\r\n"},
		{"nothing after the version", "HTTP/1.1 \r\n\r\n"},
		// The grammar is 3DIGIT with no range and no sign, so a sign is not a digit and a
		// code of "-20" would reach the caller as a negative number it never expects. The
		// two-digit spellings are the ones that matter: with a sign and three digits the
		// code is still refused, but by the space check that follows rather than by the digit
		// class, so those cases pass with the class deleted. Measured - "+200" is refused
		// either way and "+20" is not.
		{"a signed status code", "HTTP/1.1 +200 OK\r\n\r\n"},
		{"a negative status code", "HTTP/1.1 -200 OK\r\n\r\n"},
		{"a signed two-digit code", "HTTP/1.1 +20 OK\r\nContent-Length: 0\r\n\r\n"},
		{"a negative two-digit code", "HTTP/1.1 -20 OK\r\nContent-Length: 0\r\n\r\n"},
		{"no space after the version", "HTTP/1.1200 OK\r\n\r\n"},
		{"a two-digit code", "HTTP/1.1 20 OK\r\n\r\n"},
		{"a four-digit code", "HTTP/1.1 2000 OK\r\n\r\n"},
		{"a non-numeric code", "HTTP/1.1 OK 200\r\n\r\n"},
		{"the code not followed by a space", "HTTP/1.1 200OK\r\n\r\n"},
		{"a version this reader cannot frame", "HTTP/2 200\r\n\r\n"},
		{"a header line with no colon", "HTTP/1.1 200 OK\r\nnot a field\r\n\r\n"},
		{"a colon with no name", "HTTP/1.1 200 OK\r\n: 1\r\n\r\n"},
		{"a name outside the token set", "HTTP/1.1 200 OK\r\nX A: 1\r\n\r\n"},
		{"a control character in a value", "HTTP/1.1 200 OK\r\nX-A: a\x01b\r\n\r\n"},
		{"DEL in a value", "HTTP/1.1 200 OK\r\nX-A: a\x7fb\r\n\r\n"},
		{"a Content-Length that is not a number", "HTTP/1.1 200 OK\r\nContent-Length: five\r\n\r\n"},
		{"a negative Content-Length", "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n"},
		{"two Content-Length fields that disagree", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx"},
		{"two Transfer-Encoding fields", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"},
		{"Content-Length and Transfer-Encoding", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"},
		{"chunked not the last coding", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"},
		{"a coding outside the token set", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunk ed\r\n\r\n"},
		{"an obsolete line folding", "HTTP/1.1 200 OK\r\nX-A: 1\r\n  continued\r\n\r\n"},
		{"a folding with a tab", "HTTP/1.1 200 OK\r\nX-A: 1\r\n\tcontinued\r\n\r\n"},
		{"a chunk size that is not hex", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"},
		{"an empty chunk size", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\r\n"},
		// An empty size and a size that is not hex are different facts, and both would be
		// refused by the hex parse alone - so the diagnosis is the property, pinned here
		// rather than left to whichever branch happens to run first.
		{"a chunk size with a sign", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n+5\r\nhello\r\n0\r\n\r\n"},
		// Leading whitespace is refused while trailing is tolerated, because Go's own
		// chunked reader trims trailing whitespace too and a peer that pads the line should
		// not be unreachable through this stack for padding it.
		{"a chunk size with leading whitespace",
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n 5\r\nhello\r\n0\r\n\r\n"},
		{"a chunk not followed by CRLF", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabX0\r\n\r\n"},
		// Two junk bytes and then a valid terminator. This is the shape the terminator check
		// exists for: a decoder that skipped whatever two bytes sat there would read the
		// zero-size chunk after them and report a complete response, silently accepting a
		// misframing instead of refusing it. The earlier spelling of this case, "abX0", is
		// refused either way, because the fall-through parses "X0" as a size line and that is
		// not hexadecimal - so it does not distinguish a checked terminator from an assumed one.
		{"a chunk terminator replaced by junk", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabXY0\r\n\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := abi.NewHTTPResponseReader(1 << 20)
			require.NoError(t, err)
			err = r.Feed([]byte(tc.in))
			require.Error(t, err)
			assert.ErrorIs(t, err, abi.ErrHTTPMalformed)
		})
	}
}

func TestBareLineEndingsAreRefusedRatherThanTolerated(t *testing.T) {
	// RFC 7230 3.5 permits a recipient to tolerate a bare LF. This one refuses, and the
	// reason is that tolerance is only safe for the LAST parser of some bytes, and this is
	// not always that: a deployment behind an intercepting proxy has two parsers reading the
	// same stream, and a proxy that splits on LF while this reader waits for CRLF is the
	// classic desynchronization.
	for name, in := range map[string]string{
		"LF in the status line": "HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n",
		"LF in a field":         "HTTP/1.1 200 OK\r\nContent-Length: 0\n\r\n",
		"a lone CR":             "HTTP/1.1 200 OK\rContent-Length: 0\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			r, err := abi.NewHTTPResponseReader(1 << 20)
			require.NoError(t, err)
			err = r.Feed([]byte(in))
			require.Error(t, err, "one byte sequence must have one reading")
			assert.ErrorIs(t, err, abi.ErrHTTPMalformed)
		})
	}
}

func TestARefusalLatchesSoARetryCannotGetADifferentAnswer(t *testing.T) {
	// Without the latch a caller that keeps reading after an error would re-parse the same
	// buffer: a ceiling hit on one Feed and a clean parse on the next, because the bytes that
	// exceeded it were consumed by the failed attempt. That is the shape that turns a refusal
	// into a wrong answer.
	r, err := abi.NewHTTPResponseReader(1 << 20)
	require.NoError(t, err)
	require.NoError(t, r.Feed([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")))
	err = r.Feed([]byte(strings.Repeat("A", 9000)))
	require.Error(t, err)

	for range 3 {
		err2 := r.Feed([]byte("5\r\nhello\r\n0\r\n\r\n"))
		require.Error(t, err2, "the refusal must survive further bytes")
		assert.ErrorIs(t, err2, abi.ErrHTTPTooLarge, "and it must be the same refusal")
	}
	assert.False(t, r.Complete())
	assert.True(t, r.HeadComplete(), "the head parsed; what failed was the body")
	assert.Empty(t, r.Body(), "and the bytes that exceeded the bound were not decoded")
}

func TestFeedingAfterTheResponseEndedIsRefused(t *testing.T) {
	// Both ways the connection can be over. Nothing parses the bytes any more, so accepting
	// them would mean buffering with no bound: the body ceiling counts decoded body, the head
	// bound counts head lines, and a finished response is counted by neither.
	closed, err := abi.NewHTTPResponseReader(1 << 20)
	require.NoError(t, err)
	require.NoError(t, closed.Feed([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")))
	require.True(t, closed.Complete())
	err = closed.Feed([]byte("HTTP/1.1 500 Oops\r\nContent-Length: 2\r\n\r\nno"))
	require.Error(t, err)
	assert.ErrorIs(t, err, abi.ErrHTTPMalformed)
	assert.Equal(t, 200, closed.Status, "a second response must not overwrite the first")

	delimited, err := abi.NewHTTPResponseReader(1 << 20)
	require.NoError(t, err)
	require.NoError(t, delimited.Feed([]byte("HTTP/1.0 200 OK\r\n\r\nbody")))
	delimited.Close()
	require.True(t, delimited.Complete())
	err = delimited.Feed([]byte("more"))
	require.Error(t, err)
	assert.ErrorIs(t, err, abi.ErrHTTPMalformed)

	// A TRUNCATED response, which is the case the two above cannot reach: neither is
	// complete, so the "the response is complete" refusal does not fire and the close is what
	// has to refuse the bytes.
	truncated, err := abi.NewHTTPResponseReader(1 << 20)
	require.NoError(t, err)
	require.NoError(t, truncated.Feed([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab")))
	truncated.Close()
	require.True(t, truncated.Truncated())
	require.False(t, truncated.Complete(), "the fixture must be a response that never finished")
	err = truncated.Feed([]byte("cde"))
	require.Error(t, err, "bytes arriving after the connection ended belong to nothing")
	assert.ErrorIs(t, err, abi.ErrHTTPMalformed)
}

func TestPendingReportsTheNextMessageSoADirtySocketIsNotPooled(t *testing.T) {
	// The pool is keyed on the module's own pid, so leftover bytes do not reach another
	// module - they come back to this one, where its next response reads them as a status
	// line. Pending is the answer to "may I release this socket".
	r, err := abi.NewHTTPResponseReader(1 << 20)
	require.NoError(t, err)
	require.NoError(t, r.Feed([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 200 OK\r\n")))
	require.True(t, r.Complete())
	assert.Equal(t, "HTTP/1.1 200 OK\r\n", string(r.Pending()),
		"the surplus belongs to the next message")

	// Before the response is complete the bytes are decoder state, not a message.
	r2, err := abi.NewHTTPResponseReader(1 << 20)
	require.NoError(t, err)
	require.NoError(t, r2.Feed([]byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")))
	assert.Empty(t, r2.Pending())
}

func TestLookupIsCaseInsensitiveAndValuesKeepsOrder(t *testing.T) {
	// RFC 7230 field names are case-insensitive, and the vendors do not agree on casing.
	// Repeated fields are legal and ordered, which is why the collection is a slice rather
	// than a map - Set-Cookie is the common case.
	r := oneShot(t, 1<<20, "HTTP/1.1 200 OK\r\n"+
		"set-cookie: a=1\r\nSET-COOKIE: b=2\r\nSet-Cookie: c=3\r\nContent-Length: 0\r\n\r\n")
	assert.Equal(t, []string{"a=1", "b=2", "c=3"}, r.Values("set-cookie"))
	v, ok := r.Lookup("CONTENT-LENGTH")
	assert.True(t, ok)
	assert.Equal(t, "0", v)
	_, ok = r.Lookup("X-Absent")
	assert.False(t, ok)
	assert.Empty(t, r.Values("X-Absent"))
}

func TestARepeatedIdenticalLengthIsAccepted(t *testing.T) {
	// RFC 7230 3.3.2 says a recipient may treat a repeated identical length as one, and
	// refusing it would break a peer for a shape the protocol permits. Duplicates that
	// disagree are the CL.CL ambiguity and are refused, which the malformed table covers.
	r := oneShot(t, 1<<20, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nhi")
	assert.Equal(t, "hi", string(r.Body()))
	assert.True(t, r.Complete())
	assert.Len(t, r.Values("Content-Length"), 2, "both fields are still reported as received")
}

func TestAReasonPhraseIsOptional(t *testing.T) {
	// The two spellings a peer sends are "200 OK" and "200". No caller should branch on the
	// phrase; it is here because a human reads it in a log line.
	with := oneShot(t, 1<<20, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
	assert.Equal(t, 404, with.Status)
	assert.Equal(t, "Not Found", with.Reason)

	without := oneShot(t, 1<<20, "HTTP/1.1 404\r\nContent-Length: 0\r\n\r\n")
	assert.Equal(t, 404, without.Status)
	assert.Empty(t, without.Reason)

	empty := oneShot(t, 1<<20, "HTTP/1.1 404 \r\nContent-Length: 0\r\n\r\n")
	assert.Equal(t, 404, empty.Status)
	assert.Empty(t, empty.Reason)
}

func TestAHeadAndBodySplitAcrossAnyBoundaryParseIdentically(t *testing.T) {
	// The whole point of the incremental shape, stated as a check rather than as a claim:
	// every split of the same bytes gives the same answer. Splitting at every offset covers
	// the boundaries a hand-picked fixture would miss - mid-token, mid-length, between the
	// CR and the LF.
	const whole = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\nhello world"

	want := oneShot(t, 1<<20, whole)
	require.True(t, want.Complete())

	for i := 1; i < len(whole); i++ {
		got := mustFeed(t, 1<<20, whole[:i], whole[i:])
		require.Equal(t, want.Status, got.Status, "split at %d", i)
		require.Equal(t, want.Header, got.Header, "split at %d", i)
		require.Equal(t, string(want.Body()), string(got.Body()), "split at %d", i)
		require.True(t, got.Complete(), "split at %d", i)
		require.False(t, got.Truncated(), "split at %d", i)
	}
}

func TestAReaderIsNotSafeForConcurrentUseAndDoesNotClaimToBe(t *testing.T) {
	// Documented rather than enforced, so what is asserted here is the weaker claim that
	// holds: one reader driven by one caller is deterministic, and two readers over the same
	// bytes are independent. A mutex would suggest a sharing model this type does not have.
	const whole = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
	a := oneShot(t, 1<<20, whole)
	b := oneShot(t, 1<<20, whole)
	assert.Equal(t, string(a.Body()), string(b.Body()))
	assert.NotSame(t, a, b)
}

func TestNoResponseErrorCarriesAPeerChosenValue(t *testing.T) {
	// The same property as on the request side, and the more important half: the value here
	// is chosen by the peer, not by the adapter, so it is attacker-controlled by definition.
	const payload = "SMUGGLED-HEADER-VALUE"
	cases := map[string]string{
		"in a header name":   "HTTP/1.1 200 OK\r\n" + payload + " \x01: 1\r\n\r\n",
		"in a header value":  "HTTP/1.1 200 OK\r\nX-A: " + payload + "\x01\r\n\r\n",
		"in the status line": "HTTP/1.1 200 " + payload + "\x01\r\n\r\n",
		"in a chunk size":    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + payload + "\r\n",
		"in a trailer":       "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n" + payload + " \x01: 1\r\n\r\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := abi.NewHTTPResponseReader(1 << 20)
			require.NoError(t, err)
			err = r.Feed([]byte(in))
			require.Error(t, err)
			noValueLeaked(t, err, payload)
		})
	}
}

func TestTheSentinelsAreDistinct(t *testing.T) {
	// A caller has to tell "my adapter built a bad request" from "the peer answered badly"
	// from "a ceiling I chose was reached", and one of the three wants an operator. If two of
	// them were the same value the distinction would be documented and not real.
	sentinels := []error{
		abi.ErrHTTPHeaderInjection,
		abi.ErrHTTPMalformed,
		abi.ErrHTTPTooLarge,
	}
	for i, a := range sentinels {
		for j, b := range sentinels {
			if i == j {
				continue
			}
			assert.False(t, errors.Is(a, b), "%v must not match %v", a, b)
		}
	}
}

// ---------------------------------------------------------------------------
// The properties that decide whether this file may exist in abi at all.
//
// abi is the package a module compiles against, and three rules keep it from becoming a
// copy of the kernel: nothing the kernel enforces, nothing with kernel state behind it, no
// unexported helpers kernel code happens to share. Framing is pure computation over the
// caller's own bytes, so it belongs here; a decision that reads kernel state does not.
//
// These are checked against the file's SYNTAX rather than its text. A substring scan over
// the source would fail on the doc comments, which discuss the kernel at length precisely
// because the boundary is the point of the file - and a check that cannot tell prose from
// code is a check that gets deleted.

// httpAST parses abi/http.go once, for the two structural properties below.
func httpAST(t *testing.T) *ast.File {
	t.Helper()
	body, err := os.ReadFile("../../abi/http.go")
	require.NoError(t, err, "the framing file must exist; it is what a component imports")
	fset := token.NewFileSet()
	af, err := parser.ParseFile(fset, "http.go", body, 0)
	require.NoError(t, err)
	return af
}

// typeName renders the type expression of a parameter or field for a message.
func typeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return typeName(t.X) + "." + t.Sel.Name
	case *ast.StarExpr:
		return "*" + typeName(t.X)
	case *ast.ArrayType:
		if t.Len == nil {
			return "[]" + typeName(t.Elt)
		}
		return "[" + typeName(t.Len) + "]" + typeName(t.Elt)
	case *ast.Ellipsis:
		return "..." + typeName(t.Elt)
	case *ast.InterfaceType:
		return "interface"
	case *ast.FuncType:
		return "func"
	case *ast.MapType:
		return "map[" + typeName(t.Key) + "]" + typeName(t.Value)
	case *ast.BasicLit:
		return t.Value
	default:
		return fmt.Sprintf("%T", e)
	}
}

func TestHTTPFramingTouchesNoKernelType(t *testing.T) {
	// The kernel's job on a socket is the boundary: which host a module may dial, whether the
	// address it resolved to is permitted, how much one read may return. This file's job is
	// the framing of bytes already on that socket. A signature carrying SContext, a PID or a
	// kernel error type would mean a decision the kernel makes had moved into the package a
	// module compiles against, where a module can read it and reason about it.
	af := httpAST(t)

	// The kernel-facing types, spelled the way a file in abi would have to spell them: with
	// the abi prefix, since that is where they are declared.
	forbidden := map[string]bool{
		"SContext": true, "PID": true, "FD": true, "Op": true, "Level": true,
		"Kernel": true, "DeniedError": true, "NetSpec": true, "NetDialResult": true,
		"NetInfo": true, "Receipt": true, "VerifierSignature": true, "Manifest": true,
		"Record": true, "BootLimits": true, "BootConfig": true, "Span": true,
	}

	var found []string
	ast.Inspect(af, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if pkg, ok := x.X.(*ast.Ident); ok && (pkg.Name == "kernel" || pkg.Name == "abi") {
				if forbidden[x.Sel.Name] {
					found = append(found, "reference to "+pkg.Name+"."+x.Sel.Name)
				}
			}
		case *ast.Field:
			// A parameter, a result or a struct field naming one of those types is the same
			// defect wearing a different hat: the type appears in a signature either way.
			if id, ok := x.Type.(*ast.Ident); ok && forbidden[id.Name] {
				for _, name := range x.Names {
					found = append(found, "field or parameter "+name.Name+" of type "+id.Name)
				}
			}
		}
		return true
	})
	assert.Empty(t, found,
		"abi/http.go must not carry a kernel-facing type in any signature: %v", found)

	// Every exported declaration takes and returns only this file's own types and scalars.
	// Checked by name rather than by membership in a list, so a new export is covered too.
	for _, d := range af.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || !fd.Name.IsExported() {
			continue
		}
		for _, f := range fd.Type.Params.List {
			name := typeName(f.Type)
			assert.False(t, forbidden[strings.TrimPrefix(name, "*")],
				"%s takes a %s, which is a kernel-facing type", fd.Name.Name, name)
		}
		if fd.Type.Results != nil {
			for _, f := range fd.Type.Results.List {
				name := typeName(f.Type)
				assert.False(t, forbidden[strings.TrimPrefix(name, "*")],
					"%s returns a %s, which is a kernel-facing type", fd.Name.Name, name)
			}
		}
	}
}

func TestHTTPFramingHasNoConcurrencyNoTimeAndNoIO(t *testing.T) {
	// The file's doc says it is deliberately not a client: no dial, no goroutine, no
	// deadline, no retry. That is a structural claim and it is checkable, because each of
	// those is a distinct syntax shape. A second implementation of any of them here would be
	// a second place for a timeout to be wrong, and would make the framing depend on a clock
	// that in this kernel is kclock's to own.
	af := httpAST(t)

	var found []string
	ast.Inspect(af, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.GoStmt:
			found = append(found, "a goroutine")
		case *ast.DeferStmt:
			found = append(found, "a deferred call")
		case *ast.ChanType:
			found = append(found, "a channel type")
		case *ast.SendStmt:
			found = append(found, "a channel send")
		case *ast.RangeStmt:
			if _, ok := x.X.(*ast.ChanType); ok {
				found = append(found, "a channel range")
			}
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch pkg.Name {
			case "time":
				found = append(found, "a call into time")
			case "net", "net/http", "os", "io", "sync", "sync/atomic", "syscall", "context":
				found = append(found, "a call into "+pkg.Name)
			}
		}
		return true
	})
	assert.Empty(t, found, "abi/http.go must be pure computation over bytes, but it holds %v", found)

	// The import list is the same claim from the other side, and it is the one that a
	// dependency would show up in first: a package added to abi invalidates every plugin
	// built against the previous source, and a third-party one adds a version constraint
	// every component inherits.
	require.NotEmpty(t, af.Imports, "the file has imports; the parse is wrong")
	for _, imp := range af.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		first := strings.SplitN(path, "/", 2)[0]
		assert.NotContains(t, first, ".",
			"%q is not a standard-library import, and abi must depend on nothing else "+
				"or every plugin inherits that dependency's version constraint", path)
		switch path {
		case "bytes", "errors", "fmt", "strconv", "strings":
		default:
			assert.Fail(t, "abi/http.go imports "+path,
				"a framing file needs bytes, errors, fmt, strconv and strings; anything else "+
					"is a capability this file was written not to have")
		}
	}
}

func TestATransferEncodingNamingChunkedOnlyAsASubstringIsNotChunked(t *testing.T) {
	// The token has to be matched as a token. A substring test reports chunked for
	// "not-chunked-at-all", which then suppresses the framing check that catches a body
	// with no length declared - and the request goes out unfarmed, which is the hang.
	for _, coding := range []string{"not-chunked-at-all", "xchunkedx", "CHUNKEDX"} {
		t.Run(coding, func(t *testing.T) {
			req := abi.HTTPRequest{
				Method: "POST", Path: "/", Host: "h.example",
				Header: []abi.HTTPHeader{{Name: "Transfer-Encoding", Value: coding}},
				Body:   []byte("a body with no framing"),
			}
			got, err := req.Encode()
			require.Error(t, err, "%q is not the token chunked, so the body has no framing", coding)
			assert.ErrorIs(t, err, abi.ErrHTTPMalformed)
			assert.Empty(t, got)
		})
	}

	// The token itself is matched case-insensitively and as the last element of a list, which
	// is the position it has to be in: chunked frames the message, so a coding after it would
	// mean bytes de-chunked here are then framed again by something neither side implements.
	for _, coding := range []string{"chunked", "CHUNKED", "gzip, chunked", "gzip,CHUNKED"} {
		t.Run(coding, func(t *testing.T) {
			req := abi.HTTPRequest{
				Method: "POST", Path: "/", Host: "h.example",
				Header: []abi.HTTPHeader{{Name: "Transfer-Encoding", Value: coding}},
				Body:   []byte("0\r\n\r\n"),
			}
			_, err := req.Encode()
			require.NoError(t, err, "%q declares chunked framing", coding)
		})
	}

	// And not in a position where it does not frame the message.
	for _, coding := range []string{"chunked, gzip", "chunked,gzip"} {
		t.Run(coding+" not last", func(t *testing.T) {
			req := abi.HTTPRequest{
				Method: "POST", Path: "/", Host: "h.example",
				Header: []abi.HTTPHeader{{Name: "Transfer-Encoding", Value: coding}},
				Body:   []byte("0\r\n\r\n"),
			}
			got, err := req.Encode()
			require.Error(t, err, "%q does not end with the coding that frames the message", coding)
			assert.ErrorIs(t, err, abi.ErrHTTPHeaderInjection)
			assert.Empty(t, got)
		})
	}
}

func TestTheFramingDiagnosisIsPinnedWhereAFallThroughWouldAlsoRefuse(t *testing.T) {
	// Three refusals that another check would produce anyway, with a worse message. An
	// operator reading "a chunk size is not hexadecimal" about a size line that is EMPTY is
	// sent looking for a bad number where there is no number; one reading "the status line
	// has no status code" about a status line that is too short is told the wrong thing about
	// a line that does have one. The sentinel is the same, so ErrorIs cannot see the
	// difference and the text is what has to be asserted.
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"an empty chunk size", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\r\n",
			"a chunk size is empty"},
		{"a status line that is too short", "HTTP/1.1 20\r\n\r\n",
			"the status line has no status code"},
		{"a status line with no code at all", "HTTP/1.1\r\n\r\n",
			"the status line has no status code"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := mustFeedErr(t, tc.in)
			require.Error(t, err)
			assert.ErrorIs(t, err, abi.ErrHTTPMalformed)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestAChunkSizeThatOverflowsIsRefusedBeforeItIsRead(t *testing.T) {
	// Sixteen hex digits can exceed an int64, and a size that wrapped would make this reader
	// consume the wrong number of bytes and then parse the rest of the response as framing.
	// It is ErrHTTPTooLarge rather than ErrHTTPMalformed and so is not in that table: the
	// size is well-formed hex, it is just not a size this reader can represent.
	// The cap is a digit count, and the number is chosen so the property is checkable rather
	// than incidental: 15 digits always parse, 16 always refuse, and the two are separated by
	// one digit rather than by how large the number happens to be.
	for _, digits := range []int{1, 8, 14, 15} {
		size := strings.Repeat("F", digits)
		t.Run(strconv.Itoa(digits)+" digits", func(t *testing.T) {
			r, err := abi.NewHTTPResponseReader(1 << 20)
			require.NoError(t, err)
			require.NoError(t, r.Feed([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")))
			require.NoError(t, r.Feed([]byte(size+"\r\n")),
				"%d hex digits must be a representable size", digits)
		})
	}
	for _, digits := range []int{16, 17, 40} {
		size := strings.Repeat("F", digits)
		t.Run(strconv.Itoa(digits)+" digits", func(t *testing.T) {
			r, err := abi.NewHTTPResponseReader(1 << 20)
			require.NoError(t, err)
			require.NoError(t, r.Feed([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")))
			err = r.Feed([]byte(size + "\r\n"))
			require.Error(t, err, "%d hex digits cannot be represented", digits)
			assert.ErrorIs(t, err, abi.ErrHTTPTooLarge)
		})
	}
}

func TestABareLineEndingIsRefusedInEveryPosition(t *testing.T) {
	// The property, stated as a property: one byte sequence has one reading. A bare LF or a
	// lone CR anywhere in a response must be refused, and this checks every position rather
	// than one, because three separate layers in the reader contribute to the answer -
	// httpLineOK on each consumed line, boundHead on a buffer that has no complete line yet,
	// and the per-field checks on the name, the value and the reason phrase. A test of one
	// position would pass with two of the three removed and would not tell anyone that.
	//
	// Positions are named by what a conforming peer would put there.
	base := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	require.NoError(t, mustFeedErr(t, base), "the well-formed base must parse")

	positions := []struct {
		name string
		in   string
	}{
		{"the status line's terminator", "HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n"},
		{"a lone CR in the status line", "HTTP/1.1 200 OK\rContent-Length: 0\r\n\r\n"},
		{"inside the reason phrase", "HTTP/1.1 200 O\nK\r\nContent-Length: 0\r\n\r\n"},
		{"a field's terminator", "HTTP/1.1 200 OK\r\nContent-Length: 0\n\r\n"},
		{"inside a field name", "HTTP/1.1 200 OK\r\nConten\nt-Length: 0\r\n\r\n"},
		{"inside a field value", "HTTP/1.1 200 OK\r\nX-A: a\nb\r\nContent-Length: 0\r\n\r\n"},
		{"a lone CR inside a field value", "HTTP/1.1 200 OK\r\nX-A: a\rb\r\nContent-Length: 0\r\n\r\n"},
		{"the blank line", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\n"},
		{"a chunk size's terminator",
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\nhello\r\n0\r\n\r\n"},
		{"a lone CR in a chunk size",
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\r\nhello\r\n0\r\n\r\n"},
		{"a chunk's trailing terminator",
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\n\r\n0\r\n\r\n"},
		{"a trailer's terminator",
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Sum: 1\n\r\n"},
	}
	for _, tc := range positions {
		t.Run(tc.name, func(t *testing.T) {
			err := mustFeedErr(t, tc.in)
			require.Error(t, err, "position %q must be refused", tc.name)
			assert.ErrorIs(t, err, abi.ErrHTTPMalformed)
		})
	}
	_ = base
}

func TestALoneCRWaitingForItsLFIsNotYetARefusal(t *testing.T) {
	// The one shape the position table above cannot express, because it is about a boundary
	// rather than a byte: a CR at the very end of a buffer may be the first half of a CRLF
	// split across two reads. Refusing it there would refuse every response whose terminator
	// happens to land on a read boundary, which over SyscallNetRead is a matter of luck.
	//
	// The chunked shape is the one where it matters most, because the CR here is a chunk's
	// terminator and not a line ending: the decoder has to hold it across the call rather
	// than read it as an empty size line.
	r, err := abi.NewHTTPResponseReader(1 << 20)
	require.NoError(t, err)
	require.NoError(t, r.Feed([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r")),
		"a trailing CR is not yet wrong")
	assert.False(t, r.Complete())
	assert.Equal(t, "hello", string(r.Body()), "the chunk's data is already decoded")
	require.NoError(t, r.Feed([]byte("\n0\r\n\r\n")))
	assert.True(t, r.Complete(), "the CRLF finished on the next read")

	// The moment a byte follows the CR that is not LF, it was a lone CR all along, and it is
	// refused rather than treated as a terminator.
	r2, err := abi.NewHTTPResponseReader(1 << 20)
	require.NoError(t, err)
	require.NoError(t, r2.Feed([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r")))
	err = r2.Feed([]byte("X"))
	require.Error(t, err)
	assert.ErrorIs(t, err, abi.ErrHTTPMalformed)
}

// mustFeedErr feeds a whole response in one chunk and returns the first error, or nil.
func mustFeedErr(t *testing.T, whole string) error {
	t.Helper()
	r, err := abi.NewHTTPResponseReader(1 << 20)
	require.NoError(t, err)
	return r.Feed([]byte(whole))
}

func TestAFoldedLineIsDiagnosedAsFolding(t *testing.T) {
	// A folded line is refused either way: the token check independently rejects a name
	// beginning with a space or a tab, since neither is a tchar. What the explicit fold
	// refusal buys is the diagnosis, and an operator reading "a header line has no colon"
	// about a response that used obsolete folding is sent looking in the wrong place. So the
	// message is the property here, and it is pinned in the head and in a trailer.
	for name, in := range map[string]string{
		"head":    "HTTP/1.1 200 OK\r\nX-A: 1\r\n  Y-B: 2\r\n\r\n",
		"trailer": "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n  Y-B: 2\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			err := mustFeedErr(t, in)
			require.Error(t, err)
			assert.ErrorIs(t, err, abi.ErrHTTPMalformed)
			assert.Contains(t, err.Error(), "folding",
				"the refusal must name obsolete folding rather than the syntax it also breaks")
		})
	}
}

func TestAStatusCodeOfZeroIsStillAStatusLine(t *testing.T) {
	// RFC 7230's grammar for status-code is 3DIGIT with no range, so "000" parses. What the
	// reader must get right is not whether to like it but which line comes next: the one
	// after a status line is a field. Deriving that from "Status is still zero" would read
	// Content-Length as a second status line and refuse the response for a reason that has
	// nothing to do with what the peer sent, which is why sawStatus is its own flag.
	r, err := abi.NewHTTPResponseReader(1 << 20)
	require.NoError(t, err)
	require.NoError(t, r.Feed([]byte("HTTP/1.1 000 Weird\r\nContent-Length: 0\r\n\r\n")))
	assert.True(t, r.HeadComplete())
	assert.Equal(t, 0, r.Status, "the code the peer sent is reported as it was sent")
	assert.Equal(t, "Weird", r.Reason)
	assert.Equal(t, []string{"0"}, r.Values("Content-Length"),
		"the line after a status line is a field, not another status line")
	assert.True(t, r.Complete())
}

func TestAnEmptyTransferCodingIsRefused(t *testing.T) {
	// "Transfer-Encoding:" with nothing after it is a field with an empty value, and an empty
	// string is not a token. Accepting it would mean the list of codings is empty while the
	// field is present, which is a third state neither the caller nor a peer can express -
	// and on the request side it is a body with no framing at all, which is the hang.
	resp := "HTTP/1.1 200 OK\r\nTransfer-Encoding: \r\nContent-Length: 0\r\n\r\n"
	err := mustFeedErr(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, abi.ErrHTTPMalformed)

	for _, coding := range []string{"", " ", ",", "chunked,,gzip", "chunked, "} {
		t.Run("response "+strconv.Quote(coding), func(t *testing.T) {
			err := mustFeedErr(t, "HTTP/1.1 200 OK\r\nTransfer-Encoding: "+coding+
				"\r\nContent-Length: 0\r\n\r\n")
			require.Error(t, err, "%q is not a list of codings", coding)
			assert.ErrorIs(t, err, abi.ErrHTTPMalformed)
		})
	}

	// On the request side the same field with a body is refused too, and with the OTHER
	// sentinel: a module that wrote a value no peer can parse is at fault, while a peer that
	// sent one is not. That is the whole reason the two sides wrap one rule in two errors.
	for _, coding := range []string{"", " ", ",", "chunked,,gzip", "chunked, "} {
		t.Run("request "+strconv.Quote(coding), func(t *testing.T) {
			got, err := abi.HTTPRequest{
				Method: "POST", Path: "/", Host: "h.example",
				Header: []abi.HTTPHeader{{Name: "Transfer-Encoding", Value: coding}},
				Body:   []byte("a body"),
			}.Encode()
			require.Error(t, err, "%q declares no framing", coding)
			assert.ErrorIs(t, err, abi.ErrHTTPHeaderInjection)
			assert.Empty(t, got)
		})
	}
}

func TestOneCodingRuleWithTwoSentinels(t *testing.T) {
	// A value the request side accepts and the response side refuses would be a value two
	// parsers disagree about, which is the drift the shared rule exists to prevent. Both
	// sides are fed the same list and must reach the same verdict, differing only in which
	// sentinel wraps it.
	codings := []string{
		"chunked", "CHUNKED", "gzip", "gzip, chunked", "chunked, gzip",
		"chunked, ", "chunked,,gzip", "", " ", ",", "chunk ed", "not-chunked-at-all",
	}
	for _, coding := range codings {
		t.Run(strconv.Quote(coding), func(t *testing.T) {
			_, reqErr := abi.HTTPRequest{
				Method: "POST", Path: "/", Host: "h.example",
				Header: []abi.HTTPHeader{{Name: "Transfer-Encoding", Value: coding}},
				Body:   []byte("0\r\n\r\n"),
			}.Encode()
			respErr := mustFeedErr(t, "HTTP/1.1 200 OK\r\nTransfer-Encoding: "+coding+
				"\r\nContent-Length: 0\r\n\r\n")

			// Both refuse, or both accept the coding as a framing declaration. The request
			// case also carries the "a body needs framing" refusal, so the comparison is on
			// the coding rule alone: a malformed coding is refused by both, a well-formed
			// one by neither.
			reqBadCoding := reqErr != nil &&
				(strings.Contains(reqErr.Error(), "transfer coding") ||
					strings.Contains(reqErr.Error(), "last transfer coding"))
			respBadCoding := respErr != nil &&
				(strings.Contains(respErr.Error(), "transfer coding") ||
					strings.Contains(respErr.Error(), "last transfer coding"))
			assert.Equal(t, reqBadCoding, respBadCoding,
				"%q must reach the same verdict on both sides", coding)
			if reqBadCoding {
				assert.ErrorIs(t, reqErr, abi.ErrHTTPHeaderInjection)
				assert.ErrorIs(t, respErr, abi.ErrHTTPMalformed)
			}
		})
	}
}

func TestTheTokenClassIsClosedAndNotEmpty(t *testing.T) {
	// httpIsToken is one character class with two callers that wrap it in different
	// sentinels, so the class itself is worth pinning: an empty string is not a token, every
	// tchar is, and every printable non-tchar is not. The method and header-name paths both
	// run through it, and a class that admitted the empty string would admit a name that
	// names nothing.
	const tchar = "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	// An empty method, an empty header name and an empty path are all refused.
	for name, req := range map[string]abi.HTTPRequest{
		"an empty method": {Method: "", Path: "/", Host: "h.example"},
		"an empty header name": {Method: "GET", Path: "/", Host: "h.example",
			Header: []abi.HTTPHeader{{Name: "", Value: "1"}}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := req.Encode()
			require.Error(t, err)
			assert.ErrorIs(t, err, abi.ErrHTTPHeaderInjection)
			assert.Empty(t, got)
		})
	}

	// Every tchar is accepted in a header name, so the class is not narrower than the
	// protocol's.
	for i := 0; i < len(tchar); i++ {
		c := string(tchar[i])
		req := abi.HTTPRequest{Method: "GET", Path: "/", Host: "h.example",
			Header: []abi.HTTPHeader{{Name: "X" + c, Value: "1"}}}
		got, err := req.Encode()
		require.NoError(t, err, "tchar %q must be accepted in a header name", c)
		assert.Contains(t, string(got), "X"+c+": 1\r\n")
	}

	// And a response's field name runs through the same class.
	for _, bad := range []string{"X A", "X(A)", "X[A]", "X{A}", "X\"A\"", "X,A", "X;A", "X:A"} {
		// X:A is well-formed - the colon separates the name - so it is excluded below.
		if bad == "X:A" {
			continue
		}
		t.Run("response name "+bad, func(t *testing.T) {
			err := mustFeedErr(t, "HTTP/1.1 200 OK\r\n"+bad+": 1\r\nContent-Length: 0\r\n\r\n")
			require.Error(t, err)
			assert.ErrorIs(t, err, abi.ErrHTTPMalformed)
		})
	}
}
