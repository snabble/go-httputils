package httputils

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/cenkalti/backoff/v4"
	"github.com/snabble/go-logging/v2/tracex"
)

var (
	tracePropagation = tracex.NewTraceHeaderPropagation()
)

type Encoder func(interface{}) ([]byte, error)

type StreamDecoder func(io.Reader, interface{}) error
type Decoder func([]byte, interface{}) error

type Request struct {
	RawRequest *http.Request
	Header     http.Header
	Encode     Encoder
	ctx        context.Context

	StreamDecoder StreamDecoder
	Decode        Decoder
	RawResponse   *http.Response
}

func createRequest(method, url string, params []RequestParam, requestBody interface{}) (*Request, error) {
	request := newRequest(params)

	if err := request.createRaw(method, url, requestBody); err != nil {
		return nil, err
	}

	return request, nil
}

func newRequest(params []RequestParam) *Request {
	header := http.Header{}
	header.Add("Content-Type", "application/json")

	request := &Request{
		Header: header,
		ctx:    context.Background(),

		Encode: json.Marshal,
		Decode: json.Unmarshal,
	}

	applyParams(request, params)

	return request
}

func (req *Request) createRaw(method, url string, requestBody interface{}) error {
	var data io.Reader
	if requestBody != nil {
		body, err := req.Encode(requestBody)
		if err != nil {
			return fmt.Errorf("encoding raw request: %w", err)
		}

		data = bytes.NewBuffer(body)
	}

	raw, err := http.NewRequestWithContext(req.ctx, method, url, data)
	if err != nil {
		return fmt.Errorf("creating request for %v: %w", url, err)
	}

	req.RawRequest = raw

	return nil
}

func (req *Request) applyHeader() {
	for name, values := range req.Header {
		for _, value := range values {
			req.RawRequest.Header.Add(name, value)
		}
	}
}

func (req *Request) isSuccessfulPost() bool {
	return req.RawResponse.StatusCode == http.StatusOK ||
		req.RawResponse.StatusCode == http.StatusCreated ||
		req.RawResponse.StatusCode == http.StatusNoContent
}

func (req *Request) isSuccessfulPostForBody() bool {
	return req.RawResponse.StatusCode == http.StatusOK ||
		req.RawResponse.StatusCode == http.StatusCreated
}

func (req *Request) isClientError() bool {
	return http.StatusBadRequest <= req.RawResponse.StatusCode &&
		req.RawResponse.StatusCode < http.StatusInternalServerError
}

func (req *Request) decodeBody(entity interface{}) error {
	if req.StreamDecoder != nil {
		return req.StreamDecoder(req.RawResponse.Body, entity)
	}

	data, err := io.ReadAll(req.RawResponse.Body)
	if err != nil {
		return fmt.Errorf("reading response body: '%w'", err)
	}

	return req.Decode(data, entity)
}

func applyParams(req *Request, params []RequestParam) {
	for _, param := range params {
		param(req)
	}
}

func permanentHTTPError(resp *Request) error {
	return backoff.Permanent(httpError(resp))
}

func httpError(resp *Request) error {
	return HTTPClientError{Code: resp.RawResponse.StatusCode, Status: resp.RawResponse.Status}
}

type RequestParam func(*Request)

func Context(ctx context.Context) RequestParam {
	return func(req *Request) {
		req.ctx = ctx

		tracePropagation.Inject(ctx, req.Header)
	}
}

func SetEncoder(e Encoder) RequestParam {
	return func(req *Request) {
		req.Encode = e
	}
}

func SetDecoder(d Decoder) RequestParam {
	return func(req *Request) {
		req.Decode = d
	}
}

func SetStreamDecoder(d StreamDecoder) RequestParam {
	return func(req *Request) {
		req.StreamDecoder = d
	}
}

func SetHeader(name, value string) RequestParam {
	return func(req *Request) {
		req.Header.Set(name, value)
	}
}

func UserAgent(userAgent string) RequestParam {
	return func(req *Request) {
		req.Header.Set("User-Agent", userAgent)
	}
}

func Accept(mediaType string) RequestParam {
	return func(req *Request) {
		req.Header.Add("Accept", mediaType)
	}
}

// ClientToken set the "Client-Token" header
//
// Deprecated: The use of the non-standard "Client-Token" header is
// deprecated. Use the "Authorization" header instead. See
// `BearerAuth(…)`
func ClientToken(token string) RequestParam {
	return func(req *Request) {
		req.Header.Set("Client-Token", token)
	}
}

func BearerAuth(token string) RequestParam {
	return func(req *Request) {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

func BasicAuth(username, password string) RequestParam {
	return func(req *Request) {
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		req.Header.Set("Authorization", "Basic "+auth)
	}
}

func ContentType(contentType string) RequestParam {
	return func(req *Request) {
		req.Header.Set("Content-Type", contentType)
	}
}

func UseRawDecoder() RequestParam {
	return SetDecoder(
		func(b []byte, v interface{}) error {
			switch s := v.(type) {
			case *string:
				*s = string(b)
			case *[]byte:
				*s = b
			default:
				return errors.New("raw decoder only accepts *string and *[]byte as destinations")
			}
			return nil
		},
	)
}

func UseRawEncoder() RequestParam {
	return SetEncoder(
		func(v interface{}) ([]byte, error) {
			switch s := v.(type) {
			case string:
				return []byte(s), nil
			case []byte:
				return s, nil
			default:
				return nil, errors.New("raw encoder only encodes strings and []byte")
			}
		},
	)
}
