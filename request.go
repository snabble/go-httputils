package httputils

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/cenkalti/backoff/v4"
)

type Encoder func(interface{}) ([]byte, error)

type Decoder func([]byte, interface{}) error

type Request struct {
	RawRequest *http.Request
	Header     http.Header
	Encode     Encoder

	Decode      Decoder
	RawResponse *http.Response
}

func defaultRequest() *Request {
	header := http.Header{}
	header.Add("Content-Type", "application/json")

	return &Request{
		Header: header,

		Encode: json.Marshal,
		Decode: json.Unmarshal,
	}
}

func (req *Request) applyHeader() {
	for name, values := range req.Header {
		for _, value := range values {
			req.RawRequest.Header.Add(name, value)
		}
	}
}

func (req *Request) isSuccessfulPost() bool {
	return req.RawResponse.StatusCode == http.StatusOK || req.RawResponse.StatusCode == http.StatusCreated
}

func (req Request) decodeBody(entity interface{}) error {
	data, err := ioutil.ReadAll(req.RawResponse.Body)
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
			s, ok := v.(*string)
			if !ok {
				return errors.New("raw decoder only accepts a *string as destination")
			}
			*s = string(b)
			return nil
		},
	)
}
