package httputils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v3"
	"github.com/die-net/lrucache"
	"github.com/ecosia/httpcache"
	"github.com/pkg/errors"
	logging "github.com/snabble/go-logging"
	"golang.org/x/oauth2"
)

type Encoder func(interface{}) ([]byte, error)

type Decoder func([]byte, interface{}) error

type Request struct {
	Encode   Encoder
	Decode   Decoder
	Raw      *http.Request
	Response *http.Response
}

type RequestParam func(*Request)

func SetDecoder(d Decoder) func(*Request) {
	return func(req *Request) {
		req.Decode = d
	}
}

func UserAgent(userAgent string) func(*Request) {
	return func(req *Request) {
		req.Raw.Header.Set("User-Agent", userAgent)
	}
}

func Accept(mediaType string) func(*Request) {
	return func(req *Request) {
		req.Raw.Header.Add("Accept", mediaType)
	}
}

func ClientToken(token string) func(*Request) {
	return func(req *Request) {
		req.Raw.Header.Set("Client-Token", token)
	}
}

func BearerAuth(token string) func(*Request) {
	return func(req *Request) {
		req.Raw.Header.Set("Authorization", "Bearer "+token)
	}
}

// This is applied to all requests sending a body by default
func ContentTypeJSON() func(*Request) {
	return func(req *Request) {
		req.Raw.Header.Set("Content-Type", "application/json")
	}
}

const disableCache = 0

type HTTPClientError struct {
	Code   int
	Status string
}

func (err HTTPClientError) Error() string {
	return err.Status
}

type HTTPClientConfig struct {
	timeout           time.Duration
	maxRetries        uint64
	cacheSize         uint64
	oauth2TokenSource oauth2.TokenSource
}

type HTTPClientConfigOpt func(config *HTTPClientConfig)

func Timeout(timeout time.Duration) HTTPClientConfigOpt {
	return func(config *HTTPClientConfig) {
		config.timeout = timeout
	}
}

func MaxRetries(retries uint64) HTTPClientConfigOpt {
	return func(config *HTTPClientConfig) {
		config.maxRetries = retries
	}
}

func NoRetries() HTTPClientConfigOpt {
	return MaxRetries(0)
}

func CacheSize(size uint64) HTTPClientConfigOpt {
	return func(config *HTTPClientConfig) {
		config.cacheSize = size
	}
}

func DisableCache() HTTPClientConfigOpt {
	return func(config *HTTPClientConfig) {
		config.cacheSize = disableCache
	}
}

func UseOAuth2(source oauth2.TokenSource) HTTPClientConfigOpt {
	return func(config *HTTPClientConfig) {
		config.oauth2TokenSource = source
	}
}

var HTTPClientDefaultConfig = HTTPClientConfig{
	timeout:    time.Second * 5,
	maxRetries: 3,
	cacheSize:  disableCache,
}

type HTTPClient struct {
	wrapped    http.Client
	maxRetries uint64
}

func NewHTTPClient(opts ...HTTPClientConfigOpt) *HTTPClient {
	config := HTTPClientDefaultConfig
	for _, opt := range opts {
		opt(&config)
	}

	return &HTTPClient{
		wrapped: http.Client{
			Timeout:   config.timeout,
			Transport: selectTransport(config),
		},
		maxRetries: config.maxRetries,
	}
}

func selectTransport(config HTTPClientConfig) http.RoundTripper {
	transport := http.DefaultTransport
	if config.cacheSize > 0 {
		transport = httpcache.NewTransport(
			lrucache.New(int64(config.cacheSize), 0),
		)
	}
	if config.oauth2TokenSource != nil {
		transport = &oauth2.Transport{
			Base:   transport,
			Source: config.oauth2TokenSource,
		}
	}
	return transport
}

func (client *HTTPClient) Get(url string, entity interface{}, params ...RequestParam) error {
	var resp *http.Response
	clientError := false

	doRequest := func() error {
		raw, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return errors.Wrapf(err, "invalid url %v", url)
		}
		req := defaultRequest(raw)

		for _, param := range params {
			param(req)
		}

		resp, err = client.wrapped.Do(req.Raw)
		if err != nil {
			return errors.Wrapf(err, "lookup failed %v", url)
		}
		defer resp.Body.Close()

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			errors.Wrap(err, "reading body failed")
		}
		decodeErr := req.Decode(bodyBytes, entity)

		if http.StatusBadRequest <= resp.StatusCode && resp.StatusCode < http.StatusInternalServerError {
			clientError = true
			return nil
		}

		if resp.StatusCode != http.StatusOK {
			return HTTPClientError{Code: resp.StatusCode, Status: resp.Status}
		}

		if decodeErr != nil {
			return errors.Wrap(decodeErr, "decoding response body")
		}

		return nil
	}

	notify := func(err error, duration time.Duration) {
		if err != nil {
			logging.Logger.WithError(err).Errorf("request failed to '%s', retry in %v", url, duration)
		}
	}

	var err error
	if client.maxRetries > 0 {
		backOff := backoff.WithMaxRetries(backoff.NewExponentialBackOff(), client.maxRetries)
		err = backoff.RetryNotify(doRequest, backOff, notify)
	} else {
		err = doRequest()
	}
	if err != nil {
		return err
	}

	if clientError {
		return HTTPClientError{Code: resp.StatusCode, Status: resp.Status}
	}
	return nil
}

func (client *HTTPClient) PostForBody(url string, requestBody interface{}, responseBody interface{}, params ...RequestParam) error {
	resp, err := client.perform(http.MethodPost, url, requestBody, params...)
	if err != nil {
		return err
	}
	defer resp.Response.Body.Close()

	decodeErr := resp.decodeBody(responseBody)

	if resp.Response.StatusCode != http.StatusOK && resp.Response.StatusCode != http.StatusCreated {
		return HTTPClientError{Code: resp.Response.StatusCode, Status: resp.Response.Status}
	}

	if decodeErr != nil {
		return errors.Wrap(decodeErr, "decoding response body")
	}

	return nil
}

func (client *HTTPClient) Post(url string, requestBody interface{}, params ...RequestParam) error {
	resp, err := client.perform(http.MethodPost, url, requestBody, params...)
	if err != nil {
		return err
	}
	defer resp.Response.Body.Close()

	if resp.Response.StatusCode != http.StatusOK && resp.Response.StatusCode != http.StatusCreated {
		return HTTPClientError{Code: resp.Response.StatusCode, Status: resp.Response.Status}
	}

	// Read all additional bytes from the body
	ioutil.ReadAll(resp.Raw.Body)

	return nil
}

func (client *HTTPClient) Put(url string, requestBody interface{}, params ...RequestParam) error {
	resp, err := client.perform(http.MethodPut, url, requestBody, params...)
	if err != nil {
		return err
	}
	defer resp.Response.Body.Close()

	if resp.Response.StatusCode != http.StatusOK && resp.Response.StatusCode != http.StatusCreated {
		return HTTPClientError{Code: resp.Response.StatusCode, Status: resp.Response.Status}
	}

	// Read all additional bytes from the body
	ioutil.ReadAll(resp.Raw.Body)

	return nil
}

func (client *HTTPClient) Patch(url string, requestBody interface{}, params ...RequestParam) error {
	resp, err := client.perform(http.MethodPatch, url, requestBody, params...)
	if err != nil {
		return err
	}
	defer resp.Response.Body.Close()

	if resp.Response.StatusCode != http.StatusOK {
		return HTTPClientError{Code: resp.Response.StatusCode, Status: resp.Response.Status}
	}

	// Read all additional bytes from the body
	ioutil.ReadAll(resp.Response.Body)

	return nil
}

func (client *HTTPClient) PatchForBody(url string, requestBody interface{}, responseBody interface{}, params ...RequestParam) error {
	resp, err := client.perform(http.MethodPatch, url, requestBody, params...)
	if err != nil {
		return err
	}
	defer resp.Response.Body.Close()

	decodeErr := resp.decodeBody(responseBody)

	if resp.Response.StatusCode != http.StatusOK && resp.Response.StatusCode != http.StatusCreated {
		return HTTPClientError{Code: resp.Response.StatusCode, Status: resp.Response.Status}
	}

	if decodeErr != nil {
		return errors.Wrap(decodeErr, "decoding response body")
	}

	return nil
}

func (client *HTTPClient) perform(method string, url string, requestBody interface{}, params ...RequestParam) (*Request, error) {
	rawReq, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid url %v", url)
	}

	req := defaultRequest(rawReq)

	data, err := req.Encode(requestBody)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling entity")
	}

	params = append(params, ContentTypeJSON())
	client.applyParams(req, params)

	req.Raw.Body = ioutil.NopCloser(bytes.NewBuffer(data))

	req.Response, err = client.wrapped.Do(req.Raw)
	if err != nil {
		return nil, errors.Wrapf(err, "request failed %v", url)
	}

	return req, nil
}

func (client *HTTPClient) applyParams(req *Request, params []RequestParam) {
	for _, param := range params {
		param(req)
	}
}

func (r Request) decodeBody(entity interface{}) error {
	data, err := ioutil.ReadAll(r.Response.Body)
	if err != nil {
		return fmt.Errorf("reading response body: '%w'", err)
	}
	return r.Decode(data, entity)
}

func defaultRequest(raw *http.Request) *Request {
	return &Request{
		Raw:    raw,
		Encode: json.Marshal,
		Decode: json.Unmarshal,
	}
}
