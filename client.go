package httputils

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v3"
	"github.com/die-net/lrucache"
	"github.com/ecosia/httpcache"
	logging "github.com/snabble/go-logging"
	"golang.org/x/oauth2"
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

func (req *Request) applyHeader() {
	for name, values := range req.Header {
		for _, value := range values {
			req.RawRequest.Header.Add(name, value)
		}
	}
}

type RequestParam func(*Request)

func SetEncoder(e Encoder) func(*Request) {
	return func(req *Request) {
		req.Encode = e
	}
}

func SetDecoder(d Decoder) func(*Request) {
	return func(req *Request) {
		req.Decode = d
	}
}

func UserAgent(userAgent string) func(*Request) {
	return func(req *Request) {
		req.Header.Set("User-Agent", userAgent)
	}
}

func Accept(mediaType string) func(*Request) {
	return func(req *Request) {
		req.Header.Add("Accept", mediaType)
	}
}

func ClientToken(token string) func(*Request) {
	return func(req *Request) {
		req.Header.Set("Client-Token", token)
	}
}

func BearerAuth(token string) func(*Request) {
	return func(req *Request) {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

func ContentType(contentType string) func(*Request) {
	return func(req *Request) {
		req.Header.Set("Content-Type", contentType)
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

type CallLogger func(r *http.Request, resp *http.Response, start time.Time, err error)

type HTTPClientConfig struct {
	timeout           time.Duration
	tlsConfig         *tls.Config
	maxRetriesGet     uint64
	maxRetriesOther   uint64
	cacheSize         uint64
	token             string
	username          string
	password          string
	oauth2TokenSource oauth2.TokenSource
	logCall           CallLogger
}

type HTTPClientConfigOpt func(config *HTTPClientConfig)

func Timeout(timeout time.Duration) HTTPClientConfigOpt {
	return func(config *HTTPClientConfig) {
		config.timeout = timeout
	}
}

func TLSConfig(tlsConfig *tls.Config) HTTPClientConfigOpt {
	return func(config *HTTPClientConfig) {
		config.tlsConfig = tlsConfig
	}
}

func MaxRetries(retries uint64) HTTPClientConfigOpt {
	return func(config *HTTPClientConfig) {
		config.maxRetriesGet = retries
		config.maxRetriesOther = retries
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

func UseBearerAuth(token string) HTTPClientConfigOpt {
	return func(config *HTTPClientConfig) {
		config.token = token
	}
}

func UseBasicAuth(username, password string) HTTPClientConfigOpt {
	return func(config *HTTPClientConfig) {
		config.username = username
		config.password = password
	}
}

func UseOAuth2(source oauth2.TokenSource) HTTPClientConfigOpt {
	return func(config *HTTPClientConfig) {
		config.oauth2TokenSource = source
	}
}

func LogCalls(logger CallLogger) HTTPClientConfigOpt {
	return func(config *HTTPClientConfig) {
		config.logCall = logger
	}
}

var HTTPClientDefaultConfig = HTTPClientConfig{
	timeout:         time.Second * 5,
	maxRetriesGet:   3,
	maxRetriesOther: 0,
	cacheSize:       disableCache,
	logCall:         func(r *http.Request, resp *http.Response, start time.Time, err error) {},
}

type HTTPClient struct {
	wrapped         http.Client
	maxRetriesGet   uint64
	maxRetriesOther uint64
	logCall         CallLogger
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
		maxRetriesGet:   config.maxRetriesGet,
		maxRetriesOther: config.maxRetriesOther,
		logCall:         config.logCall,
	}
}

func selectTransport(config HTTPClientConfig) http.RoundTripper {
	transport := createTransport(config)

	if config.username != "" || config.password != "" {
		transport = &BasicAuthTransport{
			Username:  config.username,
			Password:  config.password,
			Transport: transport,
		}
	}

	if config.token != "" {
		transport = &BearerAuthTransport{
			Transport: transport,
			Token:     config.token,
		}
	}

	if config.cacheSize > 0 {
		transport = &httpcache.Transport{
			Transport:           transport,
			Cache:               lrucache.New(int64(config.cacheSize), 0),
			MarkCachedResponses: true,
		}
	}

	if config.oauth2TokenSource != nil {
		transport = &oauth2.Transport{
			Base:   transport,
			Source: config.oauth2TokenSource,
		}
	}

	return transport
}

func createTransport(config HTTPClientConfig) http.RoundTripper {
	return &http.Transport{
		TLSClientConfig: config.tlsConfig,
	}
}

func (client *HTTPClient) Get(url string, entity interface{}, params ...RequestParam) error {
	return client.withBackoff(
		url,
		client.maxRetriesGet,
		func() error {
			var err error

			req := defaultRequest()
			applyParams(req, params)

			req.RawRequest, err = http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				return wrapErrorF(err, "invalid url %v", url)
			}

			if err := client.do(req); err != nil {
				return err
			}

			decodeErr := req.decodeBody(entity)

			if http.StatusBadRequest <= req.RawResponse.StatusCode && req.RawResponse.StatusCode < http.StatusInternalServerError {
				return permanentHTTPError(req)
			}

			if req.RawResponse.StatusCode != http.StatusOK {
				return httpError(req)
			}

			if decodeErr != nil {
				return wrapError(decodeErr, "decoding response body")
			}

			return nil
		},
	)
}

func (client *HTTPClient) PostForBody(url string, requestBody interface{}, responseBody interface{}, params ...RequestParam) error {
	return client.performWithRetries(
		url,
		requestBody,
		params,
		func(resp *Request) error {
			decodeErr := resp.decodeBody(responseBody)

			if resp.RawResponse.StatusCode != http.StatusOK && resp.RawResponse.StatusCode != http.StatusCreated {
				return permanentHTTPError(resp)
			}

			if decodeErr != nil {
				return backoff.Permanent(wrapErrorF(decodeErr, "decoding response body"))
			}

			return nil
		},
	)
}

func (client *HTTPClient) Post(url string, requestBody interface{}, params ...RequestParam) error {
	return client.performWithRetries(
		url,
		requestBody,
		params,
		func(resp *Request) error {
			// Read all additional bytes from the body
			defer ioutil.ReadAll(resp.RawResponse.Body)

			if resp.RawResponse.StatusCode != http.StatusOK && resp.RawResponse.StatusCode != http.StatusCreated {
				return permanentHTTPError(resp)
			}

			return nil
		},
	)
}

func (client *HTTPClient) Put(url string, requestBody interface{}, params ...RequestParam) error {
	return client.performWithRetries(
		url,
		requestBody,
		params,
		func(resp *Request) error {
			// Read all additional bytes from the body
			defer ioutil.ReadAll(resp.RawResponse.Body)

			if resp.RawResponse.StatusCode != http.StatusOK && resp.RawResponse.StatusCode != http.StatusCreated {
				return permanentHTTPError(resp)
			}

			return nil
		},
	)
}

func (client *HTTPClient) Patch(url string, requestBody interface{}, params ...RequestParam) error {
	return client.performWithRetries(
		url,
		requestBody,
		params,
		func(resp *Request) error {
			// Read all additional bytes from the body
			defer ioutil.ReadAll(resp.RawResponse.Body)

			if resp.RawResponse.StatusCode != http.StatusOK {
				return permanentHTTPError(resp)
			}

			return nil
		},
	)
}

func (client *HTTPClient) PatchForBody(url string, requestBody interface{}, responseBody interface{}, params ...RequestParam) error {
	return client.performWithRetries(
		url,
		requestBody,
		params,
		func(resp *Request) error {
			decodeErr := resp.decodeBody(responseBody)

			if resp.RawResponse.StatusCode != http.StatusOK && resp.RawResponse.StatusCode != http.StatusCreated {
				return permanentHTTPError(resp)
			}

			if decodeErr != nil {
				return backoff.Permanent(wrapErrorF(decodeErr, "decoding response body"))
			}

			return nil
		},
	)
}

func (client *HTTPClient) performWithRetries(url string, requestBody interface{}, params []RequestParam, handleResponse func(*Request) error) error {
	return client.withBackoff(
		url,
		client.maxRetriesOther,
		func() error {
			resp, err := client.perform(http.MethodPost, url, requestBody, params...)
			if errors.Is(err, io.EOF) {
				return err
			}
			if err != nil {
				return backoff.Permanent(err)
			}
			defer resp.RawResponse.Body.Close()

			return handleResponse(resp)
		},
	)
}

func (client *HTTPClient) perform(method string, url string, requestBody interface{}, params ...RequestParam) (*Request, error) {
	req := defaultRequest()
	applyParams(req, params)

	data, err := req.Encode(requestBody)
	if err != nil {
		return nil, wrapError(err, "marshalling entity")
	}

	req.RawRequest, err = http.NewRequest(method, url, bytes.NewBuffer(data))
	if err != nil {
		return nil, wrapErrorF(err, "invalid url %v", url)
	}

	if err := client.do(req); err != nil {
		return nil, err
	}
	return req, nil
}

func (client *HTTPClient) do(req *Request) (err error) {
	req.applyHeader()

	start := time.Now()

	req.RawResponse, err = client.wrapped.Do(req.RawRequest)

	client.logCall(req.RawRequest, req.RawResponse, start, err)

	if err != nil {
		return wrapErrorF(err, "request failed %v", req.RawRequest.URL.String())
	}

	return nil
}

func (client *HTTPClient) withBackoff(url string, maxRetries uint64, doRequest func() error) error {
	notify := func(err error, duration time.Duration) {
		if err != nil {
			logging.Logger.WithError(err).Errorf("request failed to '%s', retry in %v", url, duration)
		}
	}

	var err error
	var b backoff.BackOff = &backoff.StopBackOff{}
	if maxRetries > 0 {
		b = backoff.WithMaxRetries(backoff.NewExponentialBackOff(), maxRetries)
	}
	err = backoff.RetryNotify(doRequest, b, notify)
	if err != nil {
		return err
	}

	return nil
}

func applyParams(req *Request, params []RequestParam) {
	for _, param := range params {
		param(req)
	}
}

func (r Request) decodeBody(entity interface{}) error {
	data, err := ioutil.ReadAll(r.RawResponse.Body)
	if err != nil {
		return fmt.Errorf("reading response body: '%w'", err)
	}
	return r.Decode(data, entity)
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

func permanentHTTPError(resp *Request) error {
	return backoff.Permanent(httpError(resp))
}

func httpError(resp *Request) error {
	return HTTPClientError{Code: resp.RawResponse.StatusCode, Status: resp.RawResponse.Status}
}
