package httputils

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"syscall"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/die-net/lrucache"
	"github.com/ecosia/httpcache"
	logging "github.com/snabble/go-logging/v2"
	"golang.org/x/oauth2"
)

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
	timeout            time.Duration
	tlsConfig          *tls.Config
	createBackOffGet   func() backoff.BackOff
	createBackOffOther func() backoff.BackOff
	cacheSize          uint64
	token              string
	username           string
	password           string
	oauth2TokenSource  oauth2.TokenSource
	logCall            CallLogger
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
		config.createBackOffGet = func() backoff.BackOff { return backoff.WithMaxRetries(backoff.NewExponentialBackOff(), retries) }
		config.createBackOffOther = func() backoff.BackOff { return backoff.WithMaxRetries(backoff.NewExponentialBackOff(), retries) }
	}
}

func NoRetries() HTTPClientConfigOpt {
	return MaxRetries(0)
}

func SetGetBackoffCreator(creator func() backoff.BackOff) HTTPClientConfigOpt {
	return func(config *HTTPClientConfig) {
		config.createBackOffGet = creator
	}
}

func SetOtherBackoffCreator(creator func() backoff.BackOff) HTTPClientConfigOpt {
	return func(config *HTTPClientConfig) {
		config.createBackOffOther = creator
	}
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
	timeout:            time.Second * 5,
	createBackOffGet:   func() backoff.BackOff { return backoff.WithMaxRetries(backoff.NewExponentialBackOff(), 3) },
	createBackOffOther: func() backoff.BackOff { return &backoff.StopBackOff{} },
	cacheSize:          disableCache,
	logCall:            func(r *http.Request, resp *http.Response, start time.Time, err error) {},
}

type HTTPClient struct {
	wrapped            http.Client
	createBackOffGet   func() backoff.BackOff
	createBackOffOther func() backoff.BackOff
	logCall            CallLogger
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
		createBackOffGet:   config.createBackOffGet,
		createBackOffOther: config.createBackOffOther,
		logCall:            config.logCall,
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

func (client *HTTPClient) Head(url string, params ...RequestParam) error {
	return client.withBackOff(
		url,
		client.createBackOffGet(),
		func() error {
			var err error

			req := defaultRequest()
			applyParams(req, params)

			req.RawRequest, err = http.NewRequest(http.MethodHead, url, nil)
			if err != nil {
				return wrapErrorF(err, "invalid url %v", url)
			}

			if err := client.do(req); err != nil {
				return err
			}

			if req.isClientError() {
				return permanentHTTPError(req)
			}

			if req.RawResponse.StatusCode != http.StatusOK {
				return httpError(req)
			}

			return nil
		},
	)
}

func (client *HTTPClient) Get(url string, entity interface{}, params ...RequestParam) error {
	return client.withBackOff(
		url,
		client.createBackOffGet(),
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

			if req.isClientError() {
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
		http.MethodPost,
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
		http.MethodPost,
		url,
		requestBody,
		params,
		func(resp *Request) error {
			// Read all additional bytes from the body
			defer ioutil.ReadAll(resp.RawResponse.Body)

			if !resp.isSuccessfulPost() {
				return permanentHTTPError(resp)
			}

			return nil
		},
	)
}

func (client *HTTPClient) PostForLocation(url string, requestBody interface{}, params ...RequestParam) (string, error) {
	var location string
	err := client.performWithRetries(
		http.MethodPost,
		url,
		requestBody,
		params,
		func(resp *Request) error {
			// Read all additional bytes from the body
			defer ioutil.ReadAll(resp.RawResponse.Body)

			if !resp.isSuccessfulPost() {
				return permanentHTTPError(resp)
			}

			location = resp.RawResponse.Header.Get("Location")

			return nil
		},
	)

	return location, err
}

func (client *HTTPClient) PostForLocationAndBody(
	url string,
	requestBody interface{},
	responseBody interface{},
	params ...RequestParam,
) (string, error) {
	var location string

	err := client.performWithRetries(
		http.MethodPost,
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

			location = resp.RawResponse.Header.Get("Location")

			return nil
		},
	)

	return location, err
}

func (client *HTTPClient) Put(url string, requestBody interface{}, params ...RequestParam) error {
	return client.performWithRetries(
		http.MethodPut,
		url,
		requestBody,
		params,
		func(resp *Request) error {
			// Read all additional bytes from the body
			defer ioutil.ReadAll(resp.RawResponse.Body)

			if !resp.isSuccessfulPost() {
				return permanentHTTPError(resp)
			}

			return nil
		},
	)
}

func (client *HTTPClient) PutForBody(url string, requestBody interface{}, responseBody interface{}, params ...RequestParam) error {
	return client.performWithRetries(
		http.MethodPut,
		url,
		requestBody,
		params,
		func(resp *Request) error {
			decodeErr := resp.decodeBody(responseBody)

			if !resp.isSuccessfulPost() {
				return permanentHTTPError(resp)
			}

			if decodeErr != nil {
				return backoff.Permanent(wrapErrorF(decodeErr, "decoding response body"))
			}

			return nil
		},
	)
}

func (client *HTTPClient) Patch(url string, requestBody interface{}, params ...RequestParam) error {
	return client.performWithRetries(
		http.MethodPatch,
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
		http.MethodPatch,
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

func (client *HTTPClient) Delete(url string, params ...RequestParam) error {
	return client.performWithRetries(
		http.MethodDelete,
		url,
		nil,
		params,
		func(resp *Request) error {
			// Read all additional bytes from the body
			defer ioutil.ReadAll(resp.RawResponse.Body)

			if http.StatusBadRequest <= resp.RawResponse.StatusCode && resp.RawResponse.StatusCode < http.StatusInternalServerError {
				return permanentHTTPError(resp)
			}

			if resp.RawResponse.StatusCode != http.StatusOK && resp.RawResponse.StatusCode != http.StatusNoContent && resp.RawResponse.StatusCode != http.StatusAccepted {
				return httpError(resp)
			}

			return nil
		},
	)
}

func (client *HTTPClient) performWithRetries(method, reqURL string, requestBody interface{}, params []RequestParam, handleResponse func(*Request) error) error {
	return client.withBackOff(
		reqURL,
		client.createBackOffOther(),
		func() error {
			resp, err := client.perform(method, reqURL, requestBody, params...)
			urlErr := &url.Error{}
			if errors.As(err, &urlErr) && (urlErr.Temporary() || urlErr.Timeout()) {
				return err
			}
			var syscallErr *os.SyscallError
			if errors.As(err, &syscallErr) && syscallErr.Err == syscall.ECONNRESET {
				return err
			}
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

func (client *HTTPClient) perform(method, url string, requestBody interface{}, params ...RequestParam) (*Request, error) {
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

func (client *HTTPClient) withBackOff(url string, b backoff.BackOff, doRequest func() error) error {
	notify := func(err error, duration time.Duration) {
		if err != nil {
			logging.Log.WithError(err).Warnf("request failed to '%s', retry in %v", url, duration)
		}
	}

	return backoff.RetryNotify(
		doRequest,
		b,
		notify,
	)
}
