package httputils

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/die-net/lrucache"
	"github.com/gregjones/httpcache"
	"github.com/pkg/errors"
	logging "github.com/snabble/go-logging"
)

type RequestParam func(*http.Request)

func UserAgent(userAgent string) func(*http.Request) {
	return func(req *http.Request) {
		req.Header.Set("User-Agent", userAgent)
	}
}

func Accept(mediaType string) func(*http.Request) {
	return func(req *http.Request) {
		req.Header.Add("Accept", mediaType)
	}
}

func ClientToken(token string) func(*http.Request) {
	return func(req *http.Request) {
		req.Header.Set("Client-Token", token)
	}
}

func BearerAuth(token string) func(*http.Request) {
	return func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+token)
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
	timeout    time.Duration
	maxRetries uint64
	cacheSize  uint64
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
			Transport: selectTransport(int64(config.cacheSize)),
		},
		maxRetries: uint64(config.maxRetries),
	}
}

func selectTransport(cacheSize int64) http.RoundTripper {
	if cacheSize > 0 {
		return httpcache.NewTransport(
			lrucache.New(cacheSize, 0),
		)
	}
	return http.DefaultTransport
}

func (client *HTTPClient) Get(url string, entity interface{}, params ...RequestParam) error {
	var resp *http.Response
	clientError := false

	doRequest := func() error {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return errors.Wrapf(err, "invalid url %v", url)
		}

		for _, param := range params {
			param(req)
		}

		resp, err = client.wrapped.Do(req)
		if err != nil {
			return errors.Wrapf(err, "lookup failed %v", url)
		}

		defer resp.Body.Close()

		if http.StatusBadRequest <= resp.StatusCode && resp.StatusCode < http.StatusInternalServerError {
			clientError = true
			return nil
		}

		if resp.StatusCode != http.StatusOK {
			return HTTPClientError{Code: resp.StatusCode, Status: resp.Status}
		}

		dec := json.NewDecoder(resp.Body)
		err = dec.Decode(entity)
		if err != nil {
			return errors.Wrap(err, "decoding response body")
		}

		// Read all additional bytes from the body
		ioutil.ReadAll(resp.Body)

		return nil
	}

	notify := func(err error, duration time.Duration) {
		if err != nil {
			logging.Logger.WithError(err).Errorf("request failed to '%s', retry in %v", url, duration)
		}
	}

	backOff := backoff.WithMaxRetries(backoff.NewExponentialBackOff(), client.maxRetries)

	err := backoff.RetryNotify(doRequest, backOff, notify)
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return HTTPClientError{Code: resp.StatusCode, Status: resp.Status}
	}

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(responseBody)
	if err != nil {
		return errors.Wrap(err, "decoding response body")
	}

	// Read all additional bytes from the body
	ioutil.ReadAll(resp.Body)

	return nil
}

func (client *HTTPClient) Post(url string, requestBody interface{}, params ...RequestParam) error {
	resp, err := client.perform(http.MethodPost, url, requestBody, params...)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return HTTPClientError{Code: resp.StatusCode, Status: resp.Status}
	}

	// Read all additional bytes from the body
	ioutil.ReadAll(resp.Body)

	return nil
}

func (client *HTTPClient) Put(url string, requestBody interface{}, params ...RequestParam) error {
	resp, err := client.perform(http.MethodPut, url, requestBody, params...)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return HTTPClientError{Code: resp.StatusCode, Status: resp.Status}
	}

	// Read all additional bytes from the body
	ioutil.ReadAll(resp.Body)

	return nil
}

func (client *HTTPClient) Patch(url string, requestBody interface{}, params ...RequestParam) error {
	resp, err := client.perform(http.MethodPatch, url, requestBody, params...)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return HTTPClientError{Code: resp.StatusCode, Status: resp.Status}
	}

	// Read all additional bytes from the body
	ioutil.ReadAll(resp.Body)

	return nil
}

func (client *HTTPClient) PatchForBody(url string, requestBody interface{}, responseBody interface{}, params ...RequestParam) error {
	resp, err := client.perform(http.MethodPatch, url, requestBody, params...)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return HTTPClientError{Code: resp.StatusCode, Status: resp.Status}
	}

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(responseBody)
	if err != nil {
		return errors.Wrap(err, "decoding response body")
	}

	// Read all additional bytes from the body
	ioutil.ReadAll(resp.Body)

	return nil
}

func (client *HTTPClient) perform(method string, url string, requestBody interface{}, params ...RequestParam) (*http.Response, error) {
	data, err := json.Marshal(requestBody)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling entity")
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(data))
	if err != nil {
		return nil, errors.Wrapf(err, "invalid url %v", url)
	}

	client.applyParams(req, params)

	req.Header.Add("Content-Type", "application/json")

	resp, err := client.wrapped.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "request failed %v", url)
	}

	return resp, nil
}

func (client *HTTPClient) applyParams(req *http.Request, params []RequestParam) {
	for _, param := range params {
		param(req)
	}
}
