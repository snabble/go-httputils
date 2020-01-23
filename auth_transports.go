package httputils

import "net/http"

type BearerAuthTransport struct {
	Token     string
	Transport http.RoundTripper
}

func (t *BearerAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+t.Token)
	return t.Transport.RoundTrip(req)
}

type BasicAuthTransport struct {
	Username, Password string
	Transport          http.RoundTripper
}

func (t *BasicAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.SetBasicAuth(t.Username, t.Password)
	return t.Transport.RoundTrip(req)
}
