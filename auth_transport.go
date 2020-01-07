package httputils

import "net/http"

type AuthTransport struct {
	Token     string
	Transport http.RoundTripper
}

func (t *AuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+t.Token)
	return t.Transport.RoundTrip(req)
}
