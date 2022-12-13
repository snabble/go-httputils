package httputils

import (
	"net/http"
	"strings"
)

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

// BearerAuthTransport wraps a RoundTripper. It capitalized bearer token
// authorization headers.
// Based on https://sgeb.io/posts/fix-go-oauth2-case-sensitive-bearer-auth-headers/
type BearerAuthOverridingHeadersTransport struct {
	rt     http.RoundTripper
	prefix string
}

// RoundTrip satisfies the RoundTripper interface. It replaces authorization
// headers of scheme `bearer` by capitalized `Bearer` (as per OAuth 2.0 spec).
func (t *BearerAuthOverridingHeadersTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	auth := req.Header.Get("Authorization")
	parts := strings.Split(auth, " ")
	if len(parts) > 1 {
		//auth probably looks like: <prefix> something
		//so we replace the prefix with our own:
		auth = t.prefix + auth[len(parts[0]):] //Bearer  Ac0H6Q410JZry95aCiTFvU2uVUHj
	}

	req2 := cloneRequest(req) // per RoundTripper contract
	req2.Header.Set("Authorization", auth)

	return t.rt.RoundTrip(req2)
}

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}
