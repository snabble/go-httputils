package httputils

import (
	"errors"
	"net/http"
)

func AsHTTPClientError(err error) (HTTPClientError, bool) {
	var httpErr HTTPClientError
	ok := errors.As(err, &httpErr)
	return httpErr, ok
}

func IsNotFound(err error) bool {
	httpErr, ok := AsHTTPClientError(err)
	return ok && httpErr.Code == http.StatusNotFound
}
