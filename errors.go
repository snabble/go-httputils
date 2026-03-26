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
	return IsErrorWithStatusCode(err, http.StatusNotFound)
}

func IsErrorWithStatusCode(err error, statusCode int) bool {
	httpErr, ok := AsHTTPClientError(err)
	return ok && httpErr.Code == statusCode
}
