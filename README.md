# go-httputils

Some go http utils.

## Customize retries
Sometimes APIs do not act as expected, for instance they return a 500 instead
of an 404 with a description in the responses body. For these cases you can amend
the behaviour when a failed request should be retried or not.

```go
client := NewHTTPClient(
    RetryPredicate(func(req *Request, err error) bool {
        body, _ := io.ReadAll(req.RawResponse.Body)
        // Do not retry when the body is "ERROR" and the error is not caused by by the client.
        return !(string(body) == "ERROR" && !req.isClientError())
    }),
    MaxRetries(1),
)
```