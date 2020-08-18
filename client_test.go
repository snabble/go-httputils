package httputils

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func Test_HTTPClient_Get(t *testing.T) {
	for _, test := range []struct {
		name      string
		responses []mockServerResponse
		expected  testEntity
	}{
		{
			name: "success",
			responses: []mockServerResponse{
				mockResponse(http.StatusOK, `{ "Field": "test"}`),
			},
			expected: testEntity{Field: "test"},
		},
		{
			name: "success after retry",
			responses: []mockServerResponse{
				mockResponse(http.StatusInternalServerError, ``),
				mockResponse(http.StatusOK, `{ "Field": "test"}`),
			},
			expected: testEntity{Field: "test"},
		},
		{
			name: "retries if response was corrupted",
			responses: []mockServerResponse{
				mockResponse(http.StatusOK, `}{`),
				mockResponse(http.StatusOK, `{ "Field": "test"}`),
			},
			expected: testEntity{Field: "test"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, verify := testMockServer(test.responses)
			server := httptest.NewServer(handler)
			defer server.Close()

			client := NewHTTPClient(MaxRetries(3))
			entity := testEntity{}

			err := client.Get(server.URL+"/", &entity)

			require.NoError(t, err)
			assert.Equal(t, test.expected, entity)
			assert.Equal(t, http.MethodGet, verify.method)
		})
	}
}

func Test_HTTPClient_Get_DoesNotRetry(t *testing.T) {
	handler, verify := testMockServer(mockResponses(http.StatusInternalServerError, `{ "Field": "test"}`))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient(NoRetries())
	entity := testEntity{}

	err := client.Get(server.URL+"/", &entity)

	require.Error(t, err)
	assert.Equal(t, 1, verify.calls)
}

func Test_HTTPClient_Get_UserAgent(t *testing.T) {
	handler, verify := testMockServer(mockResponses(http.StatusOK, `{ "Field": "test"}`))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	entity := testEntity{}

	err := client.Get(server.URL+"/", &entity, UserAgent("user-agent"))

	require.NoError(t, err)
	assert.Equal(t, "user-agent", verify.userAgent)
}

func Test_HTTPClient_Get_AcceptHeader(t *testing.T) {
	handler, verify := testMockServer(mockResponses(http.StatusOK, `{ "Field": "test"}`))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	entity := testEntity{}

	err := client.Get(server.URL+"/", &entity, Accept("application/something+json"))

	require.NoError(t, err)
	assert.Equal(t, "application/something+json", verify.accept)
}

func Test_HTTPClient_Get_ClientTokenHeader(t *testing.T) {
	handler, verify := testMockServer(mockResponses(http.StatusOK, `{ "Field": "test"}`))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	entity := testEntity{}

	err := client.Get(server.URL+"/", &entity, ClientToken("token"))

	require.NoError(t, err)
	assert.Equal(t, "token", verify.token)
}

func Test_HTTPClient_Get_SetDecoder(t *testing.T) {
	handler, _ := testMockServer(mockResponses(http.StatusOK, `not json`))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()

	testEntity := testEntity{}
	err := client.Get(server.URL+"/", &testEntity, SetDecoder(mockDecode(t)))
	require.NoError(t, err)
	assert.Equal(t, "aField", testEntity.Field)
}

func Test_HTTPClient_Get_UseRawDecoder(t *testing.T) {
	handler, _ := testMockServer(mockResponses(http.StatusOK, `not json`))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()

	var testEntity string
	err := client.Get(server.URL+"/", &testEntity, UseRawDecoder())
	require.NoError(t, err)
	assert.Equal(t, "not json", testEntity)
}

func Test_HTTPClient_Get_LogCalls(t *testing.T) {
	called := false

	handler, _ := testMockServer(mockResponses(http.StatusOK, `{ "Field": "test"}`))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient(
		LogCalls(func(r *http.Request, resp *http.Response, start time.Time, err error) { called = true }),
	)

	err := client.Get(server.URL+"/", &testEntity{})

	require.NoError(t, err)
	assert.True(t, called)
}

func Test_HTPClient_Get_HTTPErrorCases(t *testing.T) {
	for _, test := range []struct {
		Name           string
		StatusCode     int
		Body           string
		ExpectedEntity testEntity
	}{
		{
			Name:       "client error no body",
			StatusCode: http.StatusBadRequest,
		},
		{
			Name:       "client error with body",
			StatusCode: http.StatusBadRequest,
			Body:       `{"Field": "error" }`,
			ExpectedEntity: testEntity{
				Field: "error",
			},
		},
		{
			Name:       "server error no body",
			StatusCode: http.StatusInternalServerError,
		},
		{
			Name:       "server error with invalid body",
			StatusCode: http.StatusInternalServerError,
			Body:       "invalid json",
		},
		{
			Name:       "server error with body",
			StatusCode: http.StatusInternalServerError,
			Body:       `{"Field": "error" }`,
			ExpectedEntity: testEntity{
				Field: "error",
			},
		},
	} {
		t.Run(test.Name, func(t *testing.T) {
			handler, verify := testMockServer(mockResponses(test.StatusCode, test.Body))
			server := httptest.NewServer(handler)
			defer server.Close()

			client := NewHTTPClient(NoRetries())
			entity := testEntity{}

			err := client.Get(server.URL+"/", &entity)

			assert.Error(t, err)
			assert.Equal(t, 1, verify.calls)
			if clientError, ok := err.(HTTPClientError); ok {
				assert.Equal(t, test.StatusCode, clientError.Code)
			} else {
				t.Error("Not an HTTPClientError:", err)
			}
			assert.Equal(t, test.ExpectedEntity, entity)
		})
	}
}

func Test_HttpClient_Get_cache(t *testing.T) {
	handler, verify := testMockServer([]mockServerResponse{
		{statusCode: http.StatusOK, body: `{}`, header: map[string]string{"Cache-Control": "max-age=3600"}},
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient(CacheSize(8 * 1024 * 1024))

	for i := 0; i < 10; i++ {
		entity := testEntity{}
		err := client.Get(server.URL+"/", &entity)

		require.NoError(t, err)
	}

	assert.Equal(t, 1, verify.calls)
}

func Test_HttpClient_Get_OAuth2(t *testing.T) {
	handler, verify := testMockServer(mockResponses(http.StatusOK, `{}`))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient(UseOAuth2(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "some-token"})))
	request := testEntity{Field: "send"}

	err := client.Get(server.URL+"/", &request)

	assert.NoError(t, err)
	assert.Equal(t, 1, verify.calls)
	assert.Equal(t, "Bearer some-token", verify.authorization)
}

func Test_HttpClient_Get_UseBearerAuth(t *testing.T) {
	handler, verify := testMockServer(mockResponses(http.StatusOK, `{}`))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient(UseBearerAuth("some-token"))
	request := testEntity{Field: "send"}

	err := client.Get(server.URL+"/", &request)

	assert.NoError(t, err)
	assert.Equal(t, 1, verify.calls)
	assert.Equal(t, "Bearer some-token", verify.authorization)
}

func Test_HttpClient_Get_UseBasicAuth(t *testing.T) {
	handler, verify := testMockServer(mockResponses(http.StatusOK, `{}`))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient(UseBasicAuth("user", "secret"))
	request := testEntity{Field: "send"}

	err := client.Get(server.URL+"/", &request)

	assert.NoError(t, err)
	assert.Equal(t, 1, verify.calls)
	assert.Equal(t, "Basic dXNlcjpzZWNyZXQ=", verify.authorization)
}

func Test_HTTPClient_Get_TLSConfig(t *testing.T) {
	handler, _ := testMockServer(mockResponses(http.StatusOK, `{ "Field": "test"}`))
	server := httptest.NewUnstartedServer(handler)
	server.Config.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{readKeyPair(t, "server")},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    readCertPool(t),
	}
	server.StartTLS()
	defer server.Close()

	client := NewHTTPClient(TLSConfig(
		&tls.Config{Certificates: []tls.Certificate{readKeyPair(t, "client")}, InsecureSkipVerify: true},
	))
	entity := testEntity{}

	err := client.Get(server.URL+"/", &entity)

	require.NoError(t, err)
	assert.Equal(t, testEntity{Field: "test"}, entity)
}

func Test_HTTPClient_PostForBody(t *testing.T) {
	handler, verify := testMockServer(mockResponses(http.StatusCreated, `{ "Field": "test"}`))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	request := testEntity{Field: "send"}
	response := testEntity{}

	err := client.PostForBody(server.URL+"/", &request, &response)

	assert.NoError(t, err)
	assert.Equal(t, 1, verify.calls)
	assert.Equal(t, http.MethodPost, verify.method)
	assert.Equal(t, "application/json", verify.contentType)
	assert.JSONEq(t, `{ "Field": "send"}`, verify.body)
	assert.Equal(t, testEntity{Field: "test"}, response)
}

func Test_HTTPClient_PostForBody_RetriesOnConnectionError(t *testing.T) {
	server := connectionClosingServer(t)
	defer server.close()

	client := NewHTTPClient(MaxRetries(1))
	request := testEntity{Field: "send"}
	response := testEntity{}

	err := client.PostForBody(server.url, &request, &response)

	require.Error(t, err)
	assert.Equal(t, 2, server.calls)
}

func Test_HTTPClient_PostForBody_NotRetriesOnConnectionError(t *testing.T) {
	server := connectionClosingServer(t)
	defer server.close()

	client := NewHTTPClient()
	request := testEntity{Field: "send"}
	response := testEntity{}

	err := client.PostForBody(server.url, &request, &response)

	require.Error(t, err)
	assert.Equal(t, 1, server.calls)
}

func Test_HTTPClient_PostForBody_SetEncoderAndDecoder(t *testing.T) {
	handler, verify := testMockServer(mockResponses(http.StatusCreated, `not json`))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	request := testEntity{Field: "send"}
	response := testEntity{}

	err := client.PostForBody(server.URL+"/", &request, &response, SetEncoder(mockEncode(t)), SetDecoder(mockDecode(t)), ContentType("plain"))

	assert.NoError(t, err)
	assert.Equal(t, 1, verify.calls)
	assert.Equal(t, "plain", verify.contentType)
	assert.Equal(t, "send", verify.body)
	assert.Equal(t, testEntity{Field: "aField"}, response)
}

func Test_HTTPClient_PostForBody_UseRawEncoder(t *testing.T) {
	handler, verify := testMockServer(mockResponses(http.StatusCreated, `not json`))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	request := "a body"

	err := client.Post(server.URL+"/", request, UseRawEncoder(), ContentType("plain"))

	assert.NoError(t, err)
	assert.Equal(t, 1, verify.calls)
	assert.Equal(t, "plain", verify.contentType)
	assert.Equal(t, "a body", verify.body)
}

func Test_HTPClient_PostForBody_HTTPErrorCases(t *testing.T) {
	for _, test := range []struct {
		Name           string
		StatusCode     int
		Body           string
		ExpectedEntity testEntity
	}{
		{
			Name:       "client error no body",
			StatusCode: http.StatusBadRequest,
		},
		{
			Name:       "client error with invalid body",
			StatusCode: http.StatusBadRequest,
			Body:       "invalid json",
		},
		{
			Name:       "client error with body",
			StatusCode: http.StatusBadRequest,
			Body:       `{"Field": "error" }`,
			ExpectedEntity: testEntity{
				Field: "error",
			},
		},
		{
			Name:       "server error no body",
			StatusCode: http.StatusInternalServerError,
		},
		{
			Name:       "server error with invalid body",
			StatusCode: http.StatusInternalServerError,
			Body:       "invalid json",
		},
		{
			Name:       "server error with body",
			StatusCode: http.StatusInternalServerError,
			Body:       `{"Field": "error" }`,
			ExpectedEntity: testEntity{
				Field: "error",
			},
		},
	} {
		t.Run(test.Name, func(t *testing.T) {
			handler, verify := testMockServer(mockResponses(test.StatusCode, test.Body))
			server := httptest.NewServer(handler)
			defer server.Close()

			client := NewHTTPClient()
			entity := testEntity{}

			err := client.PostForBody(server.URL+"/", &entity, &entity)

			assert.Error(t, err)
			assert.Equal(t, 1, verify.calls)
			if clientError, ok := err.(HTTPClientError); ok {
				assert.Equal(t, test.StatusCode, clientError.Code)
			} else {
				t.Error("Not an HTTPClientError:", err)
			}
			assert.Equal(t, test.ExpectedEntity, entity)
		})
	}
}

func Test_HTTPClient_Post(t *testing.T) {
	handler, verify := testMockServer(mockResponses(http.StatusCreated, `{ "Field": "test"}`))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	request := testEntity{Field: "send"}

	err := client.Post(server.URL+"/", &request)

	assert.NoError(t, err)
	assert.Equal(t, 1, verify.calls)
	assert.Equal(t, http.MethodPost, verify.method)
	assert.Equal(t, "application/json", verify.contentType)
	assert.JSONEq(t, `{ "Field": "send"}`, verify.body)
}

func Test_HTTPClient_Post_clientError(t *testing.T) {
	handler, verify := testMockServer(mockResponses(http.StatusBadRequest, ``))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	entity := testEntity{}

	err := client.Post(server.URL+"/", &entity)

	assert.Error(t, err)
	assert.Equal(t, 1, verify.calls)
	if clientError, ok := err.(HTTPClientError); ok {
		assert.Equal(t, http.StatusBadRequest, clientError.Code)
	} else {
		t.Error("Not an HTTPClientError:", err)
	}
}

func Test_HTTPClient_Post_serverError(t *testing.T) {
	handler, verify := testMockServer(mockResponses(http.StatusInternalServerError, ``))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	entity := testEntity{}

	err := client.Post(server.URL+"/", &entity)

	assert.Error(t, err)
	assert.Equal(t, 1, verify.calls)
	if httpError, ok := err.(HTTPClientError); ok {
		assert.Equal(t, http.StatusInternalServerError, httpError.Code)
	} else {
		t.Fail()
	}
}

func Test_HTTPClient_Post_retriesOnConnectionError(t *testing.T) {
	server := connectionClosingServer(t)
	defer server.close()

	client := NewHTTPClient(MaxRetries(1))
	request := testEntity{Field: "send"}

	err := client.Post(server.url, &request)

	require.Error(t, err)
	assert.Equal(t, 2, server.calls)
}

func Test_HTTPClient_PostForLocation(t *testing.T) {
	handler, verify := testMockServer([]mockServerResponse{{
		statusCode: http.StatusCreated,
		body:       `{ "Field": "test"}`,
		header:     map[string]string{"Location": "/location"},
	}})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	request := testEntity{Field: "send"}

	location, err := client.PostForLocation(server.URL+"/", &request)

	assert.NoError(t, err)
	assert.Equal(t, "/location", location)
	assert.Equal(t, 1, verify.calls)
	assert.Equal(t, http.MethodPost, verify.method)
	assert.Equal(t, "application/json", verify.contentType)
	assert.JSONEq(t, `{ "Field": "send"}`, verify.body)
}

func Test_HTTPClient_PostForLocationAndBody(t *testing.T) {
	handler, verify := testMockServer([]mockServerResponse{{
		statusCode: http.StatusCreated,
		body:       `{ "Field": "test"}`,
		header:     map[string]string{"Location": "/location"},
	}})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	request := testEntity{Field: "send"}
	var response testEntity

	location, err := client.PostForLocationAndBody(server.URL+"/", &request, &response)

	assert.NoError(t, err)
	assert.Equal(t, "/location", location)
	assert.Equal(t, testEntity{Field: "test"}, response)
	assert.Equal(t, 1, verify.calls)
	assert.Equal(t, http.MethodPost, verify.method)
	assert.Equal(t, "application/json", verify.contentType)
	assert.JSONEq(t, `{ "Field": "send"}`, verify.body)
}

func Test_HTTPClient_Put(t *testing.T) {
	handler, verify := testMockServer(mockResponses(http.StatusCreated, `{ "Field": "test"}`))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	request := testEntity{Field: "send"}

	err := client.Put(server.URL+"/", &request)

	assert.NoError(t, err)
	assert.Equal(t, 1, verify.calls)
	assert.Equal(t, http.MethodPut, verify.method)
	assert.Equal(t, "application/json", verify.contentType)
	assert.JSONEq(t, `{ "Field": "send"}`, verify.body)
}

func Test_HTTPClient_Put_clientError(t *testing.T) {
	handler, verify := testMockServer(mockResponses(http.StatusBadRequest, ``))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	entity := testEntity{}

	err := client.Put(server.URL+"/", &entity)

	assert.Error(t, err)
	assert.Equal(t, 1, verify.calls)
	if clientError, ok := err.(HTTPClientError); ok {
		assert.Equal(t, http.StatusBadRequest, clientError.Code)
	} else {
		t.Error("Not an HTTPClientError:", err)
	}
}

func Test_HTTPClient_Put_retriesOnConnectionError(t *testing.T) {
	server := connectionClosingServer(t)
	defer server.close()

	client := NewHTTPClient(MaxRetries(1))
	request := testEntity{Field: "send"}

	err := client.Put(server.url, &request)

	require.Error(t, err)
	assert.Equal(t, 2, server.calls)
}

func Test_HTTPClient_PutForBody(t *testing.T) {
	handler, verify := testMockServer(mockResponses(http.StatusCreated, `{ "Field": "test"}`))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	request := testEntity{Field: "send"}
	response := testEntity{}

	err := client.PutForBody(server.URL+"/", &request, &response)

	assert.NoError(t, err)
	assert.Equal(t, 1, verify.calls)
	assert.Equal(t, http.MethodPut, verify.method)
	assert.Equal(t, "application/json", verify.contentType)
	assert.JSONEq(t, `{ "Field": "send"}`, verify.body)
	assert.Equal(t, testEntity{Field: "test"}, response)
}

func Test_HTTPClient_Patch(t *testing.T) {
	handler, verify := testMockServer(mockResponses(http.StatusOK, `{ "Field": "test"}`))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	request := testEntity{Field: "send"}

	err := client.Patch(server.URL+"/", &request)

	assert.NoError(t, err)
	assert.Equal(t, 1, verify.calls)
	assert.Equal(t, http.MethodPatch, verify.method)
	assert.Equal(t, "application/json", verify.contentType)
	assert.JSONEq(t, `{ "Field": "send"}`, verify.body)
}

func Test_HTTPClient_Patch_clientError(t *testing.T) {
	handler, verify := testMockServer(mockResponses(http.StatusBadRequest, ``))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	entity := testEntity{}

	err := client.Patch(server.URL+"/", &entity)

	assert.Error(t, err)
	assert.Equal(t, 1, verify.calls)
	if clientError, ok := err.(HTTPClientError); ok {
		assert.Equal(t, http.StatusBadRequest, clientError.Code)
	} else {
		t.Error("Not an HTTPClientError:", err)
	}
}

func Test_HTTPClient_Patch_retriesOnConnectionError(t *testing.T) {
	server := connectionClosingServer(t)
	defer server.close()

	client := NewHTTPClient(MaxRetries(1))
	request := testEntity{Field: "send"}

	err := client.Patch(server.url, &request)

	require.Error(t, err)
	assert.Equal(t, 2, server.calls)
}

func Test_HTTPClient_PatchForBody(t *testing.T) {
	handler, verify := testMockServer(mockResponses(http.StatusCreated, `{ "Field": "test"}`))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	request := testEntity{Field: "send"}
	response := testEntity{}

	err := client.PatchForBody(server.URL+"/", &request, &response)

	assert.NoError(t, err)
	assert.Equal(t, 1, verify.calls)
	assert.Equal(t, http.MethodPatch, verify.method)
	assert.Equal(t, "application/json", verify.contentType)
	assert.JSONEq(t, `{ "Field": "send"}`, verify.body)
	assert.Equal(t, testEntity{Field: "test"}, response)
}

func Test_HTTPClient_PatchForBody_retriesOnConnectionError(t *testing.T) {
	server := connectionClosingServer(t)
	defer server.close()

	client := NewHTTPClient(MaxRetries(1))
	request := testEntity{Field: "send"}
	response := testEntity{}

	err := client.PatchForBody(server.url, &request, &response)

	require.Error(t, err)
	assert.Equal(t, 2, server.calls)
}

func Test_HTPClient_PatchForBody_HTTPErrorCases(t *testing.T) {
	for _, test := range []struct {
		Name           string
		StatusCode     int
		Body           string
		ExpectedEntity testEntity
	}{
		{
			Name:       "client error no body",
			StatusCode: http.StatusBadRequest,
		},
		{
			Name:       "client error with invalid body",
			StatusCode: http.StatusBadRequest,
			Body:       "invalid json",
		},
		{
			Name:       "client error with body",
			StatusCode: http.StatusBadRequest,
			Body:       `{"Field": "error" }`,
			ExpectedEntity: testEntity{
				Field: "error",
			},
		},
		{
			Name:       "server error no body",
			StatusCode: http.StatusInternalServerError,
		},
		{
			Name:       "server error with invalid body",
			StatusCode: http.StatusInternalServerError,
			Body:       "invalid json",
		},
		{
			Name:       "server error with body",
			StatusCode: http.StatusInternalServerError,
			Body:       `{"Field": "error" }`,
			ExpectedEntity: testEntity{
				Field: "error",
			},
		},
	} {
		t.Run(test.Name, func(t *testing.T) {
			handler, verify := testMockServer(mockResponses(test.StatusCode, test.Body))
			server := httptest.NewServer(handler)
			defer server.Close()

			client := NewHTTPClient()
			entity := testEntity{}

			err := client.PatchForBody(server.URL+"/", &entity, &entity)

			assert.Error(t, err)
			assert.Equal(t, 1, verify.calls)
			if clientError, ok := err.(HTTPClientError); ok {
				assert.Equal(t, test.StatusCode, clientError.Code)
			} else {
				t.Error("Not an HTTPClientError:", err)
			}
			assert.Equal(t, test.ExpectedEntity, entity)
		})
	}
}

func Test_HTTPClient_Delete(t *testing.T) {
	for _, test := range []struct {
		name      string
		responses []mockServerResponse
	}{
		{
			name:      "success",
			responses: mockResponses(http.StatusOK, `{"message": "deleted"}`),
		},
		{
			name:      "no content",
			responses: mockResponses(http.StatusNoContent, ``),
		},
		{
			name:      "accepted",
			responses: mockResponses(http.StatusAccepted, `{"willDelete": "later"}`),
		},
		{
			name: "success after retry",
			responses: []mockServerResponse{
				mockResponse(http.StatusInternalServerError, `{"error": "occurred"}`),
				mockResponse(http.StatusOK, `{"message": "deleted"}`),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, verify := testMockServer(test.responses)
			server := httptest.NewServer(handler)
			defer server.Close()

			client := NewHTTPClient(MaxRetries(3))

			err := client.Delete(server.URL + "/")

			require.NoError(t, err)
			assert.Equal(t, http.MethodDelete, verify.method)
		})
	}
}

type testEntity struct {
	Field string
}

func mockResponses(statusCode int, body string) []mockServerResponse {
	return []mockServerResponse{mockResponse(statusCode, body)}
}

func mockResponse(statusCode int, body string) mockServerResponse {
	return mockServerResponse{
		statusCode: statusCode,
		body:       body,
	}
}

type mockServerResponse struct {
	statusCode int
	body       string
	header     map[string]string
}

type verifications struct {
	calls         int
	method        string
	token         string
	accept        string
	contentType   string
	userAgent     string
	body          string
	authorization string
}

func testMockServer(responses []mockServerResponse) (http.Handler, *verifications) {
	v := &verifications{}
	mux := http.NewServeMux()
	i := 0

	mux.HandleFunc(
		"/",
		func(w http.ResponseWriter, r *http.Request) {
			v.method = r.Method
			v.token = r.Header.Get("Client-Token")
			v.accept = r.Header.Get("Accept")
			v.contentType = r.Header.Get("Content-Type")
			v.userAgent = r.Header.Get("User-Agent")
			v.authorization = r.Header.Get("Authorization")
			body, _ := ioutil.ReadAll(r.Body)
			v.body = string(body)
			v.calls++

			current := min(i, len(responses)-1)
			response := responses[current]
			i++

			for name, value := range response.header {
				w.Header().Set(name, value)
			}

			w.WriteHeader(response.statusCode)
			w.Write([]byte(response.body))
		})

	return mux, v
}

func min(i, j int) int {
	if i < j {
		return i
	}
	return j
}

func mockDecode(t *testing.T) Decoder {
	return func(data []byte, entity interface{}) error {
		assert.Equal(t, "not json", string(data))
		testEntity, ok := entity.(*testEntity)
		require.True(t, ok)
		testEntity.Field = "aField"
		return nil
	}
}

func mockEncode(t *testing.T) Encoder {
	return func(entity interface{}) ([]byte, error) {
		testEntity, ok := entity.(*testEntity)
		require.True(t, ok)

		return []byte(testEntity.Field), nil
	}
}

func readKeyPair(t *testing.T, name string) tls.Certificate {
	cert, err := tls.LoadX509KeyPair("test-certs/"+name+".pem", "test-certs/"+name+".key")
	require.NoError(t, err)
	return cert
}

func readCertPool(t *testing.T) *x509.CertPool {
	certpool := x509.NewCertPool()
	pem, err := ioutil.ReadFile("test-certs/ca.pem")
	require.NoError(t, err)
	require.True(t, certpool.AppendCertsFromPEM(pem))
	return certpool
}

type testServer struct {
	listener net.Listener
	url      string
	calls    int
}

func connectionClosingServer(t *testing.T) *testServer {
	ln, err := net.Listen("tcp", "[::]:0")
	require.NoError(t, err)

	server := &testServer{
		listener: ln,
		url:      "http://" + ln.Addr().String(),
		calls:    0,
	}

	server.do()

	return server
}

func (server *testServer) do() {
	go func() {
		for {
			conn, err := server.listener.Accept()
			if err != nil {
				return
			}

			server.calls++

			time.Sleep(10 * time.Millisecond)

			conn.Close()
		}
	}()
}

func (server *testServer) close() {
	server.listener.Close()
}
