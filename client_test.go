package httputils

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_HTTPClient_Get(t *testing.T) {
	for _, test := range []struct {
		name      string
		responses []mockResponse
		expected  testEntity
	}{
		{
			name: "success",
			responses: []mockResponse{
				{http.StatusOK, `{ "Field": "test"}`},
			},
			expected: testEntity{Field: "test"},
		},
		{
			name: "success after retry",
			responses: []mockResponse{
				{http.StatusInternalServerError, ``},
				{http.StatusOK, `{ "Field": "test"}`},
			},
			expected: testEntity{Field: "test"},
		},
		{
			name: "retries if response was corrupted",
			responses: []mockResponse{
				{http.StatusOK, `}{`},
				{http.StatusOK, `{ "Field": "test"}`},
			},
			expected: testEntity{Field: "test"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, _ := testMockServer(test.responses)
			server := httptest.NewServer(handler)
			defer server.Close()

			client := NewHTTPClient(MaxRetries(3))
			entity := testEntity{}

			err := client.Get(server.URL+"/", &entity)

			require.NoError(t, err)
			assert.Equal(t, test.expected, entity)
		})
	}
}

func Test_HTTPClient_Get_DoesNotRetry(t *testing.T) {
	handler, verify := testMockServer([]mockResponse{{http.StatusInternalServerError, `{ "Field": "test"}`}})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient(NoRetries())
	entity := testEntity{}

	err := client.Get(server.URL+"/", &entity)

	require.Error(t, err)
	assert.Equal(t, 1, verify.calls)
}

func Test_HTTPClient_Get_UserAgent(t *testing.T) {
	handler, verify := testMockServer([]mockResponse{{http.StatusOK, `{ "Field": "test"}`}})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	entity := testEntity{}

	err := client.Get(server.URL+"/", &entity, UserAgent("user-agent"))

	require.NoError(t, err)
	assert.Equal(t, "user-agent", verify.userAgent)
}

func Test_HTTPClient_Get_AcceptHeader(t *testing.T) {
	handler, verify := testMockServer([]mockResponse{{http.StatusOK, `{ "Field": "test"}`}})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	entity := testEntity{}

	err := client.Get(server.URL+"/", &entity, Accept("application/something+json"))

	require.NoError(t, err)
	assert.Equal(t, "application/something+json", verify.accept)
}

func Test_HTTPClient_Get_ClientTokenHeader(t *testing.T) {
	handler, verify := testMockServer([]mockResponse{{http.StatusOK, `{ "Field": "test"}`}})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	entity := testEntity{}

	err := client.Get(server.URL+"/", &entity, ClientToken("token"))

	require.NoError(t, err)
	assert.Equal(t, "token", verify.token)
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
			handler, verify := testMockServer([]mockResponse{{test.StatusCode, test.Body}})
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
	handler, verify := testMockServer([]mockResponse{{http.StatusOK, `{}`}})
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

func Test_HTTPClient_PostForBody(t *testing.T) {
	handler, verify := testMockServer([]mockResponse{{http.StatusCreated, `{ "Field": "test"}`}})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	request := testEntity{Field: "send"}
	response := testEntity{}

	err := client.PostForBody(server.URL+"/", &request, &response)

	assert.NoError(t, err)
	assert.Equal(t, 1, verify.calls)
	assert.Equal(t, "application/json", verify.contentType)
	assert.JSONEq(t, `{ "Field": "send"}`, verify.body)
	assert.Equal(t, testEntity{Field: "test"}, response)
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
			handler, verify := testMockServer([]mockResponse{{test.StatusCode, test.Body}})
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
	handler, verify := testMockServer([]mockResponse{{http.StatusCreated, `{ "Field": "test"}`}})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	request := testEntity{Field: "send"}

	err := client.Post(server.URL+"/", &request)

	assert.NoError(t, err)
	assert.Equal(t, 1, verify.calls)
	assert.Equal(t, "application/json", verify.contentType)
	assert.JSONEq(t, `{ "Field": "send"}`, verify.body)
}

func Test_HTTPClient_Post_clientError(t *testing.T) {
	handler, verify := testMockServer([]mockResponse{{http.StatusBadRequest, ``}})
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
	handler, verify := testMockServer([]mockResponse{{http.StatusInternalServerError, ``}})
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

func Test_HTTPClient_Put(t *testing.T) {
	handler, verify := testMockServer([]mockResponse{{http.StatusCreated, `{ "Field": "test"}`}})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	request := testEntity{Field: "send"}

	err := client.Put(server.URL+"/", &request)

	assert.NoError(t, err)
	assert.Equal(t, 1, verify.calls)
	assert.Equal(t, "application/json", verify.contentType)
	assert.JSONEq(t, `{ "Field": "send"}`, verify.body)
}

func Test_HTTPClient_Put_clientError(t *testing.T) {
	handler, verify := testMockServer([]mockResponse{{http.StatusBadRequest, ``}})
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

func Test_HTTPClient_Patch(t *testing.T) {
	handler, verify := testMockServer([]mockResponse{{http.StatusOK, `{ "Field": "test"}`}})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	request := testEntity{Field: "send"}

	err := client.Patch(server.URL+"/", &request)

	assert.NoError(t, err)
	assert.Equal(t, 1, verify.calls)
	assert.Equal(t, "application/json", verify.contentType)
	assert.JSONEq(t, `{ "Field": "send"}`, verify.body)
}

func Test_HTTPClient_Patch_clientError(t *testing.T) {
	handler, verify := testMockServer([]mockResponse{{http.StatusBadRequest, ``}})
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

func Test_HTTPClient_PatchForBody(t *testing.T) {
	handler, verify := testMockServer([]mockResponse{{http.StatusCreated, `{ "Field": "test"}`}})
	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewHTTPClient()
	request := testEntity{Field: "send"}
	response := testEntity{}

	err := client.PatchForBody(server.URL+"/", &request, &response)

	assert.NoError(t, err)
	assert.Equal(t, 1, verify.calls)
	assert.Equal(t, "application/json", verify.contentType)
	assert.JSONEq(t, `{ "Field": "send"}`, verify.body)
	assert.Equal(t, testEntity{Field: "test"}, response)
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
			handler, verify := testMockServer([]mockResponse{{test.StatusCode, test.Body}})
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

type testEntity struct {
	Field string
}

type mockResponse struct {
	statusCode int
	body       string
}

type verifications struct {
	calls       int
	token       string
	accept      string
	contentType string
	userAgent   string
	body        string
}

func testMockServer(responses []mockResponse) (http.Handler, *verifications) {
	v := &verifications{}
	mux := http.NewServeMux()
	i := 0

	mux.HandleFunc(
		"/",
		func(w http.ResponseWriter, r *http.Request) {
			v.token = r.Header.Get("Client-Token")
			v.accept = r.Header.Get("Accept")
			v.contentType = r.Header.Get("Content-Type")
			v.userAgent = r.Header.Get("User-Agent")
			body, _ := ioutil.ReadAll(r.Body)
			v.body = string(body)
			v.calls++

			current := min(i, len(responses)-1)
			response := responses[current]
			i++

			w.Header().Set("Cache-Control", "max-age=3600")
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
