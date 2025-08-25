package main

import (
	"testing"
	"github.com/stretchr/testify/mock"
)

type MockPDK struct {
	mock.Mock
	Request  *MockRequest
	Response *MockResponse
	Log      *MockLog
}

type MockRequest struct{ mock.Mock }
func (m *MockRequest) GetHeader(key string) (string, error) {
	args := m.Called(key)
	return args.String(0), args.Error(1)
}

type MockResponse struct{ mock.Mock }
func (m *MockResponse) Exit(code int, body string, headers map[string][]string) {
	m.Called(code, body, headers)
}

type MockLog struct{ mock.Mock }
func (m *MockLog) Info(msg string) { m.Called(msg) }
func (m *MockLog) Err(msg string)  { m.Called(msg) }

func TestAccess_MissingAuthHeader(t *testing.T) {
	pdk := &MockPDK{
		Request:  &MockRequest{},
		Response: &MockResponse{},
		Log:      &MockLog{},
	}
	pdk.Request.On("GetHeader", "Authorization").Return("", nil)
	pdk.Response.On("Exit", 401, "Missing or invalid Authorization header", nil).Return()
	pdk.Log.On("Err", mock.Anything).Return()
	conf := &Config{}
	conf.Access(pdk)
	pdk.Response.AssertCalled(t, "Exit", 401, "Missing or invalid Authorization header", nil)
}
