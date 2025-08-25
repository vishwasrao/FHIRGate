package main

import (
	"encoding/json" // New import
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kong/go-pdk/test"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwa" // New import
	"github.com/lestrrat-go/jwx/jwk" // New import
	"github.com/stretchr/testify/assert"
)



func TestAccess_MissingAuthHeader(t *testing.T) {
	env, err := test.New(t, test.Request{
		Method: "GET",
		Url:    "http://example.com",
	})
	if err != nil {
		t.Fatalf("could not create test environment: %v", err)
	}

	config := &Config{}
	env.DoHttps(config)

	assert.Equal(t, 401, env.ClientRes.Status)

	assert.Equal(t, "Missing or invalid Authorization header", string(env.ClientRes.Body))
}

func TestAccess_InvalidJWT(t *testing.T) {
	env, err := test.New(t, test.Request{
		Method:  "GET",
		Url:     "http://example.com",
		Headers: map[string][]string{"Authorization": {"Bearer invalid-jwt"}},
	})
	if err != nil {
		t.Fatalf("could not create test environment: %v", err)
	}

	config := &Config{}
	env.DoHttps(config)

	assert.Equal(t, 401, env.ClientRes.Status)
	assert.Equal(t, "Invalid JWT", string(env.ClientRes.Body))
}

func TestAccess_SuccessfulValidation(t *testing.T) {
	// Define a key and its KID
	const testKey = "test-secret-key"
	const testKid = "test-kid"

	// Create a mock JWKS server that returns a JWKS with the test key
	mockJwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Create a JWK from the testKey
		key, err := jwk.New([]byte(testKey))
		assert.NoError(t, err)
		key.Set(jwk.AlgorithmKey, jwa.HS256) // Set the algorithm
		assert.NoError(t, err)
		key.Set(jwk.KeyIDKey, testKid) // Set the KID
		set := jwk.NewSet()
		set.Add(key)
		jsonBytes, err := json.Marshal(set)
		assert.NoError(t, err)
		w.Write(jsonBytes)
	}))
	defer mockJwksServer.Close()

	// Create a mock registry service
	mockRegistry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"clientId": "test-client", "jwks_url": "` + mockJwksServer.URL + `"}`))
	}))
	defer mockRegistry.Close()

	// Create a JWT token with the KID in the header
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "test-issuer",
		"jku": "test-jku",
	})
	token.Header["kid"] = testKid // Set the KID in the header
	signedToken, err := token.SignedString([]byte(testKey)) // Sign with the actual key
	assert.NoError(t, err)

	env, err := test.New(t, test.Request{
		Method:  "GET",
		Url:     "http://example.com",
		Headers: map[string][]string{"Authorization": {"Bearer " + signedToken}},
	})
	if err != nil {
		t.Fatalf("could not create test environment: %v", err)
	}

	config := &Config{}
	registryURL = mockRegistry.URL // Set global variable
	env.DoHttps(config)

	assert.Equal(t, 200, env.ClientRes.Status)
}

func TestAccess_RegistryServiceError(t *testing.T) {
	// Create a mock registry service that immediately closes the connection
	mockRegistry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a network error by not writing anything and closing the connection
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("webserver doesn't support hijacking")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}))
	// Do not defer mockRegistry.Close() here, as we want it to close immediately

	// Create a JWT token (content doesn't matter for this test)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "test-issuer",
		"jku": "test-jku",
	})
	signedToken, err := token.SignedString([]byte("dummy-key"))
	assert.NoError(t, err)

	env, err := test.New(t, test.Request{
		Method:  "GET",
		Url:     "http://example.com",
		Headers: map[string][]string{"Authorization": {"Bearer " + signedToken}},
	})
	if err != nil {
		t.Fatalf("could not create test environment: %v", err)
	}

	config := &Config{}
	registryURL = mockRegistry.URL // Set global variable
	env.DoHttps(config)

	assert.Equal(t, 500, env.ClientRes.Status)
	assert.Equal(t, "Registry service error", string(env.ClientRes.Body))

	mockRegistry.Close() // Close the server after the test
}