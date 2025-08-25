
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/server"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
	jwxjwt "github.com/lestrrat-go/jwx/jwt"
)

var Version = "0.2"
var Priority = 1

var registryURL string

type Config struct{}

// New creates a new Config instance for the FHIRGate plugin.
// It is called by the Kong plugin server to initialize the plugin.
func New() interface{} {
	return &Config{}
}

// Access is the main handler for the FHIRGate plugin.
// It intercepts incoming requests and performs JWT validation.
//
// Parameters:
//   kong: The Kong PDK instance, providing access to Kong's API.
func (conf *Config) Access(kong *pdk.PDK) {
	kong.Log.Info("[FHIRGate-plugin] Access handler called")
	kong.Log.Info("[FHIRGate-plugin] Registry URL: " + registryURL)
	// Extract JWT from Authorization header
	header, err := kong.Request.GetHeader("Authorization")
	if err != nil || !strings.HasPrefix(header, "Bearer ") {
		kong.Log.Err("[FHIRGate-plugin] Missing or invalid Authorization header")
		kong.Response.Exit(401, []byte("Missing or invalid Authorization header"), nil)
		return
	}
	jwtToken := strings.TrimPrefix(header, "Bearer ")
	kong.Log.Info("[FHIRGate-plugin] JWT extracted from header")

	// Parse JWT (without verifying) to get claims and header
	token, _, err := new(jwt.Parser).ParseUnverified(jwtToken, jwt.MapClaims{})
	if err != nil {
		kong.Log.Err("[FHIRGate-plugin] Failed to parse JWT: " + err.Error())
		kong.Response.Exit(401, []byte("Invalid JWT"), nil)
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		kong.Log.Err("[FHIRGate-plugin] JWT claims not found")
		kong.Response.Exit(401, []byte("Invalid JWT claims"), nil)
		return
	}
	issuer, _ := claims["iss"].(string)
	jku, _ := claims["jku"].(string)
	kong.Log.Info("[FHIRGate-plugin] Extracted iss: " + issuer + ", jku: " + jku)

	// Call registry-service
	regURL := registryURL + "/get?iss=" + issuer + "&jku=" + jku
	resp, err := http.Get(regURL)
	if err != nil {
		kong.Log.Err("[FHIRGate-plugin] Error calling registry-service: " + err.Error())
		kong.Response.Exit(500, []byte("Registry service error"), nil)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		kong.Log.Err("[FHIRGate-plugin] Registry-service returned status: " + resp.Status)
		kong.Response.Exit(401, []byte("Unauthorized"), nil)
		return
	}
	body, _ := ioutil.ReadAll(resp.Body)
	var regResp struct {
		ClientID string `json:"clientId"`
		JWKSURL string `json:"jwks_url"`
	}
	json.Unmarshal(body, &regResp)
	kong.Log.Info("[FHIRGate-plugin] Got registry-service response: clientId=" + regResp.ClientID + ", jwks_url=" + regResp.JWKSURL)

	// Validate JWT signature using JWKS
	keySet, err := getJWKS(regResp.JWKSURL)
	if err != nil {
		kong.Log.Err("[FHIRGate-plugin] Failed to fetch JWKS: " + err.Error())
		kong.Response.Exit(401, []byte("JWKS fetch error"), nil)
		return
	}
	
	_, err = jwxjwt.Parse([]byte(jwtToken), jwxjwt.WithKeySet(keySet))
	if err != nil {
		kong.Log.Err("[FHIRGate-plugin] JWT validation failed: " + err.Error())
		kong.Response.Exit(401, []byte("JWT validation failed"), nil)
		return
	}

	kong.Log.Info("[FHIRGate-plugin] JWT validated successfully. Allowing request.")
}

// getJWKS fetches the JSON Web Key Set (JWKS) from the provided URL.
//
// Parameters:
//   url: The URL of the JWKS endpoint.
//
// Returns:
//   jwk.Set: The fetched JWKS.
//   error: An error if fetching or parsing the JWKS fails.
func getJWKS(url string) (jwk.Set, error) {
	set, err := jwk.Fetch(context.Background(), url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", url, err)
	}
	return set, nil
}

// main is the entry point for the FHIRGate Go plugin server.
// It parses command-line arguments and starts the Kong plugin server.
func main() {
	var rURL string
	flag.StringVar(&rURL, "registry-url", "http://registry-service:8081", "URL of the registry service")
	flag.Parse()
	registryURL = rURL // Assign to global variable

	log.Println("[FHIRGate-plugin] Starting Go plugin server...")
	server.StartServer(New, Version, Priority)
}
