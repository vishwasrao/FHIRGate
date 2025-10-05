package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
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
//
//	kong: The Kong PDK instance, providing access to Kong's API.
//
// Access is the main handler for the FHIRGate plugin.
// It intercepts incoming requests and performs JWT validation based on CDS Hooks specifications.
//
// Parameters:
//
//	kong: The Kong PDK instance, providing access to Kong's API.
func (conf *Config) Access(kong *pdk.PDK) {
	kong.Log.Info("[FHIRGate-plugin] Access handler called")
	kong.Log.Info("[FHIRGate-plugin] Registry URL: " + registryURL)
	// Extract JWT from Authorization header
	header, err := kong.Request.GetHeader("Authorization")
	if err != nil || !strings.HasPrefix(header, "Bearer ") {
		kong.Log.Err("[FHIRGate-plugin] Missing or invalid Authorization header")
		kong.Response.Exit(401, []byte("Unauthorized"), nil)
		return
	}
	jwtToken := strings.TrimPrefix(header, "Bearer ")
	kong.Log.Info("[FHIRGate-plugin] JWT extracted from header")

	// Parse JWT (without verifying) to get claims and header
	token, _, err := new(jwt.Parser).ParseUnverified(jwtToken, jwt.MapClaims{})
	if err != nil {
		kong.Log.Err("[FHIRGate-plugin] Failed to parse JWT: " + err.Error())
		kong.Response.Exit(401, []byte("Unauthorized"), nil)
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		kong.Log.Err("[FHIRGate-plugin] JWT claims not found")
		kong.Response.Exit(401, []byte("Unauthorized"), nil)
		return
	}
	issuer, _ := claims["iss"].(string)
	// Extract 'jku' from JWT header (not payload)
	jku, _ := token.Header["jku"].(string)
	if jku == "" {
		kong.Log.Err("[FHIRGate-plugin] Missing 'jku' header in JWT")
		kong.Response.Exit(401, []byte("Unauthorized"), nil)
		return
	}
	if issuer == "" {
		kong.Log.Err("[FHIRGate-plugin] Missing 'iss' claim in JWT")
		kong.Response.Exit(401, []byte("Unauthorized"), nil)
		return
	}
	kong.Log.Info("[FHIRGate-plugin] Extracted iss: " + issuer + ", jku(header): " + jku)

	// CDS Hooks Recommendation: Ensure that the iss value exists in the CDS Service's allowlist of trusted CDS Clients.
	// This requires a configuration mechanism for the allowlist.
	// TODO: Implement CDS Client allowlist check.

	// CDS Hooks Recommendation: Ensure that the aud value matches the CDS Service endpoint currently processing the request.
	// This requires getting the 'aud' claim from the JWT and comparing it with the current endpoint.
	// TODO: Implement 'aud' claim validation.

	// CDS Hooks Recommendation: Ensure that the tenant value exists in the CDS Service's allowlist of trusted tenants.
	// This requires checking for a 'tenant' claim and a trusted tenant allowlist.
	// TODO: Implement 'tenant' claim validation.

	// CDS Hooks Recommendation: Ensure that the jti value doesn't exist in the short-term storage of JWTs previously processed by this CDS Service.
	// This requires a storage mechanism (e.g., a cache or database) to prevent replay attacks.
	// TODO: Implement 'jti' replay attack prevention.

	// Call registry-service (use /registry endpoint)
	regURL := registryURL + "/registry?iss=" + issuer + "&jku=" + jku
	kong.Log.Info("[FHIRGate-plugin] Calling registry-service URL: " + regURL)
	resp, err := http.Get(regURL)
	if err != nil {
		kong.Log.Err("[FHIRGate-plugin] Error calling registry-service: " + err.Error())
		kong.Response.Exit(500, []byte("Internal server error"), nil)
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
		JKU      string `json:"jku"`
	}
	json.Unmarshal(body, &regResp)
	kong.Log.Info("[FHIRGate-plugin] Got registry-service response: clientId=" + regResp.ClientID + ", jku=" + regResp.JKU)

	// Validate JWT signature using JWKS
	// CDS Hooks Recommendation: CDS Services should maintain their own rotating cache of public keys for the CDS Client.
	// TODO: Implement JWKS caching.
	keySet, err := getJWKS(regResp.JKU)
	if err != nil {
		kong.Log.Err("[FHIRGate-plugin] Failed to fetch JWKS: " + err.Error())
		kong.Response.Exit(401, []byte("Unauthorized"), nil)
		return
	}

	_, err = jwxjwt.Parse([]byte(jwtToken), jwxjwt.WithKeySet(keySet), jwxjwt.WithValidate(true))
	if err != nil {
		kong.Log.Err("[FHIRGate-plugin] JWT validation failed: " + err.Error())
		kong.Response.Exit(401, []byte("Unauthorized"), nil)
		return
	}

	// CDS Hooks Recommendation: Once the JWT has been deemed to be valid, the jti value should be stored in the short-term storage of processed JWTs.
	// TODO: Store 'jti' in short-term storage.

	kong.Log.Info("[FHIRGate-plugin] JWT validated successfully. Allowing request.")

	// FHIR Access: CDS Services should never store, share, or log the FHIR access token (fhirAuthorization.access_token).
	// TODO: Consider handling fhirAuthorization.access_token if applicable in future.
}

// getJWKS fetches the JSON Web Key Set (JWKS) from the provided URL.
//
// Parameters:
//
//	url: The URL of the JWKS endpoint.
//
// Returns:
//
//	jwk.Set: The fetched JWKS.
//	error: An error if fetching or parsing the JWKS fails.
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
	flag.StringVar(&rURL, "registry-url", os.Getenv("DEFAULT_REGISTRY_URL"), "URL of the registry service")
	flag.Parse()
	registryURL = rURL // Assign to global variable

	log.Println("[FHIRGate-plugin] Starting Go plugin server...")
	server.StartServer(New, Version, Priority)
}
