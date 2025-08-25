
package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/server"
	"github.com/golang-jwt/jwt/v5"
)

var Version = "0.2"
var Priority = 1

type Config struct{}

func New() interface{} {
	return &Config{}
}

func (conf *Config) Access(kong *pdk.PDK) {
	kong.Log.Info("[FHIRGate-plugin] Access handler called")
	// Extract JWT from Authorization header
	header, err := kong.Request.GetHeader("Authorization")
	if err != nil || !strings.HasPrefix(header, "Bearer ") {
		kong.Log.Err("[FHIRGate-plugin] Missing or invalid Authorization header")
		kong.Response.Exit(401, []byte("Missing or invalid Authorization header"), nil)
		return
	}
	jwtToken := strings.TrimPrefix(header, "Bearer ")
	kong.Log.Info("[FHIRGate-plugin] JWT extracted from header")

	// Parse JWT (without verifying)
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
	regURL := "http://registry-service:8081/lookup?iss=" + issuer + "&jku=" + jku
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
	_, err = jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		return keySet, nil // For demo, just return the keySet (mocked)
	})
	if err != nil {
		kong.Log.Err("[FHIRGate-plugin] JWT validation failed: " + err.Error())
		kong.Response.Exit(401, []byte("JWT validation failed"), nil)
		return
	}
	kong.Log.Info("[FHIRGate-plugin] JWT validated successfully. Allowing request.")
}

func getJWKS(url string) (interface{}, error) {
	// For demo, return a dummy key. In real use, fetch and parse JWKS.
	return []byte("dummy-key"), nil
}

func main() {
	log.Println("[FHIRGate-plugin] Starting Go plugin server...")
	server.StartServer(New, Version, Priority)
}
