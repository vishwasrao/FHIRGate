# FHIRGate

FHIRGate is a Kong API Gateway plugin for authorizing access to FHIR services using JWTs. It integrates with a registry service to dynamically fetch validation keys (JWKS) and secure FHIR endpoints.

## Overview

This plugin intercepts incoming requests to your FHIR server and performs the following steps:

1.  **Extracts JWT:** It retrieves the JSON Web Token (JWT) from the `Authorization: Bearer` header.
2.  **Parses Claims:** It parses the JWT to extract the issuer (`iss`) and JWKS URL (`jku`) claims.
3.  **Registry Lookup:** It queries a configured registry service to look up the client details and the JWKS URL based on the `iss` and `jku`.
4.  **JWT Validation:** It fetches the JSON Web Key Set (JWKS) from the resolved URL and validates the JWT's signature.
5.  **Proxy or Reject:** If the JWT is valid, the request is proxied to the upstream FHIR service. Otherwise, it's rejected with an appropriate error.

## Features

*   JWT-based authorization for FHIR services
*   Dynamic JWKS URL resolution via a registry service
*   Seamless integration with Kong Gateway
*   Written in Go

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

*   [Go](https://golang.org/doc/install) (version 1.18 or later)
*   [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)

### Building the Plugin

The plugin is built as part of the Docker image. You don't need to build it separately.

### Running with Docker

The easiest way to run FHIRGate is with Docker Compose, which can spin up Kong and the plugin together.

1.  **Create a `docker-compose.yaml` file:**

    ```yaml
    version: '3.8'

    services:
      mock-upstream:
        image: kennethreitz/httpbin
        container_name: mock-upstream

      kong:
        build:
          context: .
          dockerfile: Dockerfile # Build the image with the plugin embedded
        container_name: kong
        environment:
          KONG_DATABASE: "off" # Run Kong in DB-less mode
          KONG_DECLARATIVE_CONFIG: "/kong.yaml" # Point to the kong.yaml copied in Dockerfile
          KONG_PROXY_ACCESS_LOG: /dev/stdout
          KONG_ADMIN_ACCESS_LOG: /dev/stdout
          KONG_PROXY_ERROR_LOG: /dev/stderr
          KONG_ADMIN_ERROR_LOG: /dev/stderr
          KONG_ADMIN_LISTEN: 0.0.0.0:8001, 0.0.0.0:8444 ssl
          KONG_PROXY_LISTEN: 0.0.0.0:8000, 0.0.0.0:8443 ssl
          KONG_LICENSE_DATA: "" # Replace with your Kong license data if needed
          REGISTRY_URL: http://mock-upstream # Pass registry URL to the plugin
        ports:
          - "8000:8000" # Proxy HTTP
          - "8443:8443" # Proxy HTTPS
          - "8002:8001" # Admin HTTP (changed from 8001 to 8002 to avoid conflict)
          - "8444:8444" # Admin HTTPS
        depends_on:
          - mock-upstream # Depend on your mock upstream service
    ```

2.  **Start the services:**

    ```sh
    docker compose up -d --build --force-recreate
    ```

    This will build the Kong image with the FHIRGate plugin embedded and start Kong with the plugin enabled, along with a mock upstream service.

### Cleanup

To stop and remove the Docker Compose services, run:

```sh
docker compose down
```

## Testing

To run the tests for the plugin, use the following command:

```sh
go test ./...
```

## Configuration

The plugin is configured in your `kong.yaml` file. Here's an example:

```yaml
_format_version: "3.0"
services:
- name: cds-hooks-service
  url: http://mock-upstream/
  routes:
  - name: cds-hooks-route
    paths:
    - /cds-hooks
plugins:
- name: fhirgate-plugin
```

This configuration applies the `fhirgate-plugin` to the `cds-hooks-service`.

## Example Usage

To test the plugin, you can send a request to the configured route with a valid JWT.

1.  **Generate a valid JWT:**

    The plugin expects a JWT with `iss` and `jku` claims, signed with a key that can be retrieved from the `jwks_url` provided by the registry service. For testing purposes, you can use a simple HMAC key.

    First, ensure you have the `golang-jwt/jwt/v5` library installed:

    ```sh
    go get github.com/golang-jwt/jwt/v5
    ```

    Then, create a temporary Go file (e.g., `generate_jwt.go`) with the following content:

    ```go
    package main

    import (
    	"fmt"
    	"github.com/golang-jwt/jwt/v5"
    )

    func main() {
    	// This key must match the "test-secret-key" used in your mock JWKS server
    	const testKey = "test-secret-key"
    	const testKid = "test-kid"

    	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
    		"iss": "test-issuer",
    		"jku": "test-jku",
    	})
    	token.Header["kid"] = testKid // Set the KID in the header
    	signedToken, err := token.SignedString([]byte(testKey))
    	if err != nil {
    		fmt.Println("Error signing token:", err)
    		return
    	}
    	fmt.Println(signedToken)
    }
    ```

    Run the Go file to generate the JWT:

    ```sh
    go run generate_jwt.go
    ```

    Copy the generated JWT.

2.  **Send a request to Kong:**

    Now, you can make a request to the protected endpoint with the generated JWT.

    ```sh
    curl -v -H "Authorization: Bearer YOUR_GENERATED_JWT_HERE" http://localhost:8000/cds-hooks
    ```

    Replace `YOUR_GENERATED_JWT_HERE` with the actual JWT you generated.

    If the JWT is considered valid by the plugin, you should receive a `200 OK` response from the upstream service (`httpbin.org` HTML content).
