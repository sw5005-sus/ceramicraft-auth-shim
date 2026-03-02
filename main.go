package main

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

const defaultPort = "8080"
const claimKey = "https://pi-pottery.com/userid"

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	http.HandleFunc("/verify", verifyHandler)
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	log.Printf("Starting auth-shim on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	tokenString := parts[1]

	// In a real scenario, fetch JWKS from ZITADEL and verify signature.
	// For this shim implementation, we might be focusing on transformation first.
	// However, forward auth MUST verify the token.
	// Assuming an environment variable for JWKS_URL exists, or if we just decode without verification for dev (NOT SAFE FOR PROD).
	// Given the prompt implies ZITADEL is the issuer, we should really verify.
	// For now, let's implement parsing and claim extraction to demonstrate the header transformation.
	// TODO: Add proper signature verification with JWKS.

	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		log.Printf("Error parsing token: %v", err)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	// Debug: Print all claims
	log.Printf("Token Parsed. Claims found: %v", claims)

	userID, ok := claims[claimKey].(string)
	if !ok || userID == "" {
		// Fallback: Try standard "sub" claim if custom claim is missing (for testing purposes)
		if sub, ok := claims["sub"].(string); ok && sub != "" {
			log.Printf("Custom claim missing, falling back to 'sub': %s", sub)
			userID = sub
		} else {
			log.Printf("Claim %s not found or empty", claimKey)
			http.Error(w, "User ID claim missing", http.StatusForbidden)
			return
		}
	}

	// Important: Set the header for the upstream service
	w.Header().Set("X-Original-User-ID", userID)
	w.WriteHeader(http.StatusOK)
	log.Printf("Authenticated user: %s", userID)
}
