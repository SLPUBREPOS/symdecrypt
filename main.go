package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	httpSwagger "github.com/swaggo/http-swagger"
	_ "symdecrypt/docs"
	"github.com/gorilla/mux"
	"github.com/patrickmn/go-cache"
)

var (
	supportedAlgorithms = []string{"aes-ctr"}
	keyCache            = cache.New(10*time.Minute, 15*time.Minute)
)

type DecryptRequest struct {
	Algorithm  string `json:"algorithm"`
	CipherText string `json:"cipher_text"`
	Key        string `json:"key"`
}

type DecryptResponse struct {
	PlainTextBase64 string `json:"plain_text_base64"`
}

// @title Symmetric Decryption API
// @version 1.0
// @description REST service for decrypting symmetric cipher texts

// @BasePath /api/v1
// @host localhost:8080
// @schemes http
// @produce json
// @accept json
func main() {
	r := mux.NewRouter()

	r.PathPrefix("/swagger/").Handler(httpSwagger.WrapHandler)
	api := r.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/algorithms", getAlgorithms).Methods("GET")
	api.HandleFunc("/decrypt", decryptHandler).Methods("POST")

	fmt.Println("Server is running at :8080")
	http.ListenAndServe(":8080", r)
}

// getAlgorithms returns a list of supported algorithms
// @Summary Get supported symmetric algorithms
// @Description Returns supported symmetric encryption algorithms
// @Tags Algorithms
// @Produce json
// @Success 200 {object} map[string][]string
// @Router /algorithms [get]
func getAlgorithms(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string][]string{
		"algorithms": supportedAlgorithms,
	})
}

// decryptHandler handles decryption requests
// @Summary Decrypt cipher text
// @Description Decrypts the provided cipher using the given algorithm and key
// @Tags Decryption
// @Accept json
// @Produce json
// @Param request body DecryptRequest true "Decryption Request"
// @Success 200 {object} DecryptResponse
// @Failure 400 {string} string "Bad request"
// @Failure 500 {string} string "Decryption failed"
// @Router /decrypt [post]
func decryptHandler(w http.ResponseWriter, r *http.Request) {
	var req DecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	alg := strings.ToLower(req.Algorithm)
	if !isSupported(alg) {
		http.Error(w, "unsupported algorithm", http.StatusBadRequest)
		return
	}

	decodedCipher, err := base64.StdEncoding.DecodeString(req.CipherText)
	if err != nil {
		http.Error(w, "invalid cipher text", http.StatusBadRequest)
		return
	}

	key := req.Key
	cacheKey := fmt.Sprintf("%s:%s", alg, key)
	keyCache.Set(cacheKey, key, cache.DefaultExpiration)
	//fmt.Println("cacheKey: ", cacheKey)
	//fmt.Println("key: ", key) 
	//fmt.Println("decodedCipher len:", len(decodedCipher))
	//fmt.Println("decodedCipher:", decodedCipher)
	
	plainText, err := decrypt(alg, decodedCipher, []byte(key))
	if err != nil {
	//	fmt.Println("Decrypt error:", err) 
		http.Error(w, "decryption failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	base64Output := base64.StdEncoding.EncodeToString(plainText)
	json.NewEncoder(w).Encode(DecryptResponse{PlainTextBase64: base64Output})
}

func isSupported(alg string) bool {
	for _, a := range supportedAlgorithms {
		if a == alg {
			return true
		}
	}
	return false
}
