package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/julienschmidt/httprouter"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/sigstore/cosign/pkg/cosign"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/signature"
	"github.com/spf13/pflag"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

const (
	apiVersion = "externaldata.gatekeeper.sh/v1alpha1"
)

var (
	certFile string
	keyFile  string
	port     string
)

func Verify(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	results := make([]externaldata.Item, 0)
	resultsFailedImgs := make([]string, 0)

	requestBody, err := io.ReadAll(req.Body)
	fmt.Println(requestBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		sendResponse(nil, resultsFailedImgs, fmt.Sprintf("unable to read request body: %v", err), w)
		return
	}

	var providerRequest externaldata.ProviderRequest
	err = json.Unmarshal(requestBody, &providerRequest)
	fmt.Println(providerRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		sendResponse(nil, resultsFailedImgs, fmt.Sprintf("unable to unmarshal request body: %v", err), w)
		return
	}

	ctx := context.TODO()

	wDir, err := os.Getwd()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Load cosign's public key which will be used to verify signatures
	publicKeyPath := filepath.Join(wDir, "cosign.pub")
	pub, err := signature.LoadPublicKey(ctx, publicKeyPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	regUsernameByte, err := os.ReadFile("/etc/registry-secret/username")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	regPasswordByte, err := os.ReadFile("/etc/registry-secret/password")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	regUsername := string(regUsernameByte)
	regPassword := string(regPasswordByte)

	// Authenticate to our registry by getting user/pswd from the container environment variable
	co := &cosign.CheckOpts{
		SigVerifier: pub,
		RegistryClientOpts: []ociremote.Option{
			ociremote.WithRemoteOptions(
				remote.WithAuth(&authn.Basic{
					Username: regUsername,
					Password: regPassword,
				}),
			),
		},
	}

	for _, key := range providerRequest.Request.Keys {
		ref, err := name.ParseReference(key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if _, _, err = cosign.VerifyImageSignatures(ctx, ref, co); err != nil {
			results = append(results, externaldata.Item{
				Key:   key,
				Error: key + "_invalid", // You can customize the error message here in case of failure
			})
			resultsFailedImgs = append(resultsFailedImgs, key)
			fmt.Println("error: ", err)
		} else {

			results = append(results, externaldata.Item{
				Key:   key,
				Value: key + "_valid", // You can customize the message here in case of validation
			})
		}

		fmt.Println("result: ", results)
	}
	sendResponse(&results, resultsFailedImgs, "", w)
}

func sendResponse(results *[]externaldata.Item, resultsFailedImgs []string, systemErr string, w http.ResponseWriter) {
	response := externaldata.ProviderResponse{
		APIVersion: apiVersion,
		Kind:       "ProviderResponse",
	}

	if results != nil {
		response.Response.Items = *results
	} else {
		response.Response.SystemError = systemErr
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		panic(err)
	}
}

func main() {
	pflag.StringVarP(&certFile, "cert", "c", "/certs/certificate.pem", "Path to the certificate file")
	pflag.StringVarP(&keyFile, "key", "k", "/certs/privateKey.pem", "Path to the private key file")
	pflag.StringVarP(&port, "port", "p", "8090", "Port to listen on")
	pflag.Parse()
	router := httprouter.New()
	router.POST("/validate", Verify)
	log.Fatal(http.ListenAndServeTLS(port, certFile, keyFile, router))
}
