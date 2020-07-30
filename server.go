// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/x509"
	"flag"
	"os"
	"time"

	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/http2"

	lru "github.com/hashicorp/golang-lru"
)

const ()

var (
	httpPort      = flag.String("http_port", ":8080", "HTTP Server Port")
	issuer        = flag.String("issuer", "", "Certificate Issuer PEM file")
	ocsp_bucket   = flag.String("ocsp_bucket", "", "GCS Bucket with OCSP Responses")
	cache_size    = flag.Int("cache_size", 2000, "LRU Cache Size")
	storageClient *storage.Client
	bucketHandle  *storage.BucketHandle
	issuerCert    *x509.Certificate

	cache *lru.Cache
)

func defaulthandler(w http.ResponseWriter, r *http.Request) {

	var body []byte
	var err error

	// https://tools.ietf.org/html/rfc2560#appendix-A.1.1
	if r.Method == http.MethodPost {
		// openssl sends the cert in POST
		body, err = ioutil.ReadAll(r.Body)
		if err != nil {
			log.Printf("Error: Unable to read ocsp POST req... %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	} else if r.Method == http.MethodGet {
		rawReq := strings.TrimPrefix(r.URL.Path, "/")
		rc, err := base64.StdEncoding.DecodeString(rawReq)
		if err != nil {
			log.Printf("Error: unable to read ocsp GET req... %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		body = rc
	} else {
		log.Printf("Error: OCSP request must be get or post... %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	ocspReq, err := ocsp.ParseRequest(body)
	if err != nil {
		log.Printf("Could not parse OCSP Request... %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	log.Printf("OCSP Request for SerialNumber %x", ocspReq.SerialNumber)

	// TODO validate that this request is intended for a CA this  OCSP server is responsible for
	// eg comppare ocspReq.IssuerKeyHash hash of the *issuer argument

	if ae, ok := cache.Get(fmt.Sprintf("%x", ocspReq.SerialNumber)); ok {
		cachedResponse := ae.([]byte)
		log.Printf("OCSP Request for SerialNumber %x returned from cache", ocspReq.SerialNumber)
		ocspResp, err := ocsp.ParseResponse(cachedResponse, issuerCert)
		if err != nil {
			log.Printf("Could not read GCS Response Object Body. %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if ocspResp.NextUpdate.Before(time.Now()) {
			log.Printf(">>  Certificate with serialNumber [%x] Stale; Removing from Cache.", ocspReq.SerialNumber)
			cache.Remove(ocspReq.SerialNumber)
			// TODO: emit pubsub message where the subscriber can regenerate a new OCSP Response given the serial_number
			// doing so will create a more dynamic OCSP system which will update responses before the batch OCSP Generator runs.
		} else {
			if r.Method == http.MethodGet {
				expireAt := ocspResp.NextUpdate.Format(http.TimeFormat)
				w.Header().Set("Expires", expireAt)
				w.Header().Set("Cache-Control", "public")
			}
			w.Header().Set("Content-Type", "application/ocsp-response")
			w.Write(cachedResponse)
			return
		}
	}

	log.Printf("Looking for OCSP Request %s", base64.RawStdEncoding.EncodeToString(body))
	start := time.Now()
	obj := bucketHandle.Object(base64.StdEncoding.EncodeToString(body))
	rr, err := obj.NewReader(r.Context())
	if err != nil {
		log.Printf("Could not find OCSP Response Object. %v", err)
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	defer rr.Close()

	rawOCSP, err := ioutil.ReadAll(rr)
	if err != nil {
		log.Printf("Could not read GCS Response Object Body. %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Only parsing the response back out again to get the time for the NextUpdate to set as Cache-Control header
	// if thats not needed, skip this step (infact, no need to specify issuerCert)
	// The other better way to do this is to set this as an  metadata filed on the GCS object itself during pregeneration
	// phase...this is a TODO for later...
	ocspResp, err := ocsp.ParseResponse(rawOCSP, issuerCert)
	if err != nil {
		log.Printf("Could not parse OCSP Response from GCS %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	elapsed := time.Since(start)
	log.Printf("Elapsed Time for OCSP lookup %s", elapsed)

	log.Printf("Returning %x", ocspResp.SerialNumber)

	cache.Add(fmt.Sprintf("%x", ocspReq.SerialNumber), rawOCSP)

	if r.Method == http.MethodGet {
		expireAt := ocspResp.NextUpdate.Format(http.TimeFormat)
		w.Header().Set("Expires", expireAt)
	}
	w.Header().Set("Cache-Control", "public")
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Write(rawOCSP)
}

func main() {

	flag.Parse()
	var err error

	if os.Getenv("OCSP_BUCKET") != "" && *ocsp_bucket == "" {
		*ocsp_bucket = os.Getenv("OCSP_BUCKET")
	}

	if *ocsp_bucket == "" {
		log.Fatalf("Either --ocsp_bucket or OCSP_BUCKET environment variable must be set")
	}

	if *issuer != "" {
		certPEM, err := ioutil.ReadFile(*issuer)
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			log.Fatalf("failed to parse certificate PEM")
		}
		issuerCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatalf("failed to parse certificate: %v", err)
		}
	} else {
		issuerCert = nil
	}
	cache, err = lru.New(*cache_size)
	if err != nil {
		log.Fatalf("Could not initialize Cache" + err.Error())
	}
	r := mux.NewRouter()
	r.HandleFunc("/", defaulthandler)
	r.NotFoundHandler = http.HandlerFunc(defaulthandler)

	ctx := context.Background()

	storageClient, err = storage.NewClient(ctx)
	if err != nil {
		log.Fatalf("Could not init gcs client: %v", err)
	}
	bucketHandle = storageClient.Bucket(*ocsp_bucket)

	log.Println("Starting OCSP Server")

	httpSrv := &http.Server{
		Addr:    *httpPort,
		Handler: r,
	}
	http2.ConfigureServer(httpSrv, &http2.Server{})

	err = httpSrv.ListenAndServe()
	if err != nil {
		log.Fatal("Web server (HTTP): ", err)
	}

}
