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
	"errors"
	"flag"
	"net/http"

	"crypto/rsa"
	"crypto/x509"

	"bytes"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"

	"io"
	"sync"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"

	privateca "cloud.google.com/go/security/privateca/apiv1"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1"

	"github.com/golang/protobuf/ptypes"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"

	"golang.org/x/crypto/ocsp"

	"cloud.google.com/go/storage"

	"github.com/gorilla/mux"
	"golang.org/x/net/http2"
	"golang.org/x/time/rate"
	"google.golang.org/api/iterator"
)

type ErrorResult struct {
	SerialNumber string
	Message      string
	Error        error
}

const (
	maxRequestsPerSecond float64 = 10 // "golang.org/x/time/rate" limiter to throttle CA.list() operations
	burst                int     = 2
)

var (
	responder *x509.Certificate
	priv      *rsa.PrivateKey

	httpPort  = flag.String("http_port", "", "HTTP Server Port")
	projectID = flag.String("projectID", "", "ProjectID for PrivateCA")
	location  = flag.String("location", "", "Location for PrivateCA")
	caName    = flag.String("ca_name", "", "Name of CA")
	caPool    = flag.String("pool", "", "Name of CA Pool")

	bucketName    = flag.String("bucketName", "", "OCSP Response BUcket")
	ocspSignerKey = flag.String("ocsp_signer_key", "ocsp_signer_key.pem", "OCSP Signer PrivateKey")
	ocspSignerCrt = flag.String("ocsp_signer_crt", "ocsp_signer_crt.pem", "OCSP Signer PublicKey")

	serialNumber = flag.String("serial_number", "", "Update OCSP Response given a certificate serialNumber")

	expiry     = flag.Duration("expiry", 3600*time.Second, "When expire the OCSP Cert (as time.Duration, 3600s)")
	useSecrets = flag.Bool("useSecrets", false, "Use Cloud Secrets to read OCSP keys into memory")

	pcaClient *privateca.CertificateAuthorityClient

	storageClient *storage.Client
	bucketHandle  *storage.BucketHandle

	mu = &sync.Mutex{}
)

func genResponses(ctx context.Context, sn string) (res []ErrorResult) {

	var aggregatedErrors []ErrorResult // Saves any errors from each certificate ocsp response.  TODO: use channels

	// Start iterating over all the certificates in the CAPool
	parent := fmt.Sprintf("projects/%s/locations/%s/caPools/%s", *projectID, *location, *caPool)

	// 6/15/20: Filtering by time based attribute like updateTime is not yet supported in the API.
	//          Once it is ready, the filter below can be used to shard generation and/or update using attributes like updateTime
	var filter string
	// If the serialNumber is provided in an argument, just update that one alone.
	//  TODO: update list() when certificate.get() is supported with serialNumber
	if sn != "" {
		filter = fmt.Sprintf("certificateDescription.subjectDescription.hexSerialNumber=\"%s\"", sn)
	}
	req := &privatecapb.ListCertificatesRequest{
		Parent: parent,
		Filter: filter,
	}

	var wg sync.WaitGroup
	limiter := rate.NewLimiter(rate.Limit(maxRequestsPerSecond), burst)

	it := pcaClient.ListCertificates(ctx, req)
	for {
		crt, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Printf("Unable to get  certificates: %v", err)
			mu.Lock()
			aggregatedErrors = append(aggregatedErrors, ErrorResult{Message: "Unable to get certificate", Error: err})
			mu.Unlock()
			continue
		}

		wg.Add(1)
		go func(ctx context.Context, crt *privatecapb.Certificate) {
			defer wg.Done()

			// Await tokens, marking this error as fatal; we should not continue if the
			// rate limiter fails.
			if err := limiter.Wait(ctx); err != nil {
				log.Fatal(err)
			}
			// Check context for errors
			if ctx.Err() != nil {
				log.Fatal(ctx.Err())
			}

			thisUpdate := time.Now()
			nextUpdate := thisUpdate.Add(*expiry)

			sn := crt.CertificateDescription.SubjectDescription.HexSerialNumber
			intSerialNumber := new(big.Int)
			intSerialNumber, ok := intSerialNumber.SetString(crt.CertificateDescription.SubjectDescription.HexSerialNumber, 16)
			if !ok {
				mu.Lock()
				aggregatedErrors = append(aggregatedErrors, ErrorResult{
					SerialNumber: sn,
					Message:      "Could not read HexSerialNumber for revoked certificate",
					Error:        errors.New(fmt.Sprintf("Could not read HexSerialNumber for revoked certificate %v", sn)),
				})
				mu.Unlock()
				return
			}

			var status int
			var revocationReason int
			var ocspResponseTemplate ocsp.Response
			status = ocsp.Good

			var tt time.Time
			// ocsp golang client has just a few reasons to cite for revocation
			if crt.RevocationDetails != nil {
				status = ocsp.Revoked
				switch crt.RevocationDetails.RevocationState {
				case privatecapb.RevocationReason_REVOCATION_REASON_UNSPECIFIED:
					revocationReason = ocsp.Unspecified
				case privatecapb.RevocationReason_KEY_COMPROMISE:
					revocationReason = ocsp.KeyCompromise
				default:
					revocationReason = ocsp.Unspecified
					status = ocsp.Unknown
				}
				tt, err = ptypes.Timestamp(crt.RevocationDetails.RevocationTime)
				if err != nil {
					mu.Lock()
					aggregatedErrors = append(aggregatedErrors, ErrorResult{SerialNumber: sn, Message: "Error reading Certificate Revocation time:", Error: err})
					mu.Unlock()
					return
				}

			}

			ocspResponseTemplate = ocsp.Response{
				Status:           status,
				SerialNumber:     intSerialNumber,
				ThisUpdate:       thisUpdate,
				ProducedAt:       thisUpdate,
				NextUpdate:       nextUpdate,
				RevokedAt:        tt,
				RevocationReason: revocationReason,
				Certificate:      responder,
			}

			certCA := []byte(crt.GetPemCertificateChain()[0])
			blockcrtCA, _ := pem.Decode(certCA)

			iss, err := x509.ParseCertificate(blockcrtCA.Bytes)
			if err != nil {
				mu.Lock()
				aggregatedErrors = append(aggregatedErrors, ErrorResult{SerialNumber: sn, Message: "Error parsing public cert:", Error: err})
				mu.Unlock()
				return
			}

			// Generate the OCSP Response Bytes to save as the filecontent on GCS
			responseBytes, err := ocsp.CreateResponse(iss, responder, ocspResponseTemplate, priv)
			if err != nil {
				mu.Lock()
				aggregatedErrors = append(aggregatedErrors, ErrorResult{SerialNumber: sn, Message: "Error creating OCSPResponse", Error: err})
				mu.Unlock()
				return
			}

			log.Printf("Uploading OCSP Response for serialNumber [%x]", intSerialNumber)

			cc := crt.PemCertificate
			blockcrt, _ := pem.Decode([]byte(cc))

			parsedCert, err := x509.ParseCertificate(blockcrt.Bytes)
			if err != nil {
				mu.Lock()
				aggregatedErrors = append(aggregatedErrors, ErrorResult{SerialNumber: sn, Message: "Error parsing public cert", Error: err})
				mu.Unlock()
				return
			}

			// Generate the OCSP Request to save as the actual  _filename_
			ocspReqOpt := &ocsp.RequestOptions{}
			ocspReq, err := ocsp.CreateRequest(parsedCert, iss, ocspReqOpt)
			if err != nil {
				mu.Lock()
				aggregatedErrors = append(aggregatedErrors, ErrorResult{SerialNumber: sn, Message: "Error in ocsp.Request", Error: err})
				mu.Unlock()
				return
			}

			// we are passing in the NextUpdate time incase we ever want to add in GCS object attributes indicating that field.
			// at the moment, it is not used.
			err = uploadOCSPResponseWithReqBytes(ctx, base64.StdEncoding.EncodeToString(ocspReq), responseBytes, nextUpdate)

			if err != nil {
				mu.Lock()
				aggregatedErrors = append(aggregatedErrors, ErrorResult{SerialNumber: sn, Message: "Error in uploading OCSP Response object", Error: err})
				mu.Unlock()
				return
			}
		}(ctx, crt)

	}

	wg.Wait()

	return aggregatedErrors
}

func main() {

	flag.Parse()
	var err error

	if *bucketName == "" || *caName == "" || *caPool == "" || *location == "" || *projectID == "" ||
		*ocspSignerKey == "" || *ocspSignerCrt == "" {
		log.Fatalf("bucketName, caName, caPool, location, projectID, ocspSignerKey, ocspSignerCrt cannot be null")
	}

	ctx := context.Background()
	storageClient, err = storage.NewClient(ctx)
	if err != nil {
		log.Fatalf("%v", err)
	}

	bucketHandle = storageClient.Bucket(*bucketName)
	var keyRaw, crtRaw []byte

	if *useSecrets {

		crtRaw, err = getFromSecrets(ctx, *ocspSignerCrt)
		if err != nil {
			log.Fatalf("Could not read certificate from SecretManager: %v", err)
		}

		keyRaw, err = getFromSecrets(ctx, *ocspSignerKey)
		if err != nil {
			log.Fatalf("Could not read certificate key from SecretManager: %v", err)
		}

	} else {
		crtRaw, err = ioutil.ReadFile(*ocspSignerCrt)
		if err != nil {
			log.Fatalf("Unable to read OCSP Signer certificate file: %v", err)
		}

		// Read and parse the OCSP Signing keypairs
		keyRaw, err = ioutil.ReadFile(*ocspSignerKey)
		if err != nil {
			log.Fatalf("Unable to get iterate certificate: %v", err)
		}

	}

	// Read and parse the OCSP Signing keypairs

	block, _ := pem.Decode(keyRaw)

	priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Unable to get read private ocsp key: %v", err)
	}

	blockcrt, _ := pem.Decode(crtRaw)

	responder, err = x509.ParseCertificate(blockcrt.Bytes)
	if err != nil {
		log.Fatalf("failed to access aes secret version: %v", err)
	}

	pcaClient, err = privateca.NewCertificateAuthorityClient(ctx)
	if err != nil {
		log.Fatalf("Could Not create PrivateCA Client... %v", err)
	}

	if *httpPort != "" {
		log.Println("Starting HTTP server")
		r := mux.NewRouter()
		r.HandleFunc("/", defaulthandler)
		r.NotFoundHandler = http.HandlerFunc(notFoundhandler)

		httpSrv := &http.Server{
			Addr:    *httpPort,
			Handler: r,
		}
		http2.ConfigureServer(httpSrv, &http2.Server{})
		err = httpSrv.ListenAndServe()
		if err != nil {
			log.Fatal("Web server (HTTP): ", err)
		}
		return
	}

	errResponses := genResponses(ctx, *serialNumber)

	for _, elem := range errResponses {
		log.Printf("Aggregated Error: SerialNumber [%s]: error %v\n", elem.SerialNumber, elem.Error)
	}

}

func getFromSecrets(ctx context.Context, secretName string) ([]byte, error) {
	secretMgrclient, err := secretmanager.NewClient(ctx)
	if err != nil {
		return []byte(""), err
	}

	name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", *projectID, secretName)
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	}

	cResult, err := secretMgrclient.AccessSecretVersion(ctx, req)
	if err != nil {
		return []byte(""), err
	}

	return cResult.Payload.Data, nil
}

func notFoundhandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not Found", http.StatusNotFound)
}
func defaulthandler(w http.ResponseWriter, r *http.Request) {

	sn := r.URL.Query().Get("serialNumber")
	if sn == "" {
		// iterate over all values
		// http.Error(w, fmt.Sprintf("&serialNumber as hex string must be provided "), http.StatusInternalServerError)
		// return
		log.Printf("Iterating over all certificates")
	} else {
		log.Printf("Lookup for SerialNumber %s", sn)
	}
	errResponses := genResponses(r.Context(), sn)

	for _, elem := range errResponses {
		log.Printf("Aggregated Error: SerialNumber [%s]: error %v\n", elem.SerialNumber, elem.Error)
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ok"))
}

// upload OCSP response with filename==b64encode(ocspRequest)
func uploadOCSPResponseWithReqBytes(ctx context.Context, name string, oc []byte, expires time.Time) error {
	obj := bucketHandle.Object(name)
	r := bytes.NewReader(oc)
	w := obj.NewWriter(ctx)
	w.ContentType = "application/ocsp-response"
	if _, err := io.Copy(w, r); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return nil
}
