module main

go 1.14

require (
	cloud.google.com/go v0.82.0
	cloud.google.com/go/security/privateca/apiv1beta1 v0.0.0
	cloud.google.com/go/storage v1.10.0
	github.com/cloudflare/golibs v0.0.0-20190417125240-4efefffc6d5c
	github.com/golang/protobuf v1.5.2
	github.com/gorilla/mux v1.7.4
	github.com/hashicorp/golang-lru v0.5.1
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/net v0.0.0-20210503060351-7fd8e65b6420
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0
	google.golang.org/api v0.46.0
	google.golang.org/genproto v0.0.0-20210521181308-5ccab8a35a9a
	google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1 v0.0.0
)

replace google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1 => ./lib/google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1

replace cloud.google.com/go/security/privateca/apiv1beta1 => ./lib/cloud.google.com/go/security/privateca/apiv1beta1
