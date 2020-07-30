FROM golang:1.13 as build

ENV GO111MODULE=on

WORKDIR /app
COPY . .

RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build server.go

FROM gcr.io/distroless/base
COPY --from=build /app/server /

EXPOSE 8080

ENTRYPOINT ["/server"]
