FROM golang:alpine AS build
WORKDIR /src
ADD *.go go.mod go.sum /src/
RUN /usr/local/go/bin/go build -o mfctscan -ldflags="-w -s" .

FROM alpine AS bin
COPY --from=build /src/mfctscan /usr/local/bin/
