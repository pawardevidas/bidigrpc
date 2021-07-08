FROM gcr.io/cloud-builders/go as build

ENV GOPATH /go
ENV GO111MODULE on

WORKDIR ${GOPATH}/client

COPY go.mod go.sum ./

RUN go mod download

COPY server.go ./

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go install -installsuffix "static" .

# https://docs.docker.com/develop/develop-images/multistage-build/#use-multi-stage-builds

FROM gcr.io/distroless/static:nonroot

COPY --from=build /go/bin/server /bin/server

ENTRYPOINT ["/bin/server"]