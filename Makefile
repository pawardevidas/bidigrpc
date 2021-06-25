
all: client server

#protoc:
#	@echo "Generating Go files"
#	cd src/proto && protoc --go_out=plugins=grpc:. *.proto

server: #protoc
	@echo "Building server"
	go build -o server \
		github.com/pawardevidas\bidigrpc/src/server

client: #protoc
	@echo "Building client"
	go build -o client \
		github.com/pawardevidas\bidigrpc/src/client

clean:
	go clean github.com/pawardevidas\bidigrpc/...
	rm -f server client

.PHONY: client server #protoc
