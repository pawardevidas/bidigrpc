package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"

	pb "github.com/pawardevidas/bidigrpc/src/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	"google.golang.org/grpc"
)

type server struct {
	pb.UnimplementedMathServer
}

func getGID() uint64 {
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	b = b[:bytes.IndexByte(b, ' ')]
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

func (s server) Max(srv pb.Math_MaxServer) error {

	log.Println("start new server")
	var max int32
	ctx := srv.Context()

	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no peer found")
	}

	tlsAuth, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return status.Error(codes.Unauthenticated, "unexpected peer transport credentials")
	}

	if len(tlsAuth.State.VerifiedChains) == 0 || len(tlsAuth.State.VerifiedChains[0]) == 0 {
		return status.Error(codes.Unauthenticated, "could not verify peer certificate")
	}

	// Check subject common name against configured username
	if tlsAuth.State.VerifiedChains[0][0].Subject.CommonName != "abcdefg" {
		return status.Error(codes.Unauthenticated, "invalid subject common name")
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no headers in request")
	}
	authHeaders, ok := md["authorization"]
	if !ok {
		return status.Error(codes.Unauthenticated, "no header in request")
	}
	if len(authHeaders) != 1 {
		return status.Error(codes.Unauthenticated, "more than 1 header in request")
	}

	auth := authHeaders[0]
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return status.Error(codes.Unauthenticated, `missing "Basic " prefix in "Authorization" header`)
	}

	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return status.Error(codes.Unauthenticated, `invalid base64 in header`)
	}

	cs := string(c)
	pos := strings.IndexByte(cs, ':')
	if pos < 0 {
		return status.Error(codes.Unauthenticated, `invalid basic auth format`)
	}

	user, password := cs[:pos], cs[pos+1:]
	if user != "devidas" || password != "pawar" {
		return status.Error(codes.Unauthenticated, "invalid user or password")
	}

	// Remove token from headers from here on
	md["authorization"] = nil
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("Unable to get hostname %v", err)
	}
	// [END istio_sample_apps_grpc_greeter_go_server_hostname]
	for {

		// exit if context is done
		// or continue
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// receive data from stream
		req, err := srv.Recv()
		if err == io.EOF {
			// return will close stream from server side
			log.Println("exit")
			return nil
		}
		if err != nil {
			log.Printf("receive error %v", err)
			continue
		}

		// continue if number reveived from stream
		// less than max
		if req.Num <= max {
			continue
		}
		// update max and send it to stream
		max = req.Num
		resp := pb.Response{Result: max, Hostname: hostname + "-" + strconv.FormatUint(getGID(), 10)}
		if err := srv.Send(&resp); err != nil {
			log.Printf("send error %v", err)
		}
		log.Printf("send new max=%d", max)
	}
}

func main() {
	// create listiner
	lis, err := net.Listen("tcp", ":50005")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// create grpc server
	s := grpc.NewServer()
	pb.RegisterMathServer(s, server{})
	reflection.Register(s)
	// and start...
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
