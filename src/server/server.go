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
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	"google.golang.org/grpc"
)

/*
var (
	bundleCAChain = []byte(`
-----BEGIN CERTIFICATE-----
MIIFVzCCAz+gAwIBAgIUbN5d2ApZUZuKtAghJi0d1DhrU3cwDQYJKoZIhvcNAQEL
BQAwIjEOMAwGA1UECgwFSXN0aW8xEDAOBgNVBAMMB1Jvb3QgQ0EwHhcNMjEwNzE3
MDE1NzIyWhcNMjMwNzE3MDE1NzIyWjA+MQ4wDAYDVQQKDAVJc3RpbzEYMBYGA1UE
AwwPSW50ZXJtZWRpYXRlIENBMRIwEAYDVQQHDAlncnBjcHJveHkwggIiMA0GCSqG
SIb3DQEBAQUAA4ICDwAwggIKAoICAQDrodsHNiSN1VmhUPboKdwAMUD/t7y8Cj8q
1tCYKHHQcghPkieir8fmkgbFfbx0cmjpo9nF2u4FsU2gNo6Cblucw2vfx7uu4kCu
WIZY7Gfof6p4lwCcJl6pGXRZp3bT6TZxrYx3C7g8jWd3vzHOWcClyD6LRP8ENOas
29QSeV49tagaMsgGBO52KSwXX3uCli9Wnvjq9kXmG3Rfs3TUwsnYj775e/zxIlGV
hoB1uILXlFf5veD/fZ0YbuA7CN5knGwYH1FqoqTIqse95u1osac7hu4HTW0kgTR3
jPRQu+hIwWmxeELweFaLQ1HaurS02w1HmNJHIgpeLKxe3rlsnQHJFWtKLsgLZUKt
o2ORcvvybh53t4TLr7J2a73m+3PhuwmCdo6cBjcVaj8Gq3HCKAoa0JOQQl16r9Yr
AO+4ctEBDZdeXZMR2VaGKARIf4h3Ket1G53BAgjCEHjWxTJy9/xDAZ+QvbHPF//j
rMUmj5lUN7ZGR1S2odgj+ZBaueCqsp5q7UQj6kKEWXTeuPPcG2PIVbZaEHY3/EBR
Y0Q2ah8fZk/BaTmIQe06JdPbwINZ1Td90u4NwXGQ3KOcDFZxqpiPK+Tvc7ygRVGC
EgapjLJnjJVton3CFrkpigrdM1uMz5OWPXlmBq1xmsH3xxhqkEC3B5PkTfWVzF54
nnRsOGT4pwIDAQABo2kwZzAdBgNVHQ4EFgQU8qoYnnRjb/lNmolf2H2x65QlhSkw
EgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAuQwIgYDVR0RBBswGYIX
aXN0aW9kLmlzdGlvLXN5c3RlbS5zdmMwDQYJKoZIhvcNAQELBQADggIBAI8Gtdje
8Z8Ac2w8WdDHOV20QnitX2ACIFVCcVoZXgMB0Vw+9lLoOHDefk8Th1dbRVZ14q7Z
VSYOQ7s/zfkOEOVyQmU605hKETLoyJp9denRo1onKbwUVCRXccM+Akj2UocqvKiZ
7QXiOJYd+SZ1inCSwdr3/8TajYhGJYHj/ZECjqGN3ZuXJ0NzaIKdhVVLHxQFSeMq
LxwbPEABv2R60T3m+MOVH8ZrXzwZVqT4WF2NDJaUQGJ3Zf2NvJasYFooFWoJTzlt
wIKkJ4o1JZpI2t0P9/m4b49fmXxN4kQcipqJROM45jASvuVYSUG7XIJf61QehIvF
xMrwEG+aUuA+Yw4/fD3uQPE3KZrHtByKOOZiPOZduDAvc97u43Lwkxj38pc8k38k
g0q8UScAZIb4DBMiuJ/DBThNc9hOM1AxPEvDD8Vys9Qv5unCs/A3C3UZmRIVY+K4
jFr4SyXMAcS7uAa5DipJIJ3mDBpDiObDVF0IWk6J2cHvAypNnpaQa3E6OhFtFU60
WaT65BkFANl5V5hxsUpSvSm0SgOZvR6Tjdj7M6Ev0hlusI30830odqLEHIA9EBwW
kHCTEXpFkaRNQYkmbZNkeg/MwBDd+41WeTtjjMyKjpmRxoWRcqGhyNAb0iLXFd1M
WlVzo8G2xPQHvn5zKes620NbEO3DmKf/wb8H
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFFDCCAvygAwIBAgIUeZYjJdVxYw6iBunU6Gi3JbudlNcwDQYJKoZIhvcNAQEL
BQAwIjEOMAwGA1UECgwFSXN0aW8xEDAOBgNVBAMMB1Jvb3QgQ0EwHhcNMjEwNzE0
MDcxMzE3WhcNMzEwNzEyMDcxMzE3WjAiMQ4wDAYDVQQKDAVJc3RpbzEQMA4GA1UE
AwwHUm9vdCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMAQUQWS
e/kmgHgTcf65rfnnYomq/6VGSbHbECiWcvdsUIzIvgd2RevYbJxHAms5Hx9v3deM
7elnwgpkGHWtig3sbC3bc8hCHJfdEtOs1ecEfLkG8SrqOKgjB7yXRXrviyVXnjkT
WcOnc5RLgj5MAeTSd4KkHSUdOIf/gGHSaukVd+GwHog24U5Tc+qIASSduBqmqFf1
/UlUtnDi0tiLlX9FossMHqhDKARbiUmweuBRtjYc0Nxs84F6V8vCfcXU2CNWUsmA
DnJ0B5C9woN+4MVbeY7tfCptX5wopiN18FBrkroeW5Vz9wlLpKgEGlj+uFeto8zL
QjR2qfVbgQvpEtImG6Fzv+uaqPdJDZ6XVcdRgUjkjHA+VDHWlKtbArK9zlsBEFcM
Wat1SQOY0SFUbNBmtIQPVOvglyIEkcu3eYH2vg9CYzSTEnD1czHzTUiexlEAD3pi
G5q60m/EbjKYe63WOtYm/Qzy4CAO/BJX+i6yrX9qoVcN2B2nFR7QR+QjI/VyicDW
BRM9DmqFpBaPeZ7eGxoAIBWxV8ykP4db2QJBLgc4ldFBrsuQicEAEqkLyQypiKmD
oXXTg2BeVvIGR5AYT9p9s8n2K5mTs4iOdaMdZ4EBa5xzq3E40HW+HRAQ1tyeekNC
mlcn9bUc7NLEw+3yBPz6bgjaa96vue8wUpzJAgMBAAGjQjBAMB0GA1UdDgQWBBRV
9ijKLTqFO8UWWMfk7/uTYXDWbTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE
AwIC5DANBgkqhkiG9w0BAQsFAAOCAgEAavGSi+bPwrsB/wHCTklMSMnBdBAbiIW2
os9tysKCBwFpvosa0veT1fEZTOaRRlTmw7iMVpzN6Cyif3ytFjpKff6GsC5Rbn9V
I3oC3aMos2EkF/6EUudKWmubwBc85X56orV8lZQamlCQt/DE3NLHABtiGVYulkqX
cusskeTEMCpsDBS+ojxdIa0nHItNt3z1jONaaZJ3E6JRfkje2TjVDYSf3e1NnJ3Q
GpmPhPNsXrjBQFXsiAJdXyR8FfGASJBep8x2Q7nu3PTItF75DKR6BJKvZvJz+GEZ
X2y8Ev2pWBraswi0pL6NE5Xk1ZPhgt0G++My8EOa3Uk4zKYG6iln5wwIWCLN105M
fcUrfYt5tVzlheC3UvXWs/aVGGSin7hPmuZcIzSfRDeNnSRE0jl/HOLhNIiWC0N8
KZjhik814DvVPwHHnP/+ZdnoGtMgK5qIRS8n/hlFTriXMZGolzBFeKcmgPONBiqV
vnFLlYbsGwAHDKe9PSmIMnLi0BEs/4lzr4Xqotmot6khrJ3dEY61onPAaYdaRz8e
5QiMODjOxwK4/wBji1wiui/btGTatE7t8snQvy7/fWlWUCi9bD8lUgT3gDa+yxPD
lin48nUfhPbCQFl3EeYEHvcicd5bDXjn3jI850oCaKNi1YZnk+r+rePsULDjilIS
jhjW1Mplyeo=
-----END CERTIFICATE-----
`)

	bundleKey = []byte(`
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`)

	bundleCert = []byte(`
-----BEGIN CERTIFICATE-----
MIIF8TCCA9mgAwIBAgIUIvfJfHAAaNDSE4/BHkXwCWvKemgwDQYJKoZIhvcNAQEL
BQAwPjEOMAwGA1UECgwFSXN0aW8xGDAWBgNVBAMMD0ludGVybWVkaWF0ZSBDQTES
MBAGA1UEBwwJZ3JwY3Byb3h5MB4XDTIxMDcxODA3Mjc1OVoXDTMxMDcxODA3Mjgw
OVowZzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRUwEwYDVQQKEwxrcm9ubWws
IEluYy4xNDAyBgNVBAMTK2dycGNzZXJ2ZXItc3ZjLmdycGNzZXJ2ZXIuc3ZjLmNs
dXN0ZXIubG9jYWwwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDVI6S+
45LI4W1a89ocWkaxmjRFm2fG90iKqlbqxCE5zoTzoGVz1yt2s4jqWIdTvYO4BqQM
M4RMPa5ngTUjTP82/MN75LNsa5u89CeNZVye4vcW8G6P6xes3IIotT4cVdMEMmOp
64z5Do6iZ5zMNyo2gZj/JJQWvRIDyQwLT7BHxGDrdzJCuQ32Wow2BdOYCp8dxleO
LSXlnAY4qtX6aH5J5GnrSjU5F9n8SrtoipgcOx4JI1ywLGpY6FQe0oF9fulJNoQ9
j0ZDd91fpGe244/YIljmNtDD3TTPbdI2TPaV/5GtkXUXAD+tj4zmoaGKJMtmDMuS
MS5m270LkBtHFiSOcPZij/jw7gD4tTUXZBztOVjGrZGK12Xk9vphwIVte7cfAwHK
QL7pjn0cOM0L6HPZENeW/yKVIMDFFNi8uqll61Vy/tqGCeFR1jGKGH6asRtbQMuz
j97R+RfT5zsmiHO5dFsu143i08P1+PWzfFT/Gae3vnSU40ScxeGTMEnG3C3FU99g
KyxQkcLA9qwq3sWep7rGJFz4Ligg25LuTxN20Z1J6zmGd1HApcAkcRwor8imViSa
wyq4SwPIaSoivluv4mmTXdy4EpxbejoZDCcdU4twfptEHU4bdiapk/Rzf3OSozPB
Ma5mvjqJr35vghkMKuQvw8fFwJbu56bl96wz8wIDAQABo4G9MIG6MA4GA1UdDwEB
/wQEAwIFoDBPBgNVHSUESDBGBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMD
BggrBgEFBQcDBQYIKwYBBQUHAwYGCCsGAQUFBwMHBggrBgEFBQcDCTAfBgNVHSME
GDAWgBTyqhiedGNv+U2aiV/YfbHrlCWFKTA2BgNVHREELzAtgitncnBjc2VydmVy
LXN2Yy5ncnBjc2VydmVyLnN2Yy5jbHVzdGVyLmxvY2FsMA0GCSqGSIb3DQEBCwUA
A4ICAQC5mgCk9wzMjCDgFC4gpjDs9ekSyK7w9ByIW42xdSfZflnkH9ArX06CBL/A
zVNRRZVG+nuviR4jqpkEh+HBTQRQUdpAsG8tPzKnyAz767x4u+rzwtooARJ4xoUq
jq1MDXvjewZFhsgxgld58DR3YVqUSXnybQJV7mn45UvZiHt+TAyDGSnxgbCaET65
VtZKYUfbujQWdL725JxvSB4lgfMxIbbMISxPOSgdloJi5qyKm3zkakN/A0uu9BnI
vosqcvXfL7ShjDLYFhVxR48j3GgzY0S2r0NEp3MK7P57bVzbgNw9pbYjw/7mPH6e
Ka4obt4CAUEbCRwPb9ByWyit4WjcuZLd/aOspMlZQtLy8VxFFRGRz8ci6q1AR+7T
JlL8LvkWSDi5dttoFLoIQiGVxBUen98V3k+DuRgE8NmDFTxoKgeMtt5XNjKN/7tO
jMeYT7yAjz3PXMsVS1Vn73UmAygYN85CCS4doV0oJWSqmupuWlVmHFayn7ofwgWb
DuNpSsaitPEcsn1g0RHoyl1IgCvtJyBhCCqSdyD96MZjWHxiwnlf5YmmdCGxJhyE
WJNkQ8o0eHPkrpdyJFvP0V7eLEx3oBGUj7f/Dnw2cD+a0z1/BxtG7g8KFXDxwYdF
00dc9i2NNLA+kq4HqtqEUuLbLNiiJTvcMq8vKdzIm93yOqUvMQ==
-----END CERTIFICATE-----
`)
)
*/
// var (
// 	//serverHostOverride = flag.String("server_host_override", "demo.kronml.dev", "The server name use to verify the hostname returned by TLS handshake")
// 	certFile = flag.String("cert", "..\\grpcserver.kronml.dev.crt", "A PEM eoncoded certificate file.")
// 	keyFile  = flag.String("key", "..\\grpcserver-key.pem", "A PEM encoded private key file.")
// 	caFile   = flag.String("CA", "..\\cert-chain.pem", "A PEM eoncoded CA's certificate file.")
// )

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

	// p, ok := peer.FromContext(ctx)
	// // if ok {
	// // 	fmt.Println("\n %s \n", p.AuthInfo.AuthType())
	// // 	// tlsInfo := p.AuthInfo(credentials.TLSInfo)
	// // 	// //v := tlsInfo.State.PeerCertificates
	// // 	// for _, v := range tlsInfo.State.PeerCertificates {
	// // 	// 	fmt.Println("Client: Server public key is:")
	// // 	// 	fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
	// // 	// }
	// // }

	// //p, ok := peer.FromContext(ctx)
	// if !ok {
	// 	fmt.Println("no peer found")
	// }

	// tlsAuth, ok := p.AuthInfo.(credentials.TLSInfo)
	// if !ok {
	// 	fmt.Println("unexpected peer transport credentials")
	// }

	// if len(tlsAuth.State.VerifiedChains) == 0 || len(tlsAuth.State.VerifiedChains[0]) == 0 {
	// 	fmt.Println("could not verify peer certificate")
	// }

	// // Check subject common name against configured username
	// if tlsAuth.State.VerifiedChains[0][0].Subject.CommonName != "abcdefg" {
	// 	fmt.Println("invalid subject common name")
	// }

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

	// switch pub := pub.(type) {
	// case *rsa.PublicKey:
	// 	fmt.Println("pub is of type RSA:", pub)
	// case *dsa.PublicKey:
	// 	fmt.Println("pub is of type DSA:", pub)
	// case *ecdsa.PublicKey:
	// 	fmt.Println("pub is of type ECDSA:", pub)
	// case ed25519.PublicKey:
	// 	fmt.Println("pub is of type Ed25519:", pub)
	// default:
	// 	panic("unknown type of public key")
	// }

	// peerCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	// if err != nil {
	// 	log.Printf("load peer cert/key error:%v", err)
	// 	return
	// }
	// caCert, err := ioutil.ReadFile(*caFile)
	// if err != nil {
	// 	log.Printf("read ca cert file error:%v", err)
	// 	return
	// }
	// caCertPool := x509.NewCertPool()
	//caCertPool.AppendCertsFromPEM(caCert)
	// peerCert, err := tls.X509KeyPair(bundleCert, bundleKey)
	// if err != nil {
	// 	log.Printf("load peer cert/key error:%v", err)
	// 	return
	// }
	// caCertPool.AppendCertsFromPEM(bundleCAChain)
	// ta := credentials.NewTLS(&tls.Config{
	// 	Certificates: []tls.Certificate{peerCert},
	// 	ClientCAs:    caCertPool,
	// 	ClientAuth:   tls.RequireAndVerifyClientCert,
	// })

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
