	package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	mr "math/rand"
	"os"

	pb "github.com/pawardevidas/bidigrpc/src/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	//"google.golang.org/grpc"
	//"google.golang.org/grpc/credentials"

	"time"
)

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
MIIF8TCCA9mgAwIBAgIUSXfCdJqdRj7fzYPHEn/2ysoyPOkwDQYJKoZIhvcNAQEL
BQAwPjEOMAwGA1UECgwFSXN0aW8xGDAWBgNVBAMMD0ludGVybWVkaWF0ZSBDQTES
MBAGA1UEBwwJZ3JwY3Byb3h5MB4XDTIxMDcxODA2MDYzNloXDTMxMDcxODA2MDY0
NlowZzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRUwEwYDVQQKEwxrcm9ubWws
IEluYy4xNDAyBgNVBAMTK2dycGNjbGllbnQtc3ZjLmdycGNzZXJ2ZXIuc3ZjLmNs
dXN0ZXIubG9jYWwwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDOigoL
SB+83tWscl3jocxyVL+6RAW4btes9SlBlr99PRCk6PrW9T2gXn2JhsuOH/RlqPqa
eYCCFjJHHlviWew+Osdn1xuxo5vKlG/ISI165lsmFPUiKTWm8EMi7EmvEZROQAjH
ZiBMSxMzJl04k0n/mNrc0UQxinGgDiLVOUofcy0p7Rdm1wPiTK4tXnQgbFq87KJs
eM2imNsZhy3qxVph92PnzC8Ztw3bGb1iBHlyTnerHNwF/Bu0bc7DoX+pCh6x+8ZS
HCWSlIDX3D30Tza5heTYg2Bv1c+eiEgKOGifDcaVcbT3oohyoT6iPJM6NVErHPv9
/HCgsmEPRMNNzaOes7yfCZIrBQTZoq9ul3+Qa+szB9gKQnaBqvUJySSUIiZx/7LR
a3bLOGjEpjVCCJ47Ff+yuSclPSJ7Fz3wPAbwIZQHWeqI/6YMXoi2Jdotn3sayErJ
H4k48Dl2FS4qEMmsT3G7LRGMXgNiCrmIGmlakQLKuzs5R6HfkKmh+x1wREB8T2Dg
vi6ot2vXm4UPwT7IXdINWDxPM2W7FhgCyb++yvy/zBP0X94RQo7oMkQczDBq2X09
VPKVI0OKpeq4GIt/yLv+SSQi3+dAzWGs0ATHyXchbfBN9HXjD9FLhw1KF2l6EG35
ik3fsGh7Yf/bMdeEK8/iwxjrCCqhW2+5lxo+uQIDAQABo4G9MIG6MA4GA1UdDwEB
/wQEAwIFoDBPBgNVHSUESDBGBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMD
BggrBgEFBQcDBQYIKwYBBQUHAwYGCCsGAQUFBwMHBggrBgEFBQcDCTAfBgNVHSME
GDAWgBTyqhiedGNv+U2aiV/YfbHrlCWFKTA2BgNVHREELzAtgitncnBjY2xpZW50
LXN2Yy5ncnBjc2VydmVyLnN2Yy5jbHVzdGVyLmxvY2FsMA0GCSqGSIb3DQEBCwUA
A4ICAQDgalb7znLHUU+DHG5t/K4hrMXPKx1TdQYoWA7nFJhFIZP9zHA9Y0gEto98
hB3G24zmLfDyEfnW4d/QHJ6mRR8GVSCSBF3yEiDol2mTw69KaMiNuWp5LJ1MDmj+
6QbvVho/ubV9JPFmf60KDXdm28ofGfBZJJiOBehIIP+IC2uBe0X95thXCcfrs2UC
FlB/5qPFxR6Isjh5DC8wksAEbHDyy6CW0WQfeWcOFEOMtrRQ2nSIA3l5DFSBaHs0
D3ycOOzbIzCEC9F0MMF0+3ZE2NMP5a3rHfja+11G/R252PCwTDfsvIJrP3/9PzHe
GywL0wZgGQVxKMgDv5kfaSKnkx0Td4a5wG2EeIp4x35MifLWnjoBBKaYXIPgVi9g
jS8JnY1gGKQgyU4RQTMAXVornA0g18M46z1vky0iC+fA7vKsJybAxxRiqUzQOEZz
tCcQgWl/iVAy64oYRJMAl1DM7KnBmxUbF2gK+NH4oGya83jHyvjbsfY8yetdsmuL
8fetnrHPzIkmfchT6KHbZxUDL0AMYuk4M+cSysJ7vShdESYCjcgB3eHcanFV3om8
U38gmzhAuMNLMaeAFStObfVT7mCuui9t3kgf83xJYNW+hUHdrzr1Z5HYriyiSyZC
3QMtGMeNl+95G6i962Kb6y36tdU6klOixsK1+b08VXISpuXhdw==
-----END CERTIFICATE-----
`)
)

// var (
// 	//serverHostOverride = flag.String("server_host_override", "demo.kronml.dev", "The server name use to verify the hostname returned by TLS handshake")
// 	certFile = flag.String("cert", "..\\grpcclient.kronml.dev.crt", "A PEM eoncoded certificate file.")
// 	keyFile  = flag.String("key", "..\\grpcclient-key.pem", "A PEM encoded private key file.")
// 	caFile   = flag.String("CA", "..\\cert-chain.pem", "A PEM eoncoded CA's certificate file.")
// )

type tokenAuth struct {
	token string
}

func (t tokenAuth) GetRequestMetadata(ctx context.Context, in ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + t.token,
	}, nil
}

type basicAuth struct {
	username string
	password string
}

func (b basicAuth) GetRequestMetadata(ctx context.Context, in ...string) (map[string]string, error) {
	auth := b.username + ":" + b.password
	enc := base64.StdEncoding.EncodeToString([]byte(auth))
	return map[string]string{
		"authorization": "Basic " + enc,
	}, nil
}

func (basicAuth) RequireTransportSecurity() bool {
	return true
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func CreatePemKey() (certpem, keypem []byte) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	notBefore := time.Now()
	notAfter := notBefore.AddDate(1, 0, 0)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	// template.IPAddresses = append(template.IPAddresses, net.ParseIP("localhost"))
	template.IsCA = true
	derbytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	certpem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derbytes})
	keypem = pem.EncodeToMemory(pemBlockForKey(priv))
	return certpem, keypem
}

func loadTLSCredentials() (credentials.TransportCredentials, error) {
	// Load certificate of the CA who signed server's certificate
	pemServerCA, err := ioutil.ReadFile("tls.crt")
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemServerCA) {
		return nil, fmt.Errorf("failed to add server CA's certificate")
	}

	// Create the credentials and return it
	config := &tls.Config{
		RootCAs: certPool,
	}

	return credentials.NewTLS(config), nil
}

func main() {
	// flag.Parse()

	// // Load client cert
	// cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// // Load CA cert
	// caCert, err := ioutil.ReadFile(*caFile)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// caCertPool := x509.NewCertPool()
	// caCertPool.AppendCertsFromPEM(caCert)

	// creds := credentials.NewTLS(&tls.Config{
	// 	ServerName:   "demo.kronml.dev",
	// 	ClientAuth:   tls.RequireAndVerifyClientCert,
	// 	Certificates: []tls.Certificate{cert},
	// 	ClientCAs:    caCertPool,
	// 	//InsecureSkipVerify: true,
	// })

	/*	crt, key := CreatePemKey()
		certificate, err := tls.X509KeyPair(crt, key)
		if err != nil {
			fmt.Println(err)
		}

		certPool := x509.NewCertPool()
		ca, err := ioutil.ReadFile(*certFile)
		if err != nil {
			fmt.Println(err)
		}

		if ok := certPool.AppendCertsFromPEM(ca); !ok {
			fmt.Println("unable to append certificate")
		}

		creds := credentials.NewTLS(&tls.Config{
			ServerName:         "demo.kronml.dev",
			Certificates:       []tls.Certificate{certificate},
			RootCAs:            certPool,
			InsecureSkipVerify: true,
		})
	*/
	mr.Seed(time.Now().Unix())

	hostIP := os.Getenv("SERVER_CONN_STRING")
	if len(hostIP) <= 0 {
		log.Printf("\nHost IP is empty")
		hostIP = "demo.kronml.dev:443"
	}
	log.Printf("\nHost IP is %s", hostIP)

	// creds, err := loadTLSCredentials()
	// if err != nil {
	// 	log.Fatal("cannot load TLS credentials: ", err)
	// }

	flag.Parse()

	// Load client cert
	// cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	cert, err := tls.X509KeyPair(bundleCert, bundleKey)
	if err != nil {
		log.Printf("load peer cert/key error:%v", err)
		return
	}

	// Load CA cert
	// caCert, err := ioutil.ReadFile(*caFile)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	caCertPool := x509.NewCertPool()
	//caCertPool.AppendCertsFromPEM(caCert)
	caCertPool.AppendCertsFromPEM(bundleCAChain)

	// pemServerCA, err := ioutil.ReadFile("tls.crt")
	// if err != nil {
	// 	return
	// }

	rootcaCertPool := x509.NewCertPool()
	if !rootcaCertPool.AppendCertsFromPEM(bundleCAChain) {
		return
	}
	// if !rootcaCertPool.AppendCertsFromPEM(pemServerCA) {
	// 	return
	// }

	creds := credentials.NewTLS(&tls.Config{
		ServerName: "grpcserver-svc.grpcproxy.svc.cluster.local",
		//ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
		//ClientCAs:    caCertPool,
		RootCAs: rootcaCertPool,
		//InsecureSkipVerify: true,
	})

	// creds, err := credentials.NewClientTLSFromFile("grpcclient.kronml.dev.crt ", *serverHostOverride)
	// if err != nil {
	// 	log.Fatalf("can create credentials server %v", err)
	// }
	// dail server
	//conn, err := grpc.Dial(hostIP, grpc.WithInsecure())

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(creds))
	opts = append(opts, grpc.WithAuthority("grpcserver-svc.grpcproxy.svc.cluster.local"))
	opts = append(opts, grpc.WithPerRPCCredentials(basicAuth{username: "devidas", password: "pawar"}))
	//opts = append(opts, grpc.WithPerRPCCredentials(tokenAuth{token: token}))
	//opts = append(opts, grpc.WithInsecure())
	conn, err := grpc.Dial(hostIP, opts...)
	//conn, err = grpc.Dial(hostIP)
	if err != nil {
		log.Fatalf("can not connect with server %v", err)
	}

	// create stream
	client := pb.NewMathClient(conn)
	stream, err := client.Max(context.Background())
	if err != nil {
		log.Fatalf("openn stream error %v", err)
	}

	var max int32
	ctx := stream.Context()
	done := make(chan bool)

	// first goroutine sends random increasing numbers to stream
	// and closes int after 10 iterations
	go func() {
		for i := 1000; i < 1100; i++ {
			// generate random nummber and send it to stream
			rnd := int32(mr.Intn(i))
			req := pb.Request{Num: rnd}
			if err := stream.Send(&req); err != nil {
				log.Fatalf("can not send %v", err)
			}
			log.Printf("%d sent", req.Num)
			time.Sleep(time.Millisecond * 10)
		}
		if err := stream.CloseSend(); err != nil {
			log.Println(err)
		}
	}()

	// second goroutine receives data from stream
	// and saves result in max variable
	//
	// if stream is finished it closes done channel
	go func() {
		for {
			resp, err := stream.Recv()
			if err == io.EOF {
				close(done)
				return
			}
			if err != nil {
				log.Fatalf("can not receive %v", err)
			}
			log.Printf("--->Hostname -  %s", resp.Hostname)
			max = resp.Result
			log.Printf("--->new max %d received", max)
		}
	}()

	// third goroutine closes done channel
	// if context is done
	go func() {
		<-ctx.Done()
		time.Sleep(time.Millisecond * 1000)
		if err := ctx.Err(); err != nil {
			log.Println(err)
		}
		time.Sleep(time.Millisecond * 1000)
		close(done)
	}()

	<-done
	log.Printf("finished with max=%d", max)
}
