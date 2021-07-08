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
	//serverHostOverride = flag.String("server_host_override", "demo.kronml.dev", "The server name use to verify the hostname returned by TLS handshake")
	certFile = flag.String("cert", "grpcclient.kronml.dev.crt", "A PEM eoncoded certificate file.")
	keyFile  = flag.String("key", "grpcclient-key.pem", "A PEM encoded private key file.")
	caFile   = flag.String("CA", "cert-chain.pem", "A PEM eoncoded CA's certificate file.")
)

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
	flag.Parse()

	// Load client cert
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatal(err)
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile(*caFile)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	creds := credentials.NewTLS(&tls.Config{
		//ServerName: "demo.kronml.dev",
		//ClientAuth:         tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		//InsecureSkipVerify: true,
	})

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

	// creds, err := credentials.NewClientTLSFromFile("grpcclient.kronml.dev.crt ", *serverHostOverride)
	// if err != nil {
	// 	log.Fatalf("can create credentials server %v", err)
	// }
	// dail server
	//conn, err := grpc.Dial(hostIP, grpc.WithInsecure())

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(creds))
	opts = append(opts, grpc.WithAuthority("demo.kronml.dev"))
	opts = append(opts, grpc.WithPerRPCCredentials(basicAuth{username: "devidas", password: "pawar"}))
	//opts = append(opts, grpc.WithPerRPCCredentials(tokenAuth{token: token}))
	//opts = append(opts, grpc.WithInsecure())
	conn, err := grpc.Dial(hostIP, opts...)
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
		for i := 1; i < 1010; i++ {
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
		if err := ctx.Err(); err != nil {
			log.Println(err)
		}
		close(done)
	}()

	<-done
	log.Printf("finished with max=%d", max)
}
