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
	bundleCAChainProxy = []byte(`
-----BEGIN CERTIFICATE-----
MIIFVzCCAz+gAwIBAgIUMjdm72PDwblqLPUulUU7w/z/vG4wDQYJKoZIhvcNAQEL
BQAwIjEOMAwGA1UECgwFSXN0aW8xEDAOBgNVBAMMB1Jvb3QgQ0EwHhcNMjEwNzI3
MDUyMDI0WhcNMjMwNzI3MDUyMDI0WjA+MQ4wDAYDVQQKDAVJc3RpbzEYMBYGA1UE
AwwPSW50ZXJtZWRpYXRlIENBMRIwEAYDVQQHDAlncnBjcHJveHkwggIiMA0GCSqG
SIb3DQEBAQUAA4ICDwAwggIKAoICAQDVNlBuh/6pZEezjsQ7SwaaBkQgPDDA4xP1
PGvq+7Re4T/NFIngAZboB4nJsW6x/9v1VrJurtCkB7+s2mnPpSQ3qq8LCpK8JkV2
IRDlc7umAkYHyfQQd2JXfFQm3yXBJseJa6QfJSJehTBER/kr8GpDz1y0Yik0Fu0A
VdDmJUi5UlIzldbv38pjho9WtWlT/4Rxvz2LovxMb+AtIYRjnYgSJuVLOXWth6sP
GRf8QHlkTIXh3VsiCPS4qPX6rqcAmWljUdbYruxCIzIqsYJ9EMBVaid1xdowp7sW
3bDeumpZ/IgPj3sHKbmJGjO22H0gqKjztVXQVmgQlAxUBQV3V1ZsMDWfL4jytsvX
uf8t4nEmajqUkN4xOfYYJ6AJgYUim4tDMWymG6Q2h3wQWuoFx+93rhxnWs7eIz0Q
6W7uBN5o4uiP9zuKQsmqNgH8GFiMc/6BYceCsWeN4kMEErJ0I47/14VOTMFlu0ZX
kwCegEwRl7cgntWKJF/nGiYJ4Qz8Ij7RgbRfzvZlqKcHlwjCKryW2MW+/668uAjq
EI+s0mDY2elEUJe0Jv1z/C7nKJnGFXFKcTVrh+2oozlY/nA+7L904NybbFK7qedL
S75O2KH1ENzwtEO+J6RgEFBug8oHsmehKo300oE4pS1OHf6J9xKxMVrIim7QnrK7
HffOJbgglQIDAQABo2kwZzAdBgNVHQ4EFgQUzVL/PxhPkJRV+7gv4+JHganAHYUw
EgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAuQwIgYDVR0RBBswGYIX
aXN0aW9kLmlzdGlvLXN5c3RlbS5zdmMwDQYJKoZIhvcNAQELBQADggIBAD7bWgbT
A5JkvH3FlAXSJQR/el8efWxST1Q3IGDo90c5M/wpYRjPxadbpJx1gm7Zk8y8J1HF
9WVjBBE8AYldE8ioajhlD2X/bWxMP0E6yaGoHigu79CVJPn/XtXNL7E+2Ss5tOhH
ce6kTtSEQDUHylZFlM9QJRwfDdTGWgeVQaMTywtSlJNnnOhp/dYsJgW1L0zUTNfs
uGqR2g0Mg8PeMomAYtSOvghGolb5jkAY2To431DDNRDeFpMzGuEsxkk7aBM9Grz3
tbyIsM4deSY20qLa+xngvgB5PbosXFfAf1Qfl7uKL0VUT0msRaqr9OySKjiS8W52
6PMrLhYAmihAWCx4OOuPvtZAeM9XtYkI1gjVafNj5vEoedMgYqxRBYrW28KrwSDs
aRv5QNXMHlqKEFZQQBeYEsr5LcSG/2gBXfx4vc5BvDM0S76aO2OO+vzUdynh9f2N
OAKiuTnj5/W0OkpgIbggYGjx9UanWZTgVvhrftgyM/99gRYSlsi3hfqzGdECx3HN
ey/sJ4hL43Z8to4zYQoEk6OX287ZPma/b5afQS0DMhWAYkcrOA0s1Jfqq0roSiXW
lMG/1Gub+aS7Bu5vfBWDoCfBPNyfBKMhg/vFo92dNBvoqk+eJaoMa7yD65jAbLfQ
I32eVV2YAzJbhFqlmvlmQe+isKhx+Q2I3AAc
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFFDCCAvygAwIBAgIUPe5vGL491gww2lFCWCMr7qOTttwwDQYJKoZIhvcNAQEL
BQAwIjEOMAwGA1UECgwFSXN0aW8xEDAOBgNVBAMMB1Jvb3QgQ0EwHhcNMjEwNzI2
MTMwMzExWhcNMzEwNzI0MTMwMzExWjAiMQ4wDAYDVQQKDAVJc3RpbzEQMA4GA1UE
AwwHUm9vdCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMkruVxa
urvb0NO0qmoNpayoITkjrc+qzdDkayfAeSB+/TXuomNbW3po02lGoElNOifXGGTh
sAkGSDzXfPgw7imwyxrASLAlC+STLDEZn8iEVeHEt7Ji04ob63DqmQnUIzr4F6qq
U6TUalsePoDyEe4/XkzRJWgaUns18gP48KBVvuuIpdd6UoEjrF4NrnbOM4LiSVgo
4NMhZ7KcyET/K2/8QeOonpvsS5tRmrYAg9U8RIS8MqAtBjpsfxf9nWiaRUBIRzzE
rcChwA7OEmBMk753KTUw5vS0l8/ocU1Pts25AZ2NOvPdiVOCgj21QXOzmlDgpMEQ
0gPjEjtgrXS2kSXWgI0dtcFQ+VZOoWo6s4Dj/XVJYKvqwGgwhAfXdxuxh3MiTRss
Ykfp77v3F7vvjcR3VPQYQn+A0vDsY0lya/NoLVymTKTAEM8o9RSFokqMgwPxHVrY
863tE316rljYV3iMzhsdBt4E5EjSSKVnlbn68/BThbvpbO3TwOpzNvOyPAeCBOCE
0NRmJFv0v1e1NjqHBao/V1bQL1zDVzAC8QN/HzsSH65sTXQ5ueI6URILi0t5lgO6
MyK5DkApV/5WpQPKY0SPeJSL9P1gEYBQ5CP8FVwT8XPRzwcreROJLENE1nc6LICp
Zhd4UI3gZDSztohOm2TQ+ADSWLllKyV26VtLAgMBAAGjQjBAMB0GA1UdDgQWBBT8
YMPOg/orOVjwJ1ugqzObrFe6ZzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE
AwIC5DANBgkqhkiG9w0BAQsFAAOCAgEAQDdYVQ1cw9mUvghVAvxfbTHGl8c4V9fn
Vh+LsKd4jVnccP1NgSwwIo3wAfQlOZSNFbTWR1fSQ8CVPjxUGELLykOD6bJPxMG3
dMlsfD5zj/m7hHt/dkOXGeavRZg9PSAF/XEY9Z72vjp7M2ZtTg5EePBcZu6wqRR/
YlBIaSXMiEHyY0Z3qURsL9ndsWvcVR+oekuGHNqKi2BtrbTXuzQrWiF4H0DT+fnr
ryh43gA6aWahE+NaIr4GpbCcsAV3YHLf7LAKqBhiEbB4XqLMQV8tUuMK9ckERPEW
mjf8vceC1VNDdPyaaoCCMffnxiajZnasxQGaomC7tmsBYzpqs2aL6jNGn1IbR0WY
HUntMHQfT246KeBDpv4Zpd9OZrnRn+vwm39WRLNrb3cxLQ/3qpzN8ZfZBCxPCD2b
St+Cb+b3/84ikzFeBxVMTEDJ0m3+AOKAFArWOtVtgxnB3quHKtIG7IdLXSXY+Ns8
nmw/K80/Wnsn6XL3ofQJ8rZbXE/AtU6OIVN2/SxIGGoC5OY6dEAxytW7eOS5SbVS
tPN5PxflvChS8z6NMQwuL1txoUGDMTq9vPM9srwhYIV8UrTm9YsPA84UgfVO/5Az
hgWwKqlHqXILptA1n3OOYJ4C0DgKUZblhq9HyT/wbvC7Re1zv9hEouW6aq8n7LqA
0Tmu6CMJ7vo=
-----END CERTIFICATE-----
`)

	bundleKeyProxy = []byte(`
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`)

	bundleCertProxy = []byte(`
-----BEGIN CERTIFICATE-----
MIIF7zCCA9egAwIBAgIUcuUlMqtGfSXNSbaFAsRyqgESOKowDQYJKoZIhvcNAQEL
BQAwPjEOMAwGA1UECgwFSXN0aW8xGDAWBgNVBAMMD0ludGVybWVkaWF0ZSBDQTES
MBAGA1UEBwwJZ3JwY3Byb3h5MB4XDTIxMDcyNzA2MDAyNloXDTIyMDcyNzA2MDAz
MVowZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRUwEwYDVQQKEwxrcm9ubWws
IEluYy4xMzAxBgNVBAMTKmdycGNjbGllbnQtc3ZjLmdycGNwcm94eS5zdmMuY2x1
c3Rlci5sb2NhbDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJx3Ck8v
o4W+Mk9GOjPCZPy4yKh8pD/i5JN4OStd4V3Mb+/y9tt5PhZxUokC2gvEGCSLoxbu
ppFHTlFeytLv9N2GlJSv53j2Qb5p/4Eg8xpjbqU/vM+evlT39oUmdH7/Co1/bVj4
Qkkvq3OJjdSMCqNcbUGhu9IYlYfn9pEQorD4e+i+uLldr1YMwRINZk2LHLT54ztP
zhpLUqVUt72CBhLnzn037DpeYZjHT5ko/FVqsfHhUZZeX9jy7acjIz4z1BEia3wV
rD4etmFLv5G539jrK0UGp/DN9EN70C2Cz9ta1ROkn5CysmYmtlqJINr+ayYU/4rA
In0lAFEln/tQBGXlq+TIVytzxW8kO7awgf2EG5ycRP6IMiOU9z7l/1eL3y7fe5aV
DsHRv6Kkz5lYJw3EzMU21hwqshNDJptUy5Pnp9t/wHQtXLsbYSzEZK7wOMHNOEiq
CnAdwlpTnKprHDm+5fDHnTiRXYP/wX4KcJAiv6ZUxjRNjwdwlHy6mI27W4WwafYr
JK6GQsXe1qfPuNMNG0tfh2r4MDhel1ynyoxabN1ahUhHYjS51akoaQPBesh94kDN
KGcnaQQnQZN4FQTiS9uvLHuYMcmCF/B68KhDMzL9F21B1Xj4Hevl7dg8Re5KJCuf
TUYC5AeDXjwH3Ss6mYZ4i3kYxCDjKYUi/ml3AgMBAAGjgbwwgbkwDgYDVR0PAQH/
BAQDAgWgME8GA1UdJQRIMEYGCCsGAQUFBwMBBggrBgEFBQcDAgYIKwYBBQUHAwMG
CCsGAQUFBwMFBggrBgEFBQcDBgYIKwYBBQUHAwcGCCsGAQUFBwMJMB8GA1UdIwQY
MBaAFM1S/z8YT5CUVfu4L+PiR4GpwB2FMDUGA1UdEQQuMCyCKmdycGNjbGllbnQt
c3ZjLmdycGNwcm94eS5zdmMuY2x1c3Rlci5sb2NhbDANBgkqhkiG9w0BAQsFAAOC
AgEAqtYP3Wzn7QAGTslAVwngIezY3foWPOjNjXOg6nrFQ/9gfCIxarq/udBACkpm
Oknh+9QX5mZlokkZia8gEQc6nJcG+DPM3unhp8bIzF8WuB90L2lV8jyPqlXW+Iiz
4fQOfAYTY3AAJUZxnPGP7NBT/YU/ZVDYr2O6bqk6PVP+yNKkK2U5fz6VPFEIErAi
dtq07SOItI+kparg9TtJUK9Pwh0aEgaP3gpBIW5G3LwNUU1CLWc5MGe/UxSCzOd/
avORjMi1+Y45yEtRvckdkr6iNyYo9RDg5+zI+DNPjznE3ciWeXN7QxocgdHJbbdH
Gc1oPMErLageKIOUSsaczOgpUFof8Ickw0CEPWp+QJME9CvzTlFPvgBdB0zLprTp
a/27ZD6xkGJUa+OHBKfRD4ODzUtAv3rkxUpi0+s1bxxcOYrAf59Cd3wAfNiC62eO
bk7vWxCeiC4hYdGeb851ofnFdmb64LtIisD6zpOZmXS8zXR52TzZGmf9+HBtAny4
p1h3/VWBAt72mZQOjCyyYOUpVw2/mSv7vBO6xtbxsJlK6bLnFjffe/qOXMsUlPmW
LsOXhQyEQQbiNO52AemHWUoO8+HMEMkBhECdPe/90tY4sy6do4vCVPfZF85QAUh+
pBbWetQ3y3lneMZR8ATZt8spa4Ut/zDtlvgGJXJUIvpFVPI=
-----END CERTIFICATE-----
`)

	bundleCAChainServer = []byte(`
-----BEGIN CERTIFICATE-----
MIIFVzCCAz+gAwIBAgIUMjdm72PDwblqLPUulUU7w/z/vG4wDQYJKoZIhvcNAQEL
BQAwIjEOMAwGA1UECgwFSXN0aW8xEDAOBgNVBAMMB1Jvb3QgQ0EwHhcNMjEwNzI3
MDUyMDI0WhcNMjMwNzI3MDUyMDI0WjA+MQ4wDAYDVQQKDAVJc3RpbzEYMBYGA1UE
AwwPSW50ZXJtZWRpYXRlIENBMRIwEAYDVQQHDAlncnBjcHJveHkwggIiMA0GCSqG
SIb3DQEBAQUAA4ICDwAwggIKAoICAQDVNlBuh/6pZEezjsQ7SwaaBkQgPDDA4xP1
PGvq+7Re4T/NFIngAZboB4nJsW6x/9v1VrJurtCkB7+s2mnPpSQ3qq8LCpK8JkV2
IRDlc7umAkYHyfQQd2JXfFQm3yXBJseJa6QfJSJehTBER/kr8GpDz1y0Yik0Fu0A
VdDmJUi5UlIzldbv38pjho9WtWlT/4Rxvz2LovxMb+AtIYRjnYgSJuVLOXWth6sP
GRf8QHlkTIXh3VsiCPS4qPX6rqcAmWljUdbYruxCIzIqsYJ9EMBVaid1xdowp7sW
3bDeumpZ/IgPj3sHKbmJGjO22H0gqKjztVXQVmgQlAxUBQV3V1ZsMDWfL4jytsvX
uf8t4nEmajqUkN4xOfYYJ6AJgYUim4tDMWymG6Q2h3wQWuoFx+93rhxnWs7eIz0Q
6W7uBN5o4uiP9zuKQsmqNgH8GFiMc/6BYceCsWeN4kMEErJ0I47/14VOTMFlu0ZX
kwCegEwRl7cgntWKJF/nGiYJ4Qz8Ij7RgbRfzvZlqKcHlwjCKryW2MW+/668uAjq
EI+s0mDY2elEUJe0Jv1z/C7nKJnGFXFKcTVrh+2oozlY/nA+7L904NybbFK7qedL
S75O2KH1ENzwtEO+J6RgEFBug8oHsmehKo300oE4pS1OHf6J9xKxMVrIim7QnrK7
HffOJbgglQIDAQABo2kwZzAdBgNVHQ4EFgQUzVL/PxhPkJRV+7gv4+JHganAHYUw
EgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAuQwIgYDVR0RBBswGYIX
aXN0aW9kLmlzdGlvLXN5c3RlbS5zdmMwDQYJKoZIhvcNAQELBQADggIBAD7bWgbT
A5JkvH3FlAXSJQR/el8efWxST1Q3IGDo90c5M/wpYRjPxadbpJx1gm7Zk8y8J1HF
9WVjBBE8AYldE8ioajhlD2X/bWxMP0E6yaGoHigu79CVJPn/XtXNL7E+2Ss5tOhH
ce6kTtSEQDUHylZFlM9QJRwfDdTGWgeVQaMTywtSlJNnnOhp/dYsJgW1L0zUTNfs
uGqR2g0Mg8PeMomAYtSOvghGolb5jkAY2To431DDNRDeFpMzGuEsxkk7aBM9Grz3
tbyIsM4deSY20qLa+xngvgB5PbosXFfAf1Qfl7uKL0VUT0msRaqr9OySKjiS8W52
6PMrLhYAmihAWCx4OOuPvtZAeM9XtYkI1gjVafNj5vEoedMgYqxRBYrW28KrwSDs
aRv5QNXMHlqKEFZQQBeYEsr5LcSG/2gBXfx4vc5BvDM0S76aO2OO+vzUdynh9f2N
OAKiuTnj5/W0OkpgIbggYGjx9UanWZTgVvhrftgyM/99gRYSlsi3hfqzGdECx3HN
ey/sJ4hL43Z8to4zYQoEk6OX287ZPma/b5afQS0DMhWAYkcrOA0s1Jfqq0roSiXW
lMG/1Gub+aS7Bu5vfBWDoCfBPNyfBKMhg/vFo92dNBvoqk+eJaoMa7yD65jAbLfQ
I32eVV2YAzJbhFqlmvlmQe+isKhx+Q2I3AAc
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFFDCCAvygAwIBAgIUPe5vGL491gww2lFCWCMr7qOTttwwDQYJKoZIhvcNAQEL
BQAwIjEOMAwGA1UECgwFSXN0aW8xEDAOBgNVBAMMB1Jvb3QgQ0EwHhcNMjEwNzI2
MTMwMzExWhcNMzEwNzI0MTMwMzExWjAiMQ4wDAYDVQQKDAVJc3RpbzEQMA4GA1UE
AwwHUm9vdCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMkruVxa
urvb0NO0qmoNpayoITkjrc+qzdDkayfAeSB+/TXuomNbW3po02lGoElNOifXGGTh
sAkGSDzXfPgw7imwyxrASLAlC+STLDEZn8iEVeHEt7Ji04ob63DqmQnUIzr4F6qq
U6TUalsePoDyEe4/XkzRJWgaUns18gP48KBVvuuIpdd6UoEjrF4NrnbOM4LiSVgo
4NMhZ7KcyET/K2/8QeOonpvsS5tRmrYAg9U8RIS8MqAtBjpsfxf9nWiaRUBIRzzE
rcChwA7OEmBMk753KTUw5vS0l8/ocU1Pts25AZ2NOvPdiVOCgj21QXOzmlDgpMEQ
0gPjEjtgrXS2kSXWgI0dtcFQ+VZOoWo6s4Dj/XVJYKvqwGgwhAfXdxuxh3MiTRss
Ykfp77v3F7vvjcR3VPQYQn+A0vDsY0lya/NoLVymTKTAEM8o9RSFokqMgwPxHVrY
863tE316rljYV3iMzhsdBt4E5EjSSKVnlbn68/BThbvpbO3TwOpzNvOyPAeCBOCE
0NRmJFv0v1e1NjqHBao/V1bQL1zDVzAC8QN/HzsSH65sTXQ5ueI6URILi0t5lgO6
MyK5DkApV/5WpQPKY0SPeJSL9P1gEYBQ5CP8FVwT8XPRzwcreROJLENE1nc6LICp
Zhd4UI3gZDSztohOm2TQ+ADSWLllKyV26VtLAgMBAAGjQjBAMB0GA1UdDgQWBBT8
YMPOg/orOVjwJ1ugqzObrFe6ZzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE
AwIC5DANBgkqhkiG9w0BAQsFAAOCAgEAQDdYVQ1cw9mUvghVAvxfbTHGl8c4V9fn
Vh+LsKd4jVnccP1NgSwwIo3wAfQlOZSNFbTWR1fSQ8CVPjxUGELLykOD6bJPxMG3
dMlsfD5zj/m7hHt/dkOXGeavRZg9PSAF/XEY9Z72vjp7M2ZtTg5EePBcZu6wqRR/
YlBIaSXMiEHyY0Z3qURsL9ndsWvcVR+oekuGHNqKi2BtrbTXuzQrWiF4H0DT+fnr
ryh43gA6aWahE+NaIr4GpbCcsAV3YHLf7LAKqBhiEbB4XqLMQV8tUuMK9ckERPEW
mjf8vceC1VNDdPyaaoCCMffnxiajZnasxQGaomC7tmsBYzpqs2aL6jNGn1IbR0WY
HUntMHQfT246KeBDpv4Zpd9OZrnRn+vwm39WRLNrb3cxLQ/3qpzN8ZfZBCxPCD2b
St+Cb+b3/84ikzFeBxVMTEDJ0m3+AOKAFArWOtVtgxnB3quHKtIG7IdLXSXY+Ns8
nmw/K80/Wnsn6XL3ofQJ8rZbXE/AtU6OIVN2/SxIGGoC5OY6dEAxytW7eOS5SbVS
tPN5PxflvChS8z6NMQwuL1txoUGDMTq9vPM9srwhYIV8UrTm9YsPA84UgfVO/5Az
hgWwKqlHqXILptA1n3OOYJ4C0DgKUZblhq9HyT/wbvC7Re1zv9hEouW6aq8n7LqA
0Tmu6CMJ7vo=
-----END CERTIFICATE-----
`)

	bundleKeyServer = []byte(`
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`)

	bundleCertServer = []byte(`
-----BEGIN CERTIFICATE-----
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
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
	cert, err := tls.X509KeyPair(bundleCertProxy, bundleKeyProxy)
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
	caCertPool.AppendCertsFromPEM(bundleCAChainProxy)

	// pemServerCA, err := ioutil.ReadFile("tls.crt")
	// if err != nil {
	// 	return
	// }

	rootcaCertPool := x509.NewCertPool()
	if !rootcaCertPool.AppendCertsFromPEM(bundleCAChainProxy) {
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
	opts = append(opts, grpc.WithAuthority("grpcserver-svc.grpcserver.svc.cluster.local"))
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
		for i := 1; i < 1100; i++ {
			// generate random nummber and send it to stream
			rnd := int32(mr.Intn(i))
			req := pb.Request{Num: rnd}
			if err := stream.Send(&req); err != nil {
				log.Fatalf("can not send %v", err)
			}
			log.Printf("%d sent", req.Num)
			time.Sleep(time.Millisecond * 1000)
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
