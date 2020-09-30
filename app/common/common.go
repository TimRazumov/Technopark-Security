package common

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"github.com/TimRazumov/Technopark-Security/app/db"
	"github.com/TimRazumov/Technopark-Security/app/models"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"time"
)

func CreatePostgresDB() (*db.RequestStore, error) {
	postgresClient, err := gorm.Open("postgres",
		`host=localhost user=proxy_user password=proxy1234 dbname=proxy_db sslmode=disable`)
	if err != nil {
		return nil, err
	}
	// postgresClient.DropTable(&models.Request{}) // WRN!
	postgresClient.AutoMigrate(&models.Request{})
	return &db.RequestStore{DB: postgresClient}, nil
}

type onCloseConn struct {
	net.Conn
	f func()
}

func (c *onCloseConn) Close() error {
	if c.f != nil {
		c.f()
		c.f = nil
	}
	return c.Conn.Close()
}

type oneShotListener struct {
	c net.Conn
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.c == nil {
		return nil, errors.New("closed on accept")
	}
	c := l.c
	l.c = nil
	return c, nil
}

func (l *oneShotListener) Close() error {
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	return l.c.LocalAddr()
}

func wrap(upstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream.ServeHTTP(w, r)
	})
}

func bigIntHash(n *big.Int) []byte {
	h := sha1.New()
	h.Write(n.Bytes())
	return h.Sum(nil)
}

func CreateKeyPair(commonName string) (certFile string, keyFile string, err error) {

	certFile = "certs/" + commonName + ".crt"
	keyFile = "certs/" + commonName + ".key"

	// Attempt to verify certs.
	if _, err = tls.LoadX509KeyPair(certFile, keyFile); err == nil {
		// Keys already in place
		return certFile, keyFile, nil
	}

	lastWeek := time.Now().AddDate(0, 0, -7)
	notBefore := lastWeek
	notAfter := lastWeek.AddDate(2, 0, 0)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"tim"},
			OrganizationalUnit: []string{"tim"},
			CommonName:         commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	if ip := net.ParseIP(commonName); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, commonName)
	}

	rootCA, err := tls.LoadX509KeyPair("ca.crt", "ca.key")
	if err != nil {
		return "", "", err
	}

	if rootCA.Leaf, err = x509.ParseCertificate(rootCA.Certificate[0]); err != nil {
		return "", "", err
	}

	template.AuthorityKeyId = rootCA.Leaf.SubjectKeyId

	var priv *rsa.PrivateKey
	if priv, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return "", "", err
	}
	template.SubjectKeyId = bigIntHash(priv.N)

	var derBytes []byte
	if derBytes, err = x509.CreateCertificate(rand.Reader, &template, rootCA.Leaf, &priv.PublicKey, rootCA.PrivateKey); err != nil {
		return "", "", err
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return "", "", err
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return "", "", err
	}

	//TODO нужно ли это
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", "", err
	}
	defer keyOut.Close()

	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return "", "", err
	}

	return certFile, keyFile, nil
}


func certificateLookupByName(name string) (*tls.Certificate, error) {
	cert, key, err := CreateKeyPair(name)
	if err != nil {
		return nil, err
	}

	var tlsCert tls.Certificate
	if tlsCert, err = tls.LoadX509KeyPair(cert, key); err != nil {
		return nil, err
	}

	return &tlsCert, nil
}

func HandleTunneling(w http.ResponseWriter, r *http.Request) {
	name, _, err := net.SplitHostPort(r.Host)
	var sTlsConn *tls.Conn
	if err != nil || name == "" {
		log.Println("cannot determine cert name for " + r.Host)
		http.Error(w, "no upstream", 503)
		return
	}

	// получить сертификат
	provisionalCert, err := certificateLookupByName(name)
	if err != nil {
		log.Println("cert", err)
		http.Error(w, "no upstream", http.StatusNotImplemented)
		return
	}

	sLocalTlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{*provisionalCert},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cLocalTlsConfig := &tls.Config{
				InsecureSkipVerify: true,
				ServerName: hello.ServerName,
			}
			sTlsConn, err = tls.Dial("tcp", r.Host, cLocalTlsConfig)
			if err != nil {
				log.Println("dial", r.Host, err)
				return nil, err
			}
			return certificateLookupByName(hello.ServerName)
		},
	}

	// получить соединение
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	cRawConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	if _, err = cRawConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n" +
		"Proxy-agent: Golang-Proxy\r\n" +
		"\r\n")); err != nil {
		log.Println("handshake", r.Host, err)
		cRawConn.Close()
		return
	}
	cTlsConn := tls.Server(cRawConn, sLocalTlsConfig)
	err = cTlsConn.Handshake()
	if err != nil {
		log.Println("handshake", r.Host, err)
		cTlsConn.Close()
		cRawConn.Close()
		return
	}
	defer cTlsConn.Close()

	if sTlsConn == nil {
		log.Println("could not determine cert name for " + r.Host)
		return
	}
	defer sTlsConn.Close()

	rp := &httputil.ReverseProxy{
		Director:      func (r *http.Request) {
							r.URL.Host = r.Host
							r.URL.Scheme = "https"
						},
		Transport:     &http.Transport{
			DialTLS: func (network, addr string) (net.Conn, error) {
						if sTlsConn == nil {
							return nil, errors.New("closed on dial")
						}
						return sTlsConn, nil
					},
		},
	}

	ch := make(chan int)
	wc := &onCloseConn{cTlsConn, func() { ch <- 0 }}
	http.Serve(&oneShotListener{wc}, wrap(rp))
	<-ch
}

func HandleHTTP(w http.ResponseWriter, req *http.Request) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	for name, values := range resp.Header {
		w.Header()[name] = values
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
