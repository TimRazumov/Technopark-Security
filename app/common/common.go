package common

import (
	"github.com/TimRazumov/Technopark-Security/app/db"
	"github.com/TimRazumov/Technopark-Security/app/models"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"io"
	"net"
	"net/http"
	"time"
)

func CreatePostgresDB() (*db.RequestStore, error) {
	postgresClient, err := gorm.Open("postgres",
		`host=localhost user=proxy_user password=proxy1234 dbname=proxy_db sslmode=disable`)
	if err != nil {
		return nil, err
	}
	postgresClient.DropTable(&models.Request{}) // WRN!
	postgresClient.AutoMigrate(&models.Request{})
	return &db.RequestStore{DB: postgresClient}, nil
}

func HandleTunneling(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
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
