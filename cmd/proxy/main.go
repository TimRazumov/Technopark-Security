package main

import (
	"crypto/tls"
	"github.com/TimRazumov/Technopark-Security/app/common"
	"github.com/TimRazumov/Technopark-Security/app/models"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"log"
	"net/http"
)

// TODO: move to config
const ProxyCertPath string = "files/server.pem"
const ProxyKeyPath string = "files/server.key"

func main() {
	store, err := common.CreatePostgresDB()
	if err != nil {
		log.Fatal(err)
	}
	defer store.DB.Close()

	server := &http.Server{
		Addr: ":5050",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var dbReq models.Request
			if err := dbReq.SetHTTPRequest(*req); err != nil {
				log.Println(err)
			}
			if err := store.Set(dbReq); err != nil {
				log.Println(err)
			}
			if req.Method == http.MethodConnect {
				log.Println("HandleTunneling for ", req.RequestURI)
				common.HandleTunneling(w, req)
			} else {
				log.Println("HandleHTTP for ", req.RequestURI)
				common.HandleHTTP(w, req)
			}
		}),
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	log.Fatal(server.ListenAndServe())
	// log.Fatal(server.ListenAndServeTLS(ProxyCertPath, ProxyKeyPath))
}
