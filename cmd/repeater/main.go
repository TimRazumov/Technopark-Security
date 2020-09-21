package main

import (
	"crypto/tls"
	"encoding/json"
	"github.com/TimRazumov/Technopark-Security/app/common"
	"github.com/TimRazumov/Technopark-Security/app/db"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"strconv"
)

type Repeater struct {
	Store *db.RequestStore
}

func (repeater *Repeater) HandleGetRequests(w http.ResponseWriter, req *http.Request) {
	res, err := repeater.Store.GetByProtocol(req.Proto, 20)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	body, err := json.Marshal(res)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func (repeater *Repeater) HandleRepeatRequest(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := repeater.Store.GetByID(uint(id))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	resReq, err := res.GetHTTPRequest()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	common.HandleHTTP(w, resReq)
}

func (repeater *Repeater) HandleCheckRequest(w http.ResponseWriter, req *http.Request) {
	common.HandleHTTP(w, req)
}

func main() {
	store, err := common.CreatePostgresDB()
	if err != nil {
		log.Fatal(err)
	}
	defer store.DB.Close()

	repeater := Repeater{Store: store}
	router := mux.NewRouter()
	router.HandleFunc("/requests", repeater.HandleGetRequests)
	router.HandleFunc("/requests/{id:[0-9]+}", repeater.HandleRepeatRequest)
	router.HandleFunc("/requests/{id:[0-9]+}/check", repeater.HandleCheckRequest)

	server := &http.Server{
		Addr:         ":5051",
		Handler:      router,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	log.Fatal(server.ListenAndServe())
}
