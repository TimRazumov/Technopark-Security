package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"github.com/TimRazumov/Technopark-Security/app/common"
	"github.com/TimRazumov/Technopark-Security/app/db"
	"github.com/gorilla/mux"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
)

// TODO: move to config
const SelectLimit uint = 20
const DirBusterPath string = "/home/timofeyrazumov/go/src/github.com/TimRazumov/Technopark-Security/files/dicc.txt"

type Repeater struct {
	Store *db.RequestStore
}

func (repeater *Repeater) HandleGetRequests(w http.ResponseWriter, req *http.Request) {
	log.Println("HandleGetRequests for ", req.RequestURI)
	res, err := repeater.Store.Get(SelectLimit)
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
	log.Println("HandleRepeatRequest ", req.RequestURI)
	id, err := strconv.Atoi(mux.Vars(req)["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := repeater.Store.GetByID(id)
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

type Info struct {
	Status  int    `json:"status"`
	Path    string `json:"path"`
	Content string `json:"content"`
}

func (repeater *Repeater) HandleCheckRequest(w http.ResponseWriter, req *http.Request) {
	log.Println("HandleCheckRequest ", req.RequestURI)
	// get resp by id
	id, err := strconv.Atoi(mux.Vars(req)["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := repeater.Store.GetByID(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	resReq, err := res.GetHTTPRequest()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// open file
	file, err := os.Open(DirBusterPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// read file
	var info []Info
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		resReq.URL.Path = scanner.Text()
		log.Println("read path: ", resReq.URL.Path, ", make url: ", resReq.URL)
		resp, err := http.DefaultTransport.RoundTrip(resReq)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusNotFound {
			bodyBytes, _ := ioutil.ReadAll(resp.Body)
			info = append(info, Info{Status: resp.StatusCode, Path: resReq.URL.Path, Content: string(bodyBytes)})
		}
		resp.Body.Close()
	}
	if err := scanner.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// send answer
	body, _ := json.Marshal(info)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
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
