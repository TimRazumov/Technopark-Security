package models

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
)

type Request struct {
	ID       uint   `json:"id" gorm:"primary_key"`
	Url      string `json:"url" gorm:"not null"`
	Method   string `json:"method" gorm:"not null"`
	Protocol string `json:"protocol" gorm:"not null"`
	Headers  string `json:"headers"`
	Body     string `json:"body"`
}

func (req *Request) GetHTTPRequest() (*http.Request, error) {
	httpReq, err := http.NewRequest(req.Method, req.Url, strings.NewReader(req.Body))
	if err != nil {
		return nil, err
	}
	httpReq.Proto = req.Protocol
	jsonMap := make(map[string][]string)
	if unmarshalErr := json.Unmarshal([]byte(req.Headers), &jsonMap); unmarshalErr != nil {
		return nil, unmarshalErr
	}
	for key, values := range jsonMap {
		for _, value := range values {
			httpReq.Header.Add(key, value)
		}
	}
	return httpReq, nil
}

func (req *Request) SetHTTPRequest(httpReq http.Request) error {
	req.Url = httpReq.RequestURI
	req.Method = httpReq.Method
	req.Protocol = httpReq.Proto
	tmp, err := json.Marshal(httpReq.Header)
	if err != nil {
		return err
	}
	req.Headers = string(tmp)
	buf := new(bytes.Buffer)
	if _, err = buf.ReadFrom(httpReq.Body); err != nil {
		return err
	}
	req.Body = buf.String()
	return nil
}

func (req *Request) TableName() string {
	return "requests"
}
