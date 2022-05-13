package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

var Reset = "\033[0m"
var Red = "\033[31m"
var Green = "\033[32m"

func ShortenValue(v string) string {
	if len(v) > 70 {
		return v[0:34] + ".." + v[len(v)-34:]
	}
	return v
}

func ShortenJson(v map[string]interface{}) map[string]interface{} {
	for k := range v {
		switch t := v[k].(type) {
		case map[string]interface{}:
			v[k] = ShortenJson(t)
		case string:
			if k != "method" {
				v[k] = ShortenValue(t)
			}
		case []interface{}:
			for i := range t {
				switch tp := t[i].(type) {
				case map[string]interface{}:
					t[i] = ShortenJson(tp)
				case string:
					t[i] = ShortenValue(tp)
				}
			}
			v[k] = t
		}
	}

	return v
}

func PrintJson(color string, rawJson []byte) {
	print := "[INVALID JSON] " + string(rawJson)
	var tmp map[string]interface{}
	err := json.Unmarshal(rawJson, &tmp)
	if err == nil {
		tmp = ShortenJson(tmp)
		b, err := json.MarshalIndent(tmp, "", "   ")
		if err == nil {
			print = string(b)
		}
	}

	Print(color, print)
}

func Print(color string, value string) {
	fmt.Println(
		color +
			"============= " + time.Now().Format("2006-01-02 15:04:05.999") +
			" =============\n\n" + value +
			"\n\n===================================================" +
			Reset,
	)
}

func main() {
	upstream := "http://localhost:8080/"
	if os.Getenv("UPSTREAM") != "" {
		upstream = os.Getenv("UPSTREAM")
	}
	clt := http.Client{}
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "POST" {
			Print(Red, "<Invalid request>")
			Print(Green, "<Method not allowed>")
			http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
			return
		}

		var requestBody bytes.Buffer
		io.Copy(&requestBody, req.Body)
		req.Body.Close()

		PrintJson(Red, requestBody.Bytes())

		upstreamReq, err := http.NewRequest(
			"POST",
			upstream,
			bytes.NewReader(requestBody.Bytes()),
		)
		if err != nil {
			Print(Green, fmt.Sprintf("<Internal server error>: %v", err))
			http.Error(
				w,
				"Internal server error",
				http.StatusInternalServerError,
			)
			return
		}
		resp, err := clt.Do(upstreamReq)
		if err != nil {
			Print(Green, fmt.Sprintf("<Internal server error>: %v", err))
			http.Error(
				w,
				"Internal server error",
				http.StatusInternalServerError,
			)
			return
		}
		for k, v := range resp.Header {
			for _, vv := range v {
				w.Header().Add(k, vv)
			}
		}
		w.WriteHeader(resp.StatusCode)

		var responseBody bytes.Buffer
		io.Copy(&responseBody, resp.Body)
		resp.Body.Close()
		PrintJson(Green, responseBody.Bytes())
		io.Copy(w, bytes.NewReader(responseBody.Bytes()))
	})
	port := int64(80)
	if os.Getenv("PORT") != "" {
		port, _ = strconv.ParseInt(os.Getenv("PORT"), 10, 64)
	}
	http.ListenAndServe(fmt.Sprintf(":%v", port), nil)
}
