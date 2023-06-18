package main

import (
	"archive/zip"
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/fastly/compute-sdk-go/fsthttp"
	"github.com/fastly/compute-sdk-go/geo"
	"github.com/fastly/compute-sdk-go/rtlog"
)

//go:embed static/info.html
var info_html string

const (
	BASIC_SCHEMA string = "Basic "
)

type LogRecord struct {
	Timestamp            string   `json:"timestamp"`
	ClientIP             string   `json:"client_ip"`
	GeoData              *geo.Geo `json:"geo_data"`
	Host                 string   `json:"host"`
	Url                  string   `json:"url"`
	Referer              string   `json:"request_referer"`
	Method               string   `json:"request_method"`
	Protocol             string   `json:"request_protocol"`
	UserAgent            string   `json:"request_user_agent"`
	FastlyPop            string   `json:"fastly_pop"`
	FastlyServiceVersion string   `json:"fastly_service_version"`
	FastlyTraceId        string   `json:"fastly_trace_id"`
}

func main() {

	fsthttp.ServeFunc(func(ctx context.Context, w fsthttp.ResponseWriter, r *fsthttp.Request) {

		fmt.Fprintf(os.Stdout, "Request received at: %v\n", time.Now().UTC())
		err := log_request_to_bigquery(r)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error logging request to BigQuery: %v\n", err)
		}

		// Filter requests that have unexpected methods.
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" || r.Method == "DELETE" {
			w.WriteHeader(fsthttp.StatusMethodNotAllowed)
			fmt.Fprintf(w, "This method is not allowed\n")
			return
		}

		// If request is to the `/` path...
		if r.URL.Path == "/" {
			authzHeader := r.Header.Get("Authorization")
			var cred_str []byte = nil
			var err error = nil
			if strings.HasPrefix(authzHeader, BASIC_SCHEMA) {
				cred_str, err = base64.StdEncoding.DecodeString(authzHeader[len(BASIC_SCHEMA):])
				if err != nil {
					w.WriteHeader(fsthttp.StatusBadRequest)
					fmt.Fprintf(w, "Incorrect format for Basic Authorization\n")
					return
				}
			}

			readme_body := "This is a zip file downloaded from the dwnld.zip domain.\n\n"
			if cred_str != nil {
				readme_body += "The url the file was downloaded from: https://" + strings.TrimSuffix(string(cred_str), ":") + "@dwnld.zip\n\n"
				readme_body += "If you observe carefully, some of the '/' characters are replaced with '∕', which is a unicode character that look similar to a '/'.\n"
			}

			// Create zip file in memory
			buf := new(bytes.Buffer)
			zipWriter := zip.NewWriter(buf)

			// Add README.txt to zip file
			readme, err := zipWriter.Create("README.txt")
			if err != nil {
				w.WriteHeader(fsthttp.StatusInternalServerError)
				fmt.Fprintf(w, "Error creating zip file\n")
				return
			}
			_, err = readme.Write([]byte(readme_body))
			if err != nil {
				w.WriteHeader(fsthttp.StatusInternalServerError)
				fmt.Fprintf(w, "Error writing to zip file\n")
				return
			}

			// Add RTLO attack file to zip file
			rtlo_filename := "What_Type_Of_File_Is_This_pdf_or_" + "\u202E" + "fdp.txt"
			rtlo, err := zipWriter.Create(rtlo_filename)
			if err != nil {
				w.WriteHeader(fsthttp.StatusInternalServerError)
				fmt.Fprintf(w, "Error creating zip file\n")
				return
			}
			rtlo_body := "This is a text file employing the 'Right-to-Left Override Attack' to appear to be a PDF file on windows.\n"
			rtlo_body += "The file name contains a unicode char (u202E) which flips text right to left. The file name is set to be What_Type_Of_File_Is_This_pdf_or_[u202E]fdp.txt\n"
			rtlo_body += "On windows as the OS renders the unicode character correctly to flip the direction of subsequent characters, this file appears in Explorer as " + rtlo_filename + "\n"
			rtlo_body += "In this instance it was a txt file, but could easily be an exe with a PDF icon to complete the deception and perform a real attack.\n"
			_, err = rtlo.Write([]byte(rtlo_body))
			if err != nil {
				w.WriteHeader(fsthttp.StatusInternalServerError)
				fmt.Fprintf(w, "Error writing to zip file\n")
				return
			}

			err = zipWriter.Close()
			if err != nil {
				w.WriteHeader(fsthttp.StatusInternalServerError)
				fmt.Fprintf(w, "Error closing zip file\n")
				return
			}

			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Disposition", "attachment; filename=\"dwnld.zip\"")
			fmt.Fprintln(w, buf)
			return
		} else if r.URL.Path == "/info" {

			fsv := os.Getenv("FASTLY_SERVICE_VERSION")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintln(w, strings.ReplaceAll(info_html, "$fsv$", fsv))
			return
		} else if r.URL.Path == "/log" {
			log_record, err := construct_log_record(r)
			if err != nil {
				w.WriteHeader(fsthttp.StatusInternalServerError)
				fmt.Fprintf(w, "Error constructing log record: %v\n", err)
				return
			}

			json_log_record, err := json.Marshal(log_record)
			if err != nil {
				w.WriteHeader(fsthttp.StatusInternalServerError)
				fmt.Fprintf(w, "Error marshalling log record: %v\n", err)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			mw := io.MultiWriter(os.Stdout, w)
			fmt.Fprintln(mw, string(json_log_record))
			return
		}

		// Catch all other requests and return a 404.
		w.WriteHeader(fsthttp.StatusNotFound)
		fmt.Fprintf(w, "The page you requested could not be found\n")
	})
}

func log_request_to_bigquery(r *fsthttp.Request) error {
	log_record, err := construct_log_record(r)
	if err != nil {
		return err
	}

	json_log_record, err := json.Marshal(log_record)
	if err != nil {
		return err
	}

	endpoint := rtlog.Open("bigquery_website_usage_dwnld_zip")
	mw := io.MultiWriter(os.Stdout, endpoint)
	_, err = fmt.Fprintln(mw, string(json_log_record))
	return err
}

func construct_log_record(r *fsthttp.Request) (*LogRecord, error) {

	ip := net.ParseIP(r.RemoteAddr)
	g, err := geo.Lookup(ip)
	if err != nil {
		return nil, err
	}

	log_record := &LogRecord{
		Timestamp:            time.Now().UTC().Format("2006-01-02T15:04:05.000000Z"),
		ClientIP:             r.RemoteAddr,
		GeoData:              g,
		Host:                 r.Host,
		Url:                  r.URL.String(),
		Referer:              r.Header.Get("Referer"),
		Method:               r.Method,
		Protocol:             r.Proto,
		UserAgent:            r.Header.Get("User-Agent"),
		FastlyPop:            os.Getenv("FASTLY_POP"),
		FastlyServiceVersion: os.Getenv("FASTLY_SERVICE_VERSION"),
		FastlyTraceId:        os.Getenv("FASTLY_TRACE_ID"),
	}

	return log_record, nil
}
