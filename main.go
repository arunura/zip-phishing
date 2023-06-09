package main

import (
	"archive/zip"
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/fastly/compute-sdk-go/fsthttp"
)

//go:embed static/info.html
var info_html string

const (
	BASIC_SCHEMA string = "Basic "
)

func main() {

	fsthttp.ServeFunc(func(ctx context.Context, w fsthttp.ResponseWriter, r *fsthttp.Request) {
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
		}

		// Catch all other requests and return a 404.
		w.WriteHeader(fsthttp.StatusNotFound)
		fmt.Fprintf(w, "The page you requested could not be found\n")
	})
}
