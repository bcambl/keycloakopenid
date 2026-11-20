package main

import (
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
)

type pageData struct {
	Name        string
	User        string
	HasBearer   bool
	TokenClaims string
	OtherAppURL string
}

var page = template.Must(template.New("home").Parse(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>{{.Name}}</title></head>
<body>
<h1>Hello from {{.Name}}</h1>
<p>Authenticated user: <strong>{{if .User}}{{.User}}{{else}}not provided{{end}}</strong></p>
<p>Bearer token forwarded: {{.HasBearer}}</p>
<p><a href="{{.OtherAppURL}}">Open the other protected app</a></p>
{{if .TokenClaims}}<h2>Decoded token claims (display only; not verified)</h2><pre>{{.TokenClaims}}</pre>{{end}}
</body>
</html>`))

func main() {
	name := os.Getenv("APP_NAME")
	if name == "" {
		name = "helloworld"
	}

	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		data := pageData{
			Name:        name,
			User:        r.Header.Get("X-Forwarded-User"),
			HasBearer:   strings.HasPrefix(authorization, "Bearer "),
			OtherAppURL: os.Getenv("OTHER_APP_URL"),
		}
		if data.HasBearer {
			data.TokenClaims = decodeClaims(strings.TrimPrefix(authorization, "Bearer "))
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := page.Execute(w, data); err != nil {
			log.Printf("render page: %v", err)
		}
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func decodeClaims(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "Unable to decode token payload"
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "Unable to decode token payload"
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "Unable to decode token claims"
	}
	formatted, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		return "Unable to format token claims"
	}
	return string(formatted)
}
