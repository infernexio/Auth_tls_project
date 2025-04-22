package main

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	jarm "github.com/hdm/jarm-go"
	ja4 "github.com/exaring/ja4plus"
)

// fingerprintData holds the passive JA3/JA4 data per client.
type fingerprintData struct {
	JA3           string  `json:"ja3,omitempty"`
	JA3DurationMs float64 `json:"ja3_duration_ms,omitempty"`
	JA4           string  `json:"ja4,omitempty"`
}

var (
	// thread‑safe map for passive client data
	data   = make(map[string]fingerprintData)
	dataMu sync.RWMutex
)

// buildJA3 computes the MD5‑hex of the JA3 bare string.
func buildJA3(info *tls.ClientHelloInfo) string {
	ver := uint16(0)
	if len(info.SupportedVersions) > 0 {
		ver = info.SupportedVersions[0]
	}
	cs := make([]string, len(info.CipherSuites))
	for i, v := range info.CipherSuites {
		cs[i] = strconv.Itoa(int(v))
	}
	// infer extensions
	exts := []string{}
	addExt := func(id int) { exts = append(exts, strconv.Itoa(id)) }
	if info.ServerName != ""           { addExt(0) }
	if len(info.SupportedCurves) > 0   { addExt(10) }
	if len(info.SupportedPoints) > 0   { addExt(11) }
	if len(info.SignatureSchemes) > 0  { addExt(13) }
	if len(info.SupportedProtos) > 0   { addExt(16) }
	if len(info.SupportedVersions) > 0 { addExt(43) }

	cr := make([]string, len(info.SupportedCurves))
	for i, v := range info.SupportedCurves {
		cr[i] = strconv.Itoa(int(v))
	}
	pt := make([]string, len(info.SupportedPoints))
	for i, v := range info.SupportedPoints {
		pt[i] = strconv.Itoa(int(v))
	}

	bare := fmt.Sprintf("%d,%s,%s,%s,%s",
		ver,
		strings.Join(cs, "-"),
		strings.Join(exts, "-"),
		strings.Join(cr, "-"),
		strings.Join(pt, "-"),
	)
	sum := md5.Sum([]byte(bare))
	return hex.EncodeToString(sum[:])
}

// computeJARM actively scans YOUR server (localhost:8443) using the hdm/jarm-go library.
func computeJARM() (string, float64, error) {
	start := time.Now()
	host := "127.0.0.1"
	port := 8443

	probes := jarm.GetProbes(host, port)
	raws := make([]string, len(probes))

	for i, p := range probes {
		packet := jarm.BuildProbe(p)
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
		if err != nil {
			return "", 0, err
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write(packet)
		buf := make([]byte, 1500)
		n, _ := conn.Read(buf)
		conn.Close()

		raw, _ := jarm.ParseServerHello(buf[:n], p)
		raws[i] = raw
	}

	jarmHash := jarm.RawHashToFuzzyHash(strings.Join(raws, ","))
	return jarmHash, time.Since(start).Seconds() * 1000, nil
}

// computeSSLAnalyze performs a local TLS dial to your server and returns handshake details.
func computeSSLAnalyze() (map[string]any, float64, error) {
	start := time.Now()
	conn, err := tls.Dial("tcp", "localhost:8443", &tls.Config{
		InsecureSkipVerify: true, // for self‑signed
	})
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()

	dur := time.Since(start).Seconds() * 1000

	cs := conn.ConnectionState()
	cert := cs.PeerCertificates[0]

	info := map[string]any{
		"tls_version":     cs.Version,
		"cipher_suite":    cs.CipherSuite,
		"cert_subject":    cert.Subject.String(),
		"cert_issuer":     cert.Issuer.String(),
		"cert_not_before": cert.NotBefore,
		"cert_not_after":  cert.NotAfter,
	}

	return info, dur, nil
}

// mkHandler is a helper for the passive‑fingerprint endpoints.
func mkHandler(fn func(fingerprintData) any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		addr := r.RemoteAddr
		dataMu.RLock()
		d, ok := data[addr]
		dataMu.RUnlock()
		if !ok {
			http.Error(w, `{"error":"no data"}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(fn(d))
	}
}

func main() {
	// load or generate server.crt / server.key in this directory
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("failed to load cert/key: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			// PASSIVE: record JA3
			start := time.Now()
			ja3fp := buildJA3(info)
			dur3 := time.Since(start).Seconds() * 1000

			// PASSIVE: record JA4
			ja4fp := ja4.JA4(info)

			addr := info.Conn.RemoteAddr().String()
			dataMu.Lock()
			data[addr] = fingerprintData{JA3: ja3fp, JA3DurationMs: dur3, JA4: ja4fp}
			dataMu.Unlock()
			return nil, nil
		},
	}

	// HTML landing page
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		addr := r.RemoteAddr
		dataMu.RLock()
		seen := data[addr]
		dataMu.RUnlock()
		status := "No passive fingerprint yet. Make a fresh TLS request."
		if seen.JA3 != "" {
			status = "Passive fingerprint captured—see endpoints below."
		}
		fmt.Fprintf(w, `<!DOCTYPE html>
<html><body>
  <h1>TLS Fingerprint Server</h1>
  <p>Your address: %s</p>
  <p>%s</p>
  <ul>
    <li><a href="/ja3">/ja3</a></li>
    <li><a href="/ja4">/ja4</a></li>
    <li><a href="/ja3s">/ja3s</a></li>
    <li><a href="/ja4s">/ja4s</a></li>
    <li><a href="/jarm">/jarm</a></li>
    <li><a href="/jarm_s">/jarm_s</a></li>
    <li><a href="/sslanalyze">/sslanalyze</a></li>
    <li><a href="/sslanalyze_s">/sslanalyze_s</a></li>
  </ul>
</body></html>`, addr, status)
	})

	// Passive endpoints
	http.HandleFunc("/ja3", mkHandler(func(d fingerprintData) any { return map[string]string{"ja3": d.JA3} }))
	http.HandleFunc("/ja4", mkHandler(func(d fingerprintData) any { return map[string]string{"ja4": d.JA4} }))
	http.HandleFunc("/ja3s", mkHandler(func(d fingerprintData) any {
		return map[string]any{"ja3": d.JA3, "ja3_duration_ms": d.JA3DurationMs}
	}))
	http.HandleFunc("/ja4s", mkHandler(func(d fingerprintData) any {
		return map[string]any{"ja4": d.JA4, "ja4_duration_ms": d.JA3DurationMs}
	}))

	// Active JARM endpoints
	http.HandleFunc("/jarm", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		hash, _, err := computeJARM()
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"jarm": hash})
	})
	http.HandleFunc("/jarm_s", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		hash, dur, err := computeJARM()
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"jarm": hash, "jarm_duration_ms": dur})
	})

	// Active SSLAnalyze endpoints
	http.HandleFunc("/sslanalyze", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		info, _, err := computeSSLAnalyze()
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(info)
	})
	http.HandleFunc("/sslanalyze_s", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		info, dur, err := computeSSLAnalyze()
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		info["duration_ms"] = dur
		json.NewEncoder(w).Encode(info)
	})

	// Start HTTPS server
	server := &http.Server{Addr: ":8443", TLSConfig: tlsCfg}
	log.Println("Listening on https://0.0.0.0:8443/")
	log.Fatal(server.ListenAndServeTLS("", ""))
}
