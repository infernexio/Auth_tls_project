# TLS Fingerprinting Server and Collector

## Overview

This repository contains:
- A **Go** HTTPS server that passively captures JA3/JA4 fingerprints and actively computes JARM/SSLAnalyze.
- A **Python** client script that polls the server, collects fingerprint data, and generates analysis & visualizations.

## Prerequisites

- **Go** 1.18+ installed  
- **Python** 3.8+ installed  
- A POSIX‑compatible shell (bash, zsh, etc.)

## TLS Server Setup

1. **Create a self‑signed certificate:**
   ```bash
   openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key \
     -out server.crt -days 365 \
     -subj "/CN=localhost"
   ```

2. **Initialize and build the Go server:**
   ```bash
   cd path/to/go-server-directory
   go mod init tlsfingerprint
   go get github.com/hdm/jarm-go github.com/exaring/ja4plus
   go build -o tls-server main.go
   ```

3. **Run the server:**
   ```bash
   ./tls-server   # listens on https://0.0.0.0:8443/
   ```

## Python Collector Setup

1. **Install Python dependencies:**
   ```bash
   pip install requests httpx aiohttp urllib3 pandas numpy tqdm matplotlib
   ```

2. **Run the collector:**
   ```bash
   cd path/to/python-script-directory
   ./collector.py 127.0.0.1 --port 8443 --iterations 50 --output tls_data.json
   ```
   - Replace **127.0.0.1** and **8443** if your server IP or port differ.

## Workflow

1. Start the **Go** server (port 8443).  
2. Run the **Python** collector to gather fingerprints.  
3. The script will:
   - Poll all endpoints (`/ja3`, `/ja4`, `/jarm`, `/sslanalyze`, etc.)  
   - Save raw data and analysis to **tls_data.json**  
   - Generate CSV summaries and visualizations in **visualizations/**  

## Directory Structure

```
.
├── go-server/
│   ├── main.go
│   ├── server.crt
│   └── server.key
├── python-collector/
│   ├── collector.py
│   └── tls_data.json
└── README.md
```

## License

MIT © Sohail Shaik & Jason Calangi	 
