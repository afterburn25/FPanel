package main

import (
	"encoding/json"
	"flag"
	"os"
	"privora.local/panel/agent/internal/hostadapter"
)

func main() {
	var cert string
	flag.StringVar(&cert, "cert", "", "certification evidence path")
	flag.Parse()
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{"capabilities": hostadapter.New(hostadapter.Config{CertificationPath: cert}).Probe()})
}
