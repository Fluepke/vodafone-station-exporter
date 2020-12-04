package main

import (
	"flag"
	"fmt"
	"github.com/fluepke/vodafone-station-exporter/collector"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"net/http"
	"os"
)

const version = "0.0.1"

var (
	showVersion             = flag.Bool("version", false, "Print version and exit")
	listenAddress           = flag.String("web.listen-address", "[::]:9420", "Address to listen on")
	metricsPath             = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics")
	vodafoneStationUrl      = flag.String("vodafone.station-url", "http://192.168.0.1", "Vodafone station URL. For bridge mode this is 192.168.100.1 (note: Configure a route if using bridge mode)")
	vodafoneStationPassword = flag.String("vodafone.station-password", "How is the default password calculated? mhmm", "Password for logging into the Vodafone station")
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Println("vodafone-station-exporter")
		fmt.Printf("Version: %s\n", version)
		fmt.Println("Author: @fluepke")
		fmt.Println("Prometheus Exporter for the Vodafone Station (CGA4233DE)")
		os.Exit(0)
	}

	startServer()
}

func startServer() {
	log.Infof("Starting vodafone-station-exporter (version %s)", version)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
            <head><title>vodafone-station-exporter (Version ` + version + `)</title></head>
            <body>
            <h1>vodafone-station-exporter</h1>
            <a href="/metrics">metrics</a>
            </body>
            </html>`))
	})
	http.HandleFunc(*metricsPath, handleMetricsRequest)

	log.Infof("Listening on %s", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}

func handleMetricsRequest(w http.ResponseWriter, request *http.Request) {
	registry := prometheus.NewRegistry()
	registry.MustRegister(&collector.Collector{
		Station: collector.NewVodafoneStation(*vodafoneStationUrl, *vodafoneStationPassword),
	})
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		ErrorLog:      log.NewErrorLogger(),
		ErrorHandling: promhttp.ContinueOnError,
	}).ServeHTTP(w, request)
}
