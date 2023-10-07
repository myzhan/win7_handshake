package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

var verbose bool
var hosts string

// cipher suites that supported by WIN7, by not supported by Go.
const (
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   uint16 = 0xc028
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384     uint16 = 0x009f
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256     uint16 = 0x009e
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA        uint16 = 0x0039
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA        uint16 = 0x0033
	TLS_RSA_WITH_AES_256_CBC_SHA256         uint16 = 0x003d
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 uint16 = 0xc024
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA256     uint16 = 0x006a
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA256     uint16 = 0x0040
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA        uint16 = 0x0038
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA        uint16 = 0x0032
	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA       uint16 = 0x0013
	TLS_RSA_WITH_RC4_128_MD5                uint16 = 0x0004
)

var WIN7_TLS12_CONFIG *tls.Config = &tls.Config{
	MinVersion: tls.VersionTLS12,
	MaxVersion: tls.VersionTLS12,
	CipherSuites: []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_RC4_128_SHA,
	},
}

func main() {
	hostList := strings.Split(hosts, ",")
	if hosts == "" || len(hostList) == 0 {
		flag.Usage()
		log.Fatalln("At least one host is needed")
	}

	hasError := false

	for _, h := range hostList {
		h = strings.ReplaceAll(h, "https://", "")
		h = strings.ReplaceAll(h, "http://", "")
		if !strings.Contains(h, ":") {
			h = h + ":443"
		}

		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", h, WIN7_TLS12_CONFIG)
		if err != nil {
			log.Printf("host:%s, handshake fails with error:%v", h, err)
			hasError = true
		} else {
			if verbose {
				log.Printf("host:%s, handshake successfully with cipher suite: %s\n", h, tls.CipherSuiteName(conn.ConnectionState().CipherSuite))
			}
			conn.Close()
		}
	}

	if hasError {
		os.Exit(1)
	}
}

func init() {
	flag.BoolVar(&verbose, "verbose", false, "Print more log, defaults to false.")
	flag.StringVar(&hosts, "hosts", "", "Hosts seperated by comma, like google:443,baidu.com:443, defaults to \"\"")
	flag.Usage = func() {
		fmt.Println("Supported flags:")
		flag.PrintDefaults()
	}
	flag.Parse()
}
