package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	// Load certificate and key from a folder
	certFile := "cert.pem"
	keyFile := "key.pem"
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		fmt.Println("Error loading certificate and key:", err)
		return
	}

	// Configure TLS client
	// pool := x509.NewCertPool()
	// pool.AddCert()
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            x509.NewCertPool(),
		InsecureSkipVerify: true,
	}

	// Dial TLS connection to localhost:9090
	//conn, err := tls.Dial("tcp", "localhost:9090", tlsConfig)
	//if err != nil {
	//	fmt.Println("Error dialing TLS connection:", err)
	//	return
	//}
	// Create an HTTP client with the custom TLS configuration
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	// Send HTTPS request
	url := "https://localhost:9090"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTPS request:", err)
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	fmt.Println("Response Body:", string(body))
	//
	//// defer conn.Close()
	//
	//// Send data over the TLS connection
	//message := "Hello, TLS Server!"
	//n, err := conn.Write([]byte(message))
	//if err != nil {
	//	fmt.Println("Error sending data:", err)
	//	return
	//}
	//fmt.Printf("Sent %d bytes: %s\n", n, message)
	//
	//// Read response from the TLS connection
	//buffer := make([]byte, 1024)
	//n, err = conn.Read(buffer)
	//if err != nil {
	//	if err != io.EOF {
	//		fmt.Println("Error reading response:", err)
	//	}
	//	return
	//}
	//response := string(buffer[:n])
	//fmt.Printf("Received %d bytes: %s\n", n, response)
}
