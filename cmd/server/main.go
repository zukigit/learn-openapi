package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/zukigit/learn-openapi/api"
)

func main() {
	server := NewServer()

	strictHandler := api.NewStrictHandler(server, nil)
	mux := http.NewServeMux()
	api.HandlerFromMux(strictHandler, mux)

	addr := ":8080"
	fmt.Printf("Server listening on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
