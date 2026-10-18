package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// The test sentinel exposes no tools and writes only its disposable HOME journal.
func main() {
	if err := serve(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func serve() error {
	home := os.Getenv("HOME")
	if !filepath.IsAbs(home) || home == "/" {
		return fmt.Errorf("invalid fixture home")
	}
	journal, err := os.OpenFile(filepath.Join(home, "agy-mcp-probe.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer journal.Close()
	events := json.NewEncoder(journal)
	record := func(event string) error {
		return events.Encode(struct {
			Event string `json:"event"`
			PID   int    `json:"pid"`
		}{event, os.Getpid()})
	}
	if err := record("started"); err != nil {
		return err
	}
	input, output := json.NewDecoder(os.Stdin), json.NewEncoder(os.Stdout)
	for {
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Version string `json:"protocolVersion"`
			} `json:"params"`
		}
		if err := input.Decode(&request); err == io.EOF {
			return record("eof")
		} else if err != nil {
			return err
		}
		if len(request.ID) == 0 || string(request.ID) == "null" {
			continue
		}
		response := map[string]any{"jsonrpc": "2.0", "id": request.ID}
		switch request.Method {
		case "initialize":
			if request.Params.Version == "" {
				return fmt.Errorf("missing protocol version")
			}
			if err := record("initialize"); err != nil {
				return err
			}
			response["result"] = map[string]any{"protocolVersion": request.Params.Version, "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "mulgae-agy-sentinel", "version": "0.0.0"}}
		case "tools/list":
			if err := record("tools/list"); err != nil {
				return err
			}
			response["result"] = map[string]any{"tools": []any{}}
		default:
			response["error"] = map[string]any{"code": -32601, "message": "Method not found"}
		}
		if err := output.Encode(response); err != nil {
			return err
		}
	}
}
