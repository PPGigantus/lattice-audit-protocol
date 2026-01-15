package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"lapverify/internal/lap"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  lapverify [--json] [--pretty] vectors <vectors_dir>\n")
	fmt.Fprintf(os.Stderr, "  lapverify [--json] [--pretty] audit-pack <zip_or_dir> [--require-invocations]\n")
	os.Exit(2)
}

type jsonFailure struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

type jsonVectors struct {
	OK       bool              `json:"ok"`
	Command  string            `json:"command"`
	Passed   int               `json:"passed"`
	Failed   int               `json:"failed"`
	Failures []lap.VectorFailure `json:"failures,omitempty"`
	Error    *jsonFailure      `json:"error,omitempty"`
}

type jsonAuditPack struct {
	OK                bool         `json:"ok"`
	Command           string       `json:"command"`
	Path              string       `json:"path"`
	RequireInvocations bool        `json:"require_invocations"`
	Error             *jsonFailure `json:"error,omitempty"`
}

func writeJSON(pretty bool, v any) {
	var b []byte
	var err error
	if pretty {
		b, err = json.MarshalIndent(v, "", "  ")
	} else {
		b, err = json.Marshal(v)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: JSON marshal: %v\n", err)
		os.Exit(1)
	}
	os.Stdout.Write(b)
	os.Stdout.Write([]byte("\n"))
}

func main() {
	if len(os.Args) < 3 {
		usage()
	}

	// Global flags that can appear anywhere before subcommand args.
	jsonOut := false
	pretty := false
	filtered := make([]string, 0, len(os.Args)-1)
	for _, a := range os.Args[1:] {
		switch a {
		case "--json":
			jsonOut = true
			continue
		case "--pretty":
			pretty = true
			continue
		}
		filtered = append(filtered, a)
	}
	if len(filtered) < 2 {
		usage()
	}

	cmd := filtered[0]
	switch cmd {
	case "vectors":
		dir := filtered[1]
		res, err := lap.VerifyVectorsDir(dir)
		if jsonOut {
			out := jsonVectors{OK: err == nil, Command: "vectors", Passed: res.Passed, Failed: res.Failed, Failures: res.Failures}
			if err != nil {
				out.Error = &jsonFailure{Code: lap.CodeOf(err), Detail: err.Error()}
			}
			writeJSON(pretty, out)
			if err != nil {
				os.Exit(1)
			}
			return
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v (passed=%d failed=%d)\n", err, res.Passed, res.Failed)
			os.Exit(1)
		}
		fmt.Printf("OK: passed=%d failed=%d\n", res.Passed, res.Failed)

	case "audit-pack":
		path := filtered[1]
		fs := flag.NewFlagSet("audit-pack", flag.ContinueOnError)
		requireInv := fs.Bool("require-invocations", false, "require invocations.json for commitment verification")
		_ = fs.Parse(filtered[2:])
		// Make relative paths deterministic when called from repo root
		path = filepath.Clean(path)
		err := lap.VerifyAuditPack(path, *requireInv)
		if jsonOut {
			out := jsonAuditPack{OK: err == nil, Command: "audit-pack", Path: path, RequireInvocations: *requireInv}
			if err != nil {
				out.Error = &jsonFailure{Code: lap.CodeOf(err), Detail: err.Error()}
			}
			writeJSON(pretty, out)
			if err != nil {
				os.Exit(1)
			}
			return
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("OK\n")
	default:
		usage()
	}
}
