package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/jaq-project/jaq/internal/acquire"
	"github.com/jaq-project/jaq/internal/app"
	"github.com/jaq-project/jaq/internal/evidence"
	invprocess "github.com/jaq-project/jaq/internal/investigator"
	peinfo "github.com/jaq-project/jaq/internal/pe"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "jaq:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: jaq <analyze|requests|approve|deny|resume> [options]")
	}
	if args[0] == "version" || args[0] == "--version" {
		fmt.Println("jaq", app.Version)
		return nil
	}
	if args[0] != "analyze" {
		if args[0] == "resume" {
			flags := flag.NewFlagSet("jaq resume", flag.ContinueOnError)
			runDir := flags.String("run", "", "absolute existing run directory")
			if err := flags.Parse(args[1:]); err != nil {
				return err
			}
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			results, err := acquire.Resume(ctx, *runDir)
			if err != nil {
				return err
			}
			for _, result := range results {
				fmt.Printf("JAQ request %s: %s\n", result.RequestID, result.Status)
				if result.ArtifactPath != "" {
					fmt.Println("Fetched artifact:", result.ArtifactPath, "sha256:", result.SHA256)
					if _, parseErr := peinfo.AnalyzeFile(result.ArtifactPath); parseErr == nil {
						root, rootErr := projectRoot()
						if rootErr != nil {
							return rootErr
						}
						controller, controllerErr := app.NewController(root)
						if controllerErr != nil {
							return controllerErr
						}
						childOutput := filepath.Join(filepath.Dir(result.ArtifactPath), "analysis")
						if analyzeErr := controller.Analyze(ctx, result.ArtifactPath, childOutput); analyzeErr != nil {
							return analyzeErr
						}
						provenance := fmt.Sprintf("{\"schema_version\":\"1.0\",\"parent_run\":%q,\"request_id\":%q,\"artifact_sha256\":%q}\n", *runDir, result.RequestID, result.SHA256)
						if writeErr := os.WriteFile(filepath.Join(childOutput, "parent-request.json"), []byte(provenance), 0o600); writeErr != nil {
							return writeErr
						}
						if recordErr := acquire.RecordChild(*runDir, result.RequestID, childOutput); recordErr != nil {
							return recordErr
						}
						fmt.Println("Child dossier:", childOutput)
					}
				}
			}
			return nil
		}
		if args[0] == "requests" {
			flags := flag.NewFlagSet("jaq requests", flag.ContinueOnError)
			runDir := flags.String("run", "", "absolute completed run directory")
			asJSON := flags.Bool("json", false, "print the complete request document as JSON")
			if err := flags.Parse(args[1:]); err != nil {
				return err
			}
			value, err := acquire.ReadRequests(filepath.Join(*runDir, "requests.json"))
			if err != nil {
				return err
			}
			if *asJSON {
				encoded, marshalErr := json.MarshalIndent(value, "", "  ")
				if marshalErr != nil {
					return marshalErr
				}
				fmt.Println(string(encoded))
				return nil
			}
			if len(value.ActionRequests) == 0 {
				fmt.Println("No action requests.")
				return nil
			}
			for index, item := range value.ActionRequests {
				if index > 0 {
					fmt.Println()
				}
				fmt.Printf("[%s] %s — %s\n", item.ID, item.Kind, item.Status)
				if targetURL, ok := item.Target["url"].(string); ok {
					fmt.Println("  Target:", targetURL)
				} else if target, marshalErr := json.Marshal(item.Target); marshalErr == nil {
					fmt.Println("  Target:", string(target))
				}
				fmt.Println("  Reason:", item.Reason)
				fmt.Println("  Requested:", strings.Join(item.RequestedObservations, ", "))
				fmt.Println("  Evidence:", strings.Join(item.EvidenceIDs, ", "))
				if item.Screening != nil {
					fmt.Println("  Screening:", item.Screening["verdict"])
					if reasons, err := json.Marshal(item.Screening["reason_codes"]); err == nil {
						fmt.Println("  Screening reasons:", string(reasons))
					}
				}
				if item.Execution != nil {
					fmt.Println("  Execution:", item.Execution["message"])
				}
			}
			return nil
		}
		if args[0] == "approve" || args[0] == "deny" {
			flags := flag.NewFlagSet("jaq "+args[0], flag.ContinueOnError)
			runDir := flags.String("run", "", "absolute completed run directory")
			requestID := flags.String("request", "", "pending action request ID")
			if err := flags.Parse(args[1:]); err != nil {
				return err
			}
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			var result acquire.ApprovalResult
			var err error
			if args[0] == "approve" {
				result, err = acquire.Approve(ctx, *runDir, *requestID)
			} else {
				result, err = acquire.Deny(*runDir, *requestID)
			}
			if err != nil {
				return err
			}
			fmt.Printf("JAQ request %s: %s\n", result.RequestID, result.Status)
			return nil
		}
		return fmt.Errorf("unknown command %q (expected analyze, requests, approve, deny, or resume)", args[0])
	}
	flags := flag.NewFlagSet("jaq analyze", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	sample := flags.String("sample", "", "absolute path to a Windows PE")
	output := flags.String("output", "", "directory for the evidence dossier")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *sample == "" || *output == "" {
		return errors.New("usage: jaq analyze --sample <absolute-path> --output <directory>")
	}
	if !filepath.IsAbs(*sample) {
		return errors.New("--sample must be an absolute path")
	}
	root, err := projectRoot()
	if err != nil {
		return err
	}
	controller, err := app.NewController(root)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := controller.Analyze(ctx, *sample, *output); err != nil {
		return err
	}
	absoluteOutput, _ := filepath.Abs(*output)
	fmt.Println("JAQ dossier written to", absoluteOutput)
	if manifest, err := evidence.ReadManifest(filepath.Join(absoluteOutput, "run-manifest.json")); err == nil {
		fmt.Println("Status:", manifest.Status)
		if manifest.Status == "partial" {
			fmt.Println("Analysis is incomplete; see report.md for retained findings and limitations.")
		}
	}
	return nil
}

func projectRoot() (string, error) {
	if configured := os.Getenv("JAQ_PROJECT_ROOT"); configured != "" {
		absolute, err := filepath.Abs(configured)
		if err != nil {
			return "", fmt.Errorf("resolve JAQ_PROJECT_ROOT: %w", err)
		}
		return absolute, nil
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return invprocess.FindProjectRoot(workingDirectory)
}
