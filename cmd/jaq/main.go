package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/jaq-project/jaq/internal/app"
	invprocess "github.com/jaq-project/jaq/internal/investigator"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "jaq:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: jaq analyze --sample <absolute-path> --output <directory>")
	}
	if args[0] == "version" || args[0] == "--version" {
		fmt.Println("jaq", app.Version)
		return nil
	}
	if args[0] != "analyze" {
		return fmt.Errorf("unknown command %q (expected analyze)", args[0])
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
