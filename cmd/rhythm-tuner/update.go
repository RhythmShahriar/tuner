package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/RhythmShahriar/tuner/vulns"
)

// cmdUpdate refreshes cached vulnerability data now. Scans also refresh it
// automatically once it is a day old.
func cmdUpdate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	flags.SetOutput(stderr)
	clear := flags.Bool("clear", false, "delete cached vulnerability data")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	c := vulnClient(fmt.Sprintf("rhythm-tuner/%s (+https://rythm.sh/tuner)", version), nil, false)
	if *clear {
		if err := os.RemoveAll(c.CacheDir); err != nil {
			fmt.Fprintln(stderr, "rhythm tuner:", err)
			return exitError
		}
		fmt.Fprintln(stdout, "Cleared", c.CacheDir)
		return exitOK
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ok, failed, err := c.Refresh(ctx)
	if err != nil && !os.IsNotExist(err) {
		fmt.Fprintln(stderr, "rhythm tuner:", err)
		return exitError
	}
	if ok+failed == 0 {
		fmt.Fprintln(stdout, "Nothing cached yet. Vulnerability data is fetched during scans and refreshed daily.")
	} else {
		fmt.Fprintf(stdout, "Refreshed %d vulnerability records", ok)
		if failed > 0 {
			fmt.Fprintf(stdout, " (%d failed; cached copies kept)", failed)
		}
		fmt.Fprintf(stdout, "\nData: %s\nCache: %s\n", vulns.Source, c.CacheDir)
	}
	if failed > 0 {
		return exitError
	}
	return exitOK
}
