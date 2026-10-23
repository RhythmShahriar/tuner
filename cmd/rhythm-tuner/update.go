package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/RhythmShahriar/tuner/checkpack"
	"github.com/RhythmShahriar/tuner/vulns"
)

// cmdUpdate refreshes the check pack and cached vulnerability data now.
// Scans also refresh both automatically once they are a day old.
func cmdUpdate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	flags.SetOutput(stderr)
	clear := flags.Bool("clear", false, "delete the cached check pack and vulnerability data")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	ua := fmt.Sprintf("rhythm-tuner/%s (+https://rythm.sh/tuner)", version)
	c := vulnClient(ua, nil, false)
	pc := packClient(ua, nil, false, true)
	if *clear {
		for _, dir := range []string{pc.CacheDir, c.CacheDir} {
			if err := os.RemoveAll(dir); err != nil {
				fmt.Fprintln(stderr, "rhythm tuner:", err)
				return exitError
			}
			fmt.Fprintln(stdout, "Cleared", dir)
		}
		return exitOK
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	packOK := updatePack(ctx, pc, stdout, stderr)
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
	if failed > 0 || !packOK {
		return exitError
	}
	return exitOK
}

// updatePack refreshes the check pack and says which checks scans will use.
func updatePack(ctx context.Context, pc *checkpack.Client, stdout, stderr io.Writer) bool {
	p, err := pc.Get(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "rhythm tuner: check pack: %v\n", err)
		fmt.Fprintf(stdout, "Checks: built-in (rhythm-tuner %s)\n", version)
		return false
	}
	if p.Warning != nil {
		fmt.Fprintln(stderr, "rhythm tuner:", p.Warning)
	}
	if p.Supersedes(checkpack.CurrentBuild()) {
		fmt.Fprintf(stdout, "Checks: pack %s, %d checks (commit %.7s)\n", p.Version, p.Checks, p.Commit)
	} else {
		fmt.Fprintf(stdout, "Checks: built-in (rhythm-tuner %s); they're as new as pack %s\n", version, p.Version)
	}
	return p.Warning == nil
}
