# Roadmap

What we plan for Tuner. Plans change as we learn, so treat this as a direction, not a promise.

Have an idea or a check we should add? Start a thread in [Discussions: Ideas](https://github.com/RhythmShahriar/tuner/discussions/categories/ideas). Want to help now? Pick a [good first issue](https://github.com/RhythmShahriar/tuner/labels/good%20first%20issue). New checks are a great place to start.

## Now

- **Signed check packs.** Check updates between releases, signed and verified before Tuner uses them.
- **Public benchmark.** A rerunnable testbed run that compares Tuner with WPScan, wpprobe and Nuclei on the same sites.
- **One CLI contract.** Move onto rhythm's `kit/cli.Main` for `version --json`, shared exit codes and the update prompt.

## Next

- **More checks.** Grow the catalogue toward 200 safe, GET-only checks, each with a positive and a negative fixture.
- **A larger secret catalogue.** About 80 rules in the shared kit for mail, payment, cloud and AI keys, all masked in every output.
- **Deeper plugin discovery.** Let `--plugins deep` also probe plugins with known advisories once a data source lists them.
- **Windows and macOS.** Test every release on both, including local scans and Windows paths.

## Later

- **Update night with Soundcheck and Echo.** Tuner orders security updates first, then Soundcheck and Echo check what each update broke.
- **One rule format.** Tuner checks, Soundcheck error rules and Echo custom rules share one YAML loader and fixture runner.
- **Agency fleet file.** One `sites.yaml` for Tuner, Soundcheck and Echo with one branded report per client.
