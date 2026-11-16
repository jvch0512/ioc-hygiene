# ioc-hygiene

ioc-hygiene reads text, Markdown, CSV and JSON files that contain indicators of compromise and checks the list itself: URLs, IPv4 addresses and email addresses that are published live instead of defanged, private or reserved addresses listed as indicators, well-known benign indicators such as public DNS resolvers and the hashes of empty files, hash labels that do not match the hash length, invalid IPv4 addresses and indicators listed more than once. It is a pre-publication gate for reports and blocklists.

**Live demo:** https://jvch0512.github.io/ioc-hygiene/ (Synthetic data.)

Perl 5 core modules only. The demo page is rendered from the tool's `--tsv` output by `scripts/site.py` (Python 3, only needed to regenerate the page).

## Use

```bash
bin/ioc-hygiene examples
bin/ioc-hygiene ./reports --tsv
bin/ioc-hygiene ./reports --fail-on high       # exit 1 on any high finding
```

Exit codes: 0 ok, 1 findings at or above `--fail-on`, 2 bad input. Output is human text by default and TSV with `--tsv` (`# N files, M findings`, then `SEVERITY<TAB>RULE<TAB>WHERE<TAB>MESSAGE`).

| Rule | Severity | What it catches |
|---|---|---|
| IOC001 | high | a live http, https or ftp URL that is not defanged |
| IOC002 | medium | a live public IPv4 address that is not defanged |
| IOC003 | low | a live email address |
| IOC004 | low | a private, loopback, link-local, documentation or reserved IPv4 address listed as an indicator |
| IOC005 | low | a hash whose label (md5, sha1, sha256, sha512) does not match its length |
| IOC006 | low | an indicator listed more than once in the scanned set, defanged or not |
| IOC007 | medium | a known-good indicator: public DNS resolvers, big vendor domains, hashes of an empty file |
| IOC008 | low | an IPv4 address with an octet above 255 |
| IOC000 | info | the file has no indicators |

See [examples](examples) and [docs/sample-output.txt](docs/sample-output.txt).

## Limits

- It checks how indicators are written, not whether they are malicious. Reputation lookups are out of scope.
- Defanged forms understood: `hxxp`, `hxxps`, `[.]`, `(.)`, `[dot]`, `[:]` and `[@]`.
- In Markdown, lines under a heading named References, Sources, Further reading or Links are skipped.
- Dotted version numbers that look like IPv4 addresses (`1.2.3.4`) cannot be told apart from addresses. Prefix them with `v` or write them in a code span to avoid findings.
- Files read: `.txt`, `.md`, `.csv`, `.tsv`, `.json`, `.ioc`, `.list`. A single file is read whatever its extension.

## Where it fits

Reviewing threat intelligence reports and blocklists before they are shared, and CI checks for an IOC feed repository.

## Tests

```bash
make test    # A Test::More suite: every rule, defanging forms, reference sections, hash labels, duplicates, hostile input, fuzzing and CLI exit codes
```

MIT.
