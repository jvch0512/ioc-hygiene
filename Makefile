.PHONY: test sample

test:
	perl -I src tests/ioc.t && bash tests/cli.sh

sample:
	mkdir -p docs site
	bin/ioc-hygiene examples > docs/sample-output.txt; true
	bin/ioc-hygiene examples --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "ioc-hygiene" "Lints threat intel reports and IOC lists for live URLs and IPs that were not defanged, reserved addresses, known-good indicators, bad hashes and duplicates. Perl." "Synthetic data."
