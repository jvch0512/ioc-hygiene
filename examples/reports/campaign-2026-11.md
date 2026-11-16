# Campaign report: invoice lures

Initial access came from emails sent by billing@invoice-portal.example to finance staff.
The payload was fetched from http://cdn.evil-host.example/drop/payload.exe and executed.

## Indicators

- C2: 203.0.114.9 (port 443)
- C2 backup: 198.18.5.77
- Staging URL: hxxps://stage[.]evil-host[.]example/a.php
- Sender: billing[@]invoice-portal[.]example
- Internal host seen beaconing: 10.20.30.40
- Resolver used by the implant: 8.8.8.8
- SHA256: 3f786850e387550fdab836ed7e6dc881de23001b
- MD5: d41d8cd98f00b204e9800998ecf8427e
- Dropper sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
- Seen again: 203.0.114.9
- Broken address: 300.1.1.1

## References

- https://vendor.example/blog/invoice-lures-2026
