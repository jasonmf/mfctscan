# mfctscan

`mfctscan` scans Google's Certificate Transparency system for hostnames under a given domain, inspired by https://github.com/tares003/ct-exposer.

It reads domains from `STDIN`, scans them in parallel, performs DNS resolution on the discovered names, and writes the results to `STDOUT` as a CSV. Hostnames that administrators consider secret may be less protected, and may not realize that certificate transparency makes many hostnames public.

## Building

`mfctscan` is written in [Go](https://golang.org/) and requires the [Go toolchain](https://golang.org/dl/) to build.

```
go build -o mfctscan -ldflags="-s -w" *.go
```

To retain debug symbols, resulting in a larger binary, omit `-ldflags="-s -w"`.

The resulting binary is statically-compiled, requiring no dependencies. The tool is written in pure Go and can be compile for any OS Go supports (Linux, Windows, Mac, etc) and any architecture go supports (amd64, x86, ARM, etc). You can can [cross compile](https://dave.cheney.net/2015/08/22/cross-compilation-with-go-1-5) for other OSs and architectures.

## Running

```
$ ./mfctscan -h
Usage of /tmp/mfctscan:
  -max-pages int
        maximum result pages per domain (default 50)
  -resolvers int
        number of concurrent resovlers. More is safe but won't speed things up much (default 10)
  -scanners int
        number of concurrent scanners. More will make things faster but risk rate limiting (default 5)
```

Domains to scan are read from STDIN, one per line. Each line has leading and trailing whitespace stripped. Stripped lines that are empty or begin with a `#` are ignored. Duplicate lines are processed only once.

Each line to be processed is added to a queue. Multiple scan workers process the queue in parallel. Increasing the number of scan worker can speed up scanning the domains significantly but increases the risk of being rate limited or blocked.

Scan results from Google are returned with pagination. `-max-pages` controls the maximum number of pages retrieved, limiting results.

Discovered names go into an internal queue for DNS resolution. Multiple DNS resolution workers process the queue in parallel. Increasing the number of DNS resolution workers is relatively safe but won't have a huge effect on performance.

Results are streamed to `STDOUT` as CSV data with the following columns:

* `<source domain>`
* `<discovered name>`
* `<resolved address>` - May be absent
* `<error in DNS resolution>` - May be absent

When a discovered name has multiple DNS results, each result becomes a distinct row in the CSV output.