package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
)

var (
	fMaxPages  = flag.Int("max-pages", 50, "maximum result pages per domain")
	fResolvers = flag.Int("resolvers", 10, "number of concurrent resovlers. More is safe but won't speed things up much")
	fScanners  = flag.Int("scanners", 5, "number of concurrent scanners. More will make things faster but risk rate limiting")
)

func fatalIfError(err error, msg string) {
	if err != nil {
		log.Fatal("error ", msg, ": ", err)
	}
}

func main() {
	flag.Parse()

	// Need an auth cookie for requests. These aren't persisted to disk
	jar, err := cookiejar.New(nil)
	fatalIfError(err, "creating cookie jar")
	client := &http.Client{
		Jar: jar,
	}

	fatalIfError(getGoogleCookie(client), "getting google cookie")

	scanner := Scanner{
		client:   client,
		maxPages: *fMaxPages,
		lock:     &sync.Mutex{},
		scanned:  map[string]struct{}{},
		in:       make(chan string),
		out:      make(chan Record),
	}

	scanners := errgroup.Group{}
	for i := 0; i < *fScanners; i++ {
		// Start up multiple scanners
		scanners.Go(scanner.ScanStream)
	}

	resolver := Resolver{
		in:       scanner.out,
		out:      make(chan Record),
		lock:     &sync.Mutex{},
		resolved: map[string]struct{}{},
	}
	resolvers := errgroup.Group{}
	for i := 0; i < *fResolvers; i++ {
		// Start up multiple resolvers
		resolvers.Go(resolver.Resolve)
	}

	go func() {
		// when we've received everything from STDIN, close the input channel
		// to the scanners to signal no more work
		defer close(scanner.in)
		lineScanner := bufio.NewScanner(os.Stdin)
		for lineScanner.Scan() {
			// read lines from standard in
			line := lineScanner.Text()
			line = strings.TrimSpace(line)
			if line == "" || line[0] == '#' {
				// skip empty lines and comments
				continue
			}
			scanner.in <- line
		}
	}()

	go func() {
		// wait for the scanners to finish
		fatalIfError(scanners.Wait(), "in scanner")
		// close scanner.out/resolver.in to signal no more resolver work
		close(scanner.out)
		// Wait for the resolvers to finish
		fatalIfError(resolvers.Wait(), "in resolver")
		// close resolver.out to signal no more output work
		close(resolver.out)
	}()

	w := csv.NewWriter(os.Stdout)
	for record := range resolver.out {
		var row []string
		if record.Err != nil {
			w.Write([]string{
				record.From,
				record.Name,
				"",
				record.Err.Error(),
			})
		} else {
			row = []string{
				record.From,
				record.Name,
				"",
				"",
			}
			for _, addr := range record.Addrs {
				row[2] = addr
				w.Write(row)
			}
		}
	}
	w.Flush()
}
