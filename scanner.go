package main

import (
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/bitly/go-simplejson"
)

var (
	googleHeaders = map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36",
		"Accept":          "application/json, text/plain, */*",
		"Accept-Language": "en-US,en;q=0.5",
		"Accept-Encoding": "gzip, deflate, br",
		"Referer":         "https://transparencyreport.google.com",
		"Sec-Fetch-Site":  "same-origin",
		"Sec-Fetch-Mode":  "cors",
		"Sec-Fetch-Dest":  "empty",
		"Connection":      "keep-alive",
		"DNT":             "1",
	}
)

// A Scanner processes a stream of domain names, looking them up in Google's
// certificate transparency system. One scanner can process many domains in
// parallel.
type Scanner struct {
	client   *http.Client
	maxPages int
	lock     *sync.Mutex
	scanned  map[string]struct{}
	in       chan string
	out      chan Record
}

// ScanStream loops over a channel of domain strings, scans them, and writes
// records to an output stream.
func (s Scanner) ScanStream() error {
	for domain := range s.in {
		domain = normalizeDomain(domain)
		s.lock.Lock()
		if _, present := s.scanned[domain]; present {
			// This domain has already been seen. Skip it
			s.lock.Unlock()
			continue
		}
		s.scanned[domain] = struct{}{}
		s.lock.Unlock()

		if err := s.scan(domain); err != nil {
			return err
		}
	}
	return nil
}

// scan a single domain.
func (s Scanner) scan(domain string) error {
	token := ""
	for i := 0; i < s.maxPages; i++ {
		q := url.Values{}
		var reqPath string
		if token == "" {
			// There's no continuation token. This is the first request
			reqPath = "/transparencyreport/api/v3/httpsreport/ct/certsearch"
			q.Set("include_subdomains", "true")
			q.Set("domain", domain)
		} else {
			// Continue retrieving pages of results
			reqPath = "/transparencyreport/api/v3/httpsreport/ct/certsearch/page"
			q.Set("p", token)
		}

		u := &url.URL{
			Scheme:   "https",
			Host:     "transparencyreport.google.com",
			Path:     reqPath,
			RawQuery: q.Encode(),
		}
		req, err := http.NewRequest(
			http.MethodGet,
			u.String(),
			nil,
		)
		if err != nil {
			return fmt.Errorf("creating request: %w", err)
		}
		setGoogleHeaders(req)

		resp, err := s.client.Do(req)
		if err != nil {
			return fmt.Errorf("sending request: %w", err)
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return fmt.Errorf("non-200 response %d: %s", resp.StatusCode, resp.Status)
		}

		r := resp.Body
		if resp.Header.Get("Content-Encoding") == "gzip" {
			r, err = gzip.NewReader(r)
			if err != nil {
				return fmt.Errorf("creating gzip reader: %w", err)
			}
		}

		b, err := ioutil.ReadAll(r)
		if err != nil {
			return fmt.Errorf("reading response body: %w", err)
		}
		resp.Body.Close()
		if string(b[:4]) == ")]}'" {
			// To prevent XSSI, a prefix is added that needs to be stripped
			b = b[4:]
		}

		records, newToken, err := parseCTData(b)
		if err != nil {
			return fmt.Errorf("parsing CT data: %w", err)
		}
		for _, record := range records {
			// mark each record with which domain it came from and send it
			record.From = domain
			s.out <- record
		}

		if newToken == "" {
			// no continuation token, this domain is done
			break
		}
		token = newToken
	}
	return nil
}

// normalizeDomain tries to normalize domain name strings, with room to grow.
func normalizeDomain(d string) string {
	return strings.TrimSpace(d)
}

// setGoogleHeaders applies the headers google expets to a request
func setGoogleHeaders(req *http.Request) {
	for h, v := range googleHeaders {
		req.Header.Set(h, v)
	}
}

// A Record captures information about a domain from certificate transparency
// and subsequent DNS resolution
type Record struct {
	From          string
	Name          string
	Issuer        string
	NotBeforeTime int64
	NotAfterTime  int64
	Addrs         []string
	Err           error
}

/*
[
  [
    "https.ct.cdsr",
    [
      [
        null,
        "debug.example.org",
        "Let's Encrypt Authority X3",
        1605043123456,
        1612819123456,
        "<base64>",
        2,
        null,
        1
      ],
      [
        null,
        "debug.example.org",
        "Let's Encrypt Authority X3",
        1605043123456,
        1612819123456,
        "<base64>",
        2,
        null,
        1
      ]
    ],
    [
      [
        "1234567890193923849",
        null,
        "C=US, O=Let's Encrypt, CN=R3",
        6
      ],
      [
        "9328174140391839128",
        null,
        "C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3",
        44
      ]
    ],
    [
      null,
      "<base64>",
      null,
      1,
      5
    ]
  ]
]
*/

// parseCTData parses a page of certificate transparency data from a goolge
// response. The JSON returned is all nested arrays instead of having a
// sensible object structure.
func parseCTData(b []byte) ([]Record, string, error) {
	j, err := simplejson.NewJson(b)
	if err != nil {
		return nil, "", fmt.Errorf("parsing JSON: %w", err)
	}

	recordsJSON := j.GetIndex(0).GetIndex(1)
	recordsArray, err := recordsJSON.Array()
	if err != nil {
		return nil, "", fmt.Errorf("records not an array")
	}
	lenRecords := len(recordsArray)
	records := make([]Record, lenRecords)
	for i := 0; i < lenRecords; i++ {
		currentRecord := recordsJSON.GetIndex(i)
		records[i] = Record{
			Name:          currentRecord.GetIndex(1).MustString(),
			Issuer:        currentRecord.GetIndex(2).MustString(),
			NotBeforeTime: currentRecord.GetIndex(3).MustInt64(),
			NotAfterTime:  currentRecord.GetIndex(4).MustInt64(),
		}
	}

	token := j.GetIndex(0).GetIndex(3).GetIndex(1).MustString()

	return records, token, nil
}

// getGoogleCookie retrieves a cookie uses for subsequent CT scan requests.
// The cookie only needs to be fetched once. The tool doesn't monitor cookie
// expiration.
func getGoogleCookie(client *http.Client) error {
	if client.Jar == nil {
		return fmt.Errorf("no cookie jar set")
	}
	req, err := http.NewRequest(
		http.MethodGet,
		"https://transparencyreport.google.com/https/certificates?hl=en_GB",
		nil,
	)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	setGoogleHeaders(req)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("non-200 response %d: %s", resp.StatusCode, resp.Status)
	}
	return nil
}
