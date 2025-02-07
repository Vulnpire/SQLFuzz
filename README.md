# SQLFuzz

is a fast and reliable SQL Injection scanner written in Go. This tool scans a list of URLs for SQL injection vulnerabilities by injecting common payloads and checking for error messages in the responses.

## Features

- **Verbose Logging**: Enable detailed logs with the `-verbose` flag.
- **Proxy Support**: Use a proxy to bypass CORS restrictions with the `-dp` flag.
- **Custom Parameter Injection**: Specify a file with parameter names to target specific parameters using the `-params` flag.
- **Concurrency**: Handles multiple URLs simultaneously for faster scanning.
- **Random User-Agents**: Uses random user-agent strings to avoid detection.
- **SQL Error Detection**: Detects a wide range of SQL error messages.
- **URL Encoding**: Encodes payloads to bypass basic input filters.

## Installation

`go install -v github.com/Vulnpire/sqlfuzz@latest`

## Usage

### Basic Usage
Provide a list of URLs via a file and pipe it to the tool:

```bash
cat urls.txt | ./sqlfuzz
```

### Verbose Mode
Enable verbose logging for detailed output:

```bash
cat urls.txt | ./sqlfuzz -verbose
```

### Using a Proxy
Use the AllOrigins proxy to bypass CORS restrictions:

```bash
cat urls.txt | ./sqlfuzz -dp
```

### Custom Parameter Injection
Specify a file with parameters to inject:

```bash
cat urls.txt | ./sqlfuzz -params params.txt
```

### Example

**urls.txt**
```
http://example.com/page.php?id=1
http://testsite.com/view.php?order_id=2
```

**params.txt**
```
id
order_id
```

Run the scanner:

```bash
cat urls.txt | ./sqlfuzz -verbose -params params.txt
```

## Output

- **[VULNERABLE]**: Indicates a vulnerable URL along with the parameter and payload used.
- **[ERROR]**: Any errors encountered during the scan.
- **[INFO]**: General information about the scan progress.


## Contributing

Open issues or submit pull requests for any improvements or bug fixes.

## Disclaimer

This tool is for educational and authorized penetration testing purposes only. Unauthorized use of this tool against systems you do not own or have explicit permission to test is illegal and unethical.

