![Banner](banner.png)

# net-http-analyzer
Performs automated HTTP request analysis to detect vulnerabilities like XSS, SQL injection, and exposed sensitive information based on response content. Focused on basic network operations.

## Install
`git clone https://github.com/ShadowGuard-AI/net-http-analyzer`
`pip install -r requirements.txt`

## Usage
`python3 main.py -u URL [options]`

## Parameters
- `-h`: Show help message and exit
- `-u, --url`: The URL to analyze. Required.
- `-d, --data`: The data to send in a POST request (e.g., 'param1=value1&param2=value2').
- `-m, --method`: The HTTP method to use, GET or POST (default: GET).
- `-t, --timeout`: Request timeout in seconds for the main request (default: 10). The XSS, SQL injection, and fuzzing sub-requests always use 10 seconds.
- `-v, --verbose`: Enable verbose output (debug logging).
- `--xss`: Enable XSS vulnerability scanning.
- `--sqli`: Enable SQL injection vulnerability scanning.
- `--sensitive`: Enable sensitive information detection.
- `--fuzz`: Enable basic fuzzing (append common paths).

## Verified behavior
- A run against a local test server returned status 200 for the base request, and the fuzzing pass probed `/admin`, `/login`, `/config.php`, `/.git/`, and `/.env`, logging each 404 at debug level.
- An invalid URL prints "Invalid URL provided." and the program still exits 0, because the analysis function returns instead of exiting with an error code. A missing `-u` is rejected by argparse with exit 2.
- URL validation checks scheme and host shape only. It does not prove the target is real or safe.
- The XSS check sends one payload, `<script>alert('XSS')</script>`, and only flags it when the response contains that exact string back. Escaped or encoded reflection is not flagged.
- The SQL injection check sends `admin' OR '1'='1` and only flags a response containing the string "error in your SQL syntax". Other database errors and blind cases read as a pass.
- The sensitive check is a case-insensitive substring search for: password, secret, api_key, credit card, ssn. A hit is a reason to look by eye, not proof anything sensitive was exposed. In this wave's local test, a page containing the word "secrets" triggered the secret warning.
- The fuzzing pass follows redirects only through the normal session request, and a 404 is logged at debug level from the request error handler, not reported as an interesting resource.
- The base request sends the user agent `net-http-analyzer/1.0`.

## License
See LICENSE.
