import argparse
import logging
import requests
import socket
import sys
from urllib.parse import urlparse, urljoin

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Performs automated HTTP request analysis to detect vulnerabilities.",
                                     epilog="Example usage: python net_http_analyzer.py -u http://example.com")
    parser.add_argument("-u", "--url", required=True, help="The URL to analyze.")
    parser.add_argument("-d", "--data", help="The data to send in a POST request (e.g., 'param1=value1&param2=value2').")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="The HTTP method to use (default: GET).")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds (default: 10).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    parser.add_argument("--xss", action="store_true", help="Enable XSS vulnerability scanning.")
    parser.add_argument("--sqli", action="store_true", help="Enable SQL injection vulnerability scanning.")
    parser.add_argument("--sensitive", action="store_true", help="Enable sensitive information detection.")
    parser.add_argument("--fuzz", action="store_true", help="Enable basic fuzzing (append common paths).")

    return parser

def is_valid_url(url):
    """
    Validates a URL.
    Args:
        url (str): The URL to validate.
    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def test_xss(url, session):
    """
    Tests for XSS vulnerabilities by injecting a simple payload.
    Args:
        url (str): The URL to test.
        session (requests.Session): The requests session to use.
    Returns:
        None
    """
    xss_payload = "<script>alert('XSS')</script>"
    try:
        response = session.get(url, params={"xss": xss_payload}, timeout=10)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        if xss_payload in response.text:
            logging.warning(f"Possible XSS vulnerability detected at {url} with payload: {xss_payload}")
        else:
            logging.info(f"XSS test passed at {url}. No vulnerability detected with basic payload.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error testing XSS at {url}: {e}")

def test_sqli(url, session):
    """
    Tests for SQL injection vulnerabilities by injecting a simple payload.
    Args:
        url (str): The URL to test.
        session (requests.Session): The requests session to use.
    Returns:
        None
    """
    sqli_payload = "admin' OR '1'='1"
    try:
        response = session.get(url, params={"sql": sqli_payload}, timeout=10)
        response.raise_for_status()
        if "error in your SQL syntax" in response.text.lower():
            logging.warning(f"Possible SQL Injection vulnerability detected at {url} with payload: {sqli_payload}")
        else:
            logging.info(f"SQL Injection test passed at {url}. No vulnerability detected with basic payload.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error testing SQL Injection at {url}: {e}")

def detect_sensitive_info(url, response):
    """
    Detects potential sensitive information in the response content.
    Args:
        url (str): The URL of the response.
        response (requests.Response): The HTTP response object.
    Returns:
        None
    """
    sensitive_patterns = ["password", "secret", "api_key", "credit card", "ssn"]
    try:
        content = response.text.lower()
        for pattern in sensitive_patterns:
            if pattern in content:
                logging.warning(f"Possible sensitive information '{pattern}' detected in response from {url}")
    except Exception as e:
        logging.error(f"Error processing response content for sensitive information at {url}: {e}")

def basic_fuzzing(url, session):
    """
    Performs basic fuzzing by appending common paths to the URL.
    Args:
        url (str): The base URL.
        session (requests.Session): The requests session.
    Returns:
        None
    """
    common_paths = ["/admin", "/login", "/config.php", "/.git/", "/.env"]
    for path in common_paths:
        fuzzed_url = urljoin(url, path)
        try:
            response = session.get(fuzzed_url, timeout=10)
            response.raise_for_status()
            if response.status_code != 404:  # Check for other status codes than 404
                logging.info(f"Found interesting resource at {fuzzed_url} - Status code: {response.status_code}")
                detect_sensitive_info(fuzzed_url, response) #check the response content for sensitive information
            else:
                logging.debug(f"Path {fuzzed_url} returned 404.")
        except requests.exceptions.RequestException as e:
            logging.debug(f"Error accessing {fuzzed_url}: {e}")
        except Exception as e:
            logging.error(f"General error during fuzzing of {fuzzed_url}: {e}")

def analyze_http_request(url, method="GET", data=None, timeout=10, verbose=False, xss=False, sqli=False, sensitive=False, fuzz=False):
    """
    Performs HTTP request analysis.
    Args:
        url (str): The URL to analyze.
        method (str): The HTTP method to use (GET or POST).
        data (str, optional): The data to send in a POST request. Defaults to None.
        timeout (int, optional): The request timeout in seconds. Defaults to 10.
        verbose (bool, optional): Enable verbose output. Defaults to False.
        xss (bool, optional): Enable XSS vulnerability scanning. Defaults to False.
        sqli (bool, optional): Enable SQL injection vulnerability scanning. Defaults to False.
        sensitive (bool, optional): Enable sensitive information detection. Defaults to False.
        fuzz (bool, optional): Enable basic fuzzing. Defaults to False.
    Returns:
        None
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not is_valid_url(url):
        logging.error("Invalid URL provided.")
        return

    try:
        with requests.Session() as session:
            session.headers.update({'User-Agent': 'net-http-analyzer/1.0'}) #Set a user agent

            if method == "GET":
                try:
                    response = session.get(url, timeout=timeout)
                    response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
                except requests.exceptions.RequestException as e:
                    logging.error(f"Error during GET request to {url}: {e}")
                    return
            elif method == "POST":
                try:
                    response = session.post(url, data=data, timeout=timeout)
                    response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
                except requests.exceptions.RequestException as e:
                    logging.error(f"Error during POST request to {url}: {e}")
                    return
            else:
                logging.error("Invalid HTTP method specified.")
                return

            logging.info(f"Request to {url} successful. Status code: {response.status_code}")

            if sensitive:
                detect_sensitive_info(url, response)
            if xss:
                test_xss(url, session)
            if sqli:
                test_sqli(url, session)
            if fuzz:
                basic_fuzzing(url, session)

    except requests.exceptions.RequestException as e:
        logging.error(f"General request error: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

def main():
    """
    Main function to execute the network HTTP analyzer.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    analyze_http_request(args.url, args.method, args.data, args.timeout, args.verbose, args.xss, args.sqli, args.sensitive, args.fuzz)

if __name__ == "__main__":
    main()