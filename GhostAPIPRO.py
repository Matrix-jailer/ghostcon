import time
import logging
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import cloudscraper
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Manager
from requests.exceptions import RequestException
import hashlib
from collections import deque
import random
from fastapi import FastAPI, HTTPException
from pydantic import HttpUrl
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# User-agents
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Go-http-client/2.0'  # Added for compatibility
]

# Gateway patterns
GATEWAY_KEYWORDS = {
    "stripe": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'js\.stripe\.com', r'api\.stripe\.com/v1', r'stripe\.js', r'stripe\.min\.js',
        r'client_secret', r'pi_', r'payment_intent', r'data-stripe', r'stripe-payment-element',
        r'stripe-elements', r'stripe-checkout', r'hooks\.stripe\.com', r'm\.stripe\.network',
        r'stripe__input', r'stripe-card-element', r'stripe-v3ds', r'confirmCardPayment',
        r'createPaymentMethod', r'stripePublicKey', r'Stripe\(', r'stripe\.handleCardAction',
        r'elements\.create', r'stripe\.createToken', r'stripe-payment-request', r'stripe__frame',
        r'api\.stripe\.com/v1/payment_methods', r'api\.stripe\.com/v1/tokens',
        r'stripe\.com', r'checkout\.stripe\.com', r'stripe-js', r'payment-method', r'stripe-redirect',
        r'stripe-payment', r'stripe\.network', r'stripe-checkout\.js', r'payment-element',
        r'stripe'  # Added for broader matching
    ]],
    "paypal": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'api\.paypal\.com', r'paypal\.com', r'paypal-sdk\.com', r'paypal\.js', r'paypalobjects\.com',
        r'paypal-button', r'paypal-checkout-sdk', r'paypal-sdk\.js', r'paypal-smart-button',
        r'paypal-rest-sdk', r'paypal-transaction', r'PayPal\.Buttons', r'paypal\.Buttons',
        r'data-paypal-client-id', r'paypal\.com/sdk/js', r'paypal\.Order\.create',
        r'paypal-checkout-component', r'api-m\.paypal\.com', r'paypal-funding',
        r'paypal-hosted-fields', r'paypal-transaction-id',
        r'paypal\.me', r'paypal\.com/v2/checkout', r'paypal-checkout', r'paypal\.com/api',
        r'paypal', r'sdk\.paypal\.com', r'gotopaypalexpresscheckout',
        r'paypal'  # Added for broader matching
    ]],
    "braintree": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'api\.braintreegateway\.com/v1', r'braintreepayments\.com', r'js\.braintreegateway\.com',
        r'client_token', r'braintree\.js', r'braintree-hosted-fields', r'braintree-dropin',
        r'braintree-v3', r'braintree-client', r'braintree-data-collector', r'braintree-payment-form',
        r'braintree-3ds-verify', r'client\.create', r'braintree\.min\.js',
        r'assets\.braintreegateway\.com', r'braintree\.setup', r'data-braintree', r'braintree\.tokenize',
        r'braintree-dropin-ui', r'braintree\.com'
    ]],
    "adyen": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'checkoutshopper-live\.adyen\.com', r'adyen\.com/hpp', r'adyen\.js', r'data-adyen',
        r'adyen-checkout', r'adyen-payment', r'adyen-components', r'adyen-encrypted-data',
        r'adyen-cse', r'adyen-dropin', r'adyen-web-checkout', r'live\.adyen-services\.com',
        r'adyen\.encrypt', r'checkoutshopper-test\.adyen\.com', r'adyen-checkout__component',
        r'adyen\.com/v1', r'adyen-payment-method', r'adyen-action', r'adyen\.min\.js',
        r'adyen\.com'
    ]]
}

# Payment indicators
PAYMENT_INDICATORS = [
    "cart", "checkout", "payment", "buy", "purchase", "order", "billing", "subscribe",
    "shop", "store", "pricing", "add-to-cart", "pay-now", "secure-checkout", "complete-order",
    "transaction", "invoice", "donate", "donation", "add-to-bag", "add-to-basket",
    "shop-now", "buy-now", "order-now", "proceed-to-checkout", "pay", "payment-method",
    "credit-card", "debit-card", "place-order", "confirm-purchase", "get-started",
    "sign-up", "join-now", "membership", "upgrade", "renew", "trial", "subscribe-now",
    "book-now", "reserve", "back-now", "fund", "pledge", "support", "contribute",
    "complete-purchase", "finalize-order", "payment-details", "billing-info",
    "secure-payment", "pay-securely", "shop-secure", "trial", "subscribe", "subscription",
    "give", "donate-now", "donatenow", "donate_now", "get-now", "browse", "category",
    "items", "product", "item", "pay-now", "giftcard", "topup", "plans", "buynow",
    "sell", "sell-now", "purchase-now", "shopnow", "shopping", "menu", "games",
    "accessories", "men", "women", "collections", "sale", "vps", "server", "about",
    "about-us", "shirt", "pant", "hoodie", "keys", "cart-items", "buy-secure", "cart-page",
    "basket", "checkout-page", "order-summary", "payment-form", "purchase-flow",
    "shop-cart", "ecommerce", "store-cart", "buy-button", "purchase-button",
    "add-item", "remove-item", "cart-update", "apply-coupon", "redeem-code",
    "discount-code", "promo-code", "gift-card", "pay-with", "payment-options",
    "express-checkout", "quick-buy", "one-click-buy", "instant-purchase"
]

# Non-HTML extensions
NON_HTML_EXTENSIONS = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.pdf'}

# Skip domains
SKIP_DOMAINS = {'help.ko-fi.com', 'static.cloudflareinsights.com', 'twitter.com', 'facebook.com', 'youtube.com'}

def create_scraper():
    scraper = cloudscraper.create_scraper(browser={'browser': 'chrome', 'platform': 'windows', 'mobile': False}, delay=1.0)
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    scraper.mount('http://', HTTPAdapter(max_retries=retries))
    scraper.mount('https://', HTTPAdapter(max_retries=retries))
    return scraper

def is_valid_url(url, base_domain):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    if domain != base_domain and not any(gw in domain for gw in ['paypal.com', 'stripe.com', 'braintreegateway.com', 'adyen.com']):
        return False
    if any(path.endswith(ext) for ext in NON_HTML_EXTENSIONS):
        return False
    if any(ind in path or ind in query for ind in ['manage', 'settings', 'sidemenu', 'login', 'signup', 'auth']):
        return False
    return True

def check_url_status(url, scraper):
    headers = {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html',
        'Connection': 'keep-alive',
        'Referer': 'https://www.google.com/',
        'DNT': '1',
        'Cache-Control': 'no-cache'
    }
    try:
        response = scraper.head(url, headers=headers, timeout=5, allow_redirects=True)
        logger.debug(f"Status {response.status_code} for {url}")
        return response.status_code == 200
    except RequestException as e:
        logger.error(f"Error checking {url}: {str(e)}")
        return False

def fetch_url(url, scraper):
    if not check_url_status(url, scraper):
        logger.debug(f"Skipping non-200 URL: {url}")
        return "", url
    headers = {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Referer': 'https://www.google.com/',
        'DNT': '1',
        'Cache-Control': 'no-cache'
    }
    try:
        response = scraper.get(url, headers=headers, timeout=15, allow_redirects=True)
        if response.status_code == 200:
            logger.debug(f"Fetched {url}: {response.text[:100]}")
            return response.text, url
        logger.debug(f"Non-200 status {response.status_code} for {url}, headers: {response.headers}")
        return "", url
    except RequestException as e:
        logger.error(f"Error fetching {url}: {str(e)}")
        return "", url

def get_all_sources(url, html_content, base_domain):
    if not html_content:
        return []
    try:
        soup = BeautifulSoup(html_content, 'lxml')
        sources = deque()
        url_lower = url.lower()
        for tag in soup.find_all(['a', 'button', 'script', 'iframe', 'form']):
            href = tag.get('href') or tag.get('src') or tag.get('action')
            if not href:
                continue
            full_url = urljoin(url, href).lower()
            if not full_url.startswith(('http://', 'https://')) or full_url.split('#')[0] == url_lower.split('#')[0]:
                continue
            if not is_valid_url(full_url, base_domain):
                continue
            score = 1
            if any(p in full_url for p in PAYMENT_INDICATORS):
                score += 4
            classes = tag.get('class') or []
            if classes and any(isinstance(cls, str) and any(p in cls.lower() for p in PAYMENT_INDICATORS) for cls in classes):
                score += 1
            text = tag.get_text(strip=True).lower()
            if text and any(p in text for p in PAYMENT_INDICATORS):
                score += 1
            sources.append((full_url, score))
        sources = [url for url, score in sorted(sources, key=lambda x: x[1], reverse=True)][:12]
        logger.debug(f"Selected {len(sources)} sources for {url}: {sources}")
        return sources
    except Exception as e:
        logger.error(f"Error parsing sources for {url}: {str(e)}")
        return []

def detect_gateways(content, url, detected_gateways):
    if not content:
        logger.info(f"No content for {url}")
        return [], url
    logger.debug(f"Analyzing content for {url}: {content[:200]}")
    content_lower = content.lower()
    gateways = set()
    for gateway, patterns in GATEWAY_KEYWORDS.items():
        for pattern in patterns:
            if pattern.search(content_lower) and gateway.capitalize() not in detected_gateways:
                logger.info(f"Detected {gateway} with pattern {pattern.pattern} at {url}")
                gateways.add(gateway.capitalize())
                detected_gateways.append(gateway.capitalize())
                break
    if not gateways:
        logger.info(f"No gateways detected for {url}")
    return list(gateways), url

def crawl_worker(args):
    url, max_depth, visited, content_hashes, base_domain, detected_gateways = args
    if url in visited or len(visited) > 50:
        return []
    visited.add(url)
    if max_depth < 1 or not is_valid_url(url, base_domain):
        return []
    scraper = create_scraper()
    html_content, fetched_url = fetch_url(url, scraper)
    if not html_content:
        return [(html_content, fetched_url)]
    content_hash = hashlib.md5(html_content.encode('utf-8')).hexdigest()
    if content_hash in content_hashes:
        return [(html_content, fetched_url)]
    content_hashes.add(content_hash)
    results = [(html_content, fetched_url)]
    sources = get_all_sources(fetched_url, html_content, base_domain)
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(fetch_url, source, scraper) for source in sources]
        for future in futures:
            content, source_url = future.result()
            if content:
                content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()
                if content_hash not in content_hashes:
                    content_hashes.add(content_hash)
                    results.append((content, source_url))
    if max_depth > 1:
        sub_args = [(source, max_depth - 1, visited, content_hashes, base_domain, detected_gateways) for source in sources]
        with ThreadPoolExecutor(max_workers=4) as executor:
            sub_results = [executor.submit(crawl_worker, sub_arg) for sub_arg in sub_args]
            for future in sub_results:
                results.extend(future.result())
    return results

def scan_website(url: str, max_depth: int = 1) -> dict:
    """
    Scan a website for payment gateways.
    """
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urlparse(url)
        if not parsed.netloc:
            return {"success": False, "error": "Invalid URL format"}
        
        start_time = time.time()
        logger.info(f"Starting scan for {url}")
        visited = set()
        content_hashes = set()
        manager = Manager()
        detected_gateways = manager.list()
        base_domain = parsed.netloc.lower()

        contents = crawl_worker((url, max_depth, visited, content_hashes, base_domain, detected_gateways))
        if not contents or not any(html_content for html_content, _ in contents):
            if "discord.com" in url.lower():
                return {"success": False, "error": "This site requires manual verification. Please check manually."}
            return {"success": False, "error": "Failed to scan the website or no valid content retrieved."}

        gateways = set()
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(detect_gateways, html, file_url, detected_gateways) for html, file_url in contents]
            for future in futures:
                gateway_list, _ = future.result()
                gateways.update(gateway_list)

        time_taken = round(time.time() - start_time, 2)
        result = (
            f"🟢 Scan Results for {url}\n"
            f"⏱️ Time Taken: {time_taken}s seconds\n"
            f"💳 Payment Gateways: {', '.join(sorted(gateways)) if gateways else 'None'}"
        )
        return {
            "success": True,
            "result": result,
            "data": {
                "url": url,
                "time_taken": time_taken,
                "payment_gateways": sorted(gateways)
            }
        }
    except Exception as e:
        logger.error(f"Scan failed for {url}: {str(e)}")
        return {"success": False, "error": f"Unexpected error: {str(e)}"}

# Initialize FastAPI app
app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Use /sexy_api/gate?url=<target_url>&depth=<depth> to scan for payment gateways"}

@app.get("/sexy_api/gate")
async def gateway_hunter(url: HttpUrl, depth: int = 1):
    """
    API endpoint to scan a URL and return payment gateway results.
    Example: /sexy_api/gate?url=https://example.com&depth=1
    """
    result = scan_website(str(url), depth)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])
    return result
