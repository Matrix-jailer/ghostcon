import time
import logging
import re
import sys
import argparse
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import cloudscraper
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.exceptions import RequestException

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Comprehensive payment gateway keywords with regex
GATEWAY_KEYWORDS = {
    "stripe": [
        r'js\.stripe\.com', r'api\.stripe\.com/v1', r'stripe\.js', r'stripe\.min\.js',
        r'client_secret', r'pi_', r'payment_intent', r'data-stripe', r'stripe-payment-element',
        r'stripe-elements', r'stripe-checkout', r'hooks\.stripe\.com', r'm\.stripe\.network',
        r'stripe__input', r'stripe-card-element', r'stripe-v3ds', r'confirmCardPayment',
        r'createPaymentMethod', r'stripePublicKey', r'Stripe\(', r'stripe\.handleCardAction',
        r'elements\.create', r'stripe\.createToken', r'stripe-payment-request', r'stripe__frame',
        r'api\.stripe\.com/v1/payment_methods', r'api\.stripe\.com/v1/tokens'
    ],
    "paypal": [
        r'api\.paypal\.com', r'paypal\.com', r'paypal-sdk\.com', r'paypal\.js', r'paypalobjects\.com',
        r'paypal-button', r'paypal-checkout-sdk', r'paypal-sdk\.js', r'paypal-smart-button',
        r'paypal-rest-sdk', r'paypal-transaction', r'PayPal\.Buttons', r'paypal\.Buttons',
        r'data-paypal-client-id', r'paypal\.com/sdk/js', r'paypal\.Order\.create',
        r'paypal-checkout-component', r'api-m\.paypal\.com', r'paypal-funding',
        r'paypal-hosted-fields', r'paypal-transaction-id'
    ],
    "braintree": [
        r'api\.braintreegateway\.com/v1', r'braintreepayments\.com', r'js\.braintreegateway\.com',
        r'client_token', r'braintree\.js', r'braintree-hosted-fields', r'braintree-dropin',
        r'braintree-v3', r'braintree-client', r'braintree-data-collector', r'braintree-payment-form',
        r'braintree-3ds-verify', r'client\.create', r'braintree\.min\.js',
        r'assets\.braintreegateway\.com', r'braintree\.setup', r'data-braintree', r'braintree\.tokenize',
        r'braintree-dropin-ui'
    ],
    "adyen": [
        r'checkoutshopper-live\.adyen\.com', r'adyen\.com/hpp', r'adyen\.js', r'data-adyen',
        r'adyen-checkout', r'adyen-payment', r'adyen-components', r'adyen-encrypted-data',
        r'adyen-cse', r'adyen-dropin', r'adyen-web-checkout', r'live\.adyen-services\.com',
        r'adyen\.encrypt', r'checkoutshopper-test\.adyen\.com', r'adyen-checkout__component',
        r'adyen\.com/v1', r'adyen-payment-method', r'adyen-action', r'adyen\.min\.js'
    ]
}

# Extensive list of payment-related indicators
PAYMENT_INDICATORS = [
    "cart", "checkout", "payment", "buy", "purchase", "order", "billing", "subscribe",
    "shop", "store", "pricing", "add-to-cart", "pay-now", "secure-checkout", "complete-order",
    "transaction", "invoice", "donate", "donation", "add-to-bag", "add-to-basket",
    "shop-now", "buy-now", "order-now", "proceed-to-checkout", "pay", "payment-method",
    "credit-card", "debit-card", "place-order", "confirm-purchase", "get-started",
    "sign-up", "join-now", "membership", "upgrade", "renew", "trial", "subscribe-now",
    "book-now", "reserve", "back-now", "fund", "pledge", "support", "contribute",
    "complete-purchase", "finalize-order", "payment-details", "billing-info",
    "secure-payment", "pay-securely", "shop-secure", "trial", "subscribe", "subscription", "give", "donate-now", "donatenow", "donate_now", "get-now", "browse", "category", "items", "product", "item", "pay-now", "giftcard", "topup", "plans", "buynow", "sell", "sell-now", "purchase-now", "shopnow", "shopping", "menu", "games", "accessories", "men", "women", "collections", "sale", "vps", "server", "about", "about-us", "shirt", "pant", "hoodie", "keys", "cart-items", "buy-secure", "cart-page",
    "basket", "checkout-page", "order-summary", "payment-form", "purchase-flow",
    "shop-cart", "ecommerce", "store-cart", "buy-button", "purchase-button",
    "add-item", "remove-item", "cart-update", "apply-coupon", "redeem-code",
    "discount-code", "promo-code", "gift-card", "pay-with", "payment-options",
    "express-checkout", "quick-buy", "one-click-buy", "instant-purchase"
]

def fetch_url(url, scraper, max_retries=3):
    """Fetch URL content, return only if status code is 200."""
    for attempt in range(1, max_retries + 1):
        try:
            response = scraper.get(url, timeout=15)
            if response.status_code == 200:
                logger.debug(f"Fetched {url} successfully")
                return response.text
            else:
                logger.warning(f"Non-200 status {response.status_code} for {url}")
                return ""
        except RequestException as e:
            logger.error(f"Error on attempt {attempt} for {url}: {str(e)}")
            if attempt == max_retries:
                return ""
            time.sleep(2 ** attempt)
    return ""

def get_all_sources(url, html_content):
    """Extract and score payment-related links."""
    if not html_content or not html_content.strip():
        return []
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        sources = []
        for tag in soup.find_all(['a', 'button', 'script', 'iframe']):
            href = tag.get('href') or tag.get('src')
            if not href:
                continue
            full_url = urljoin(url, href)
            # Skip non-HTTP URLs or fragments
            if not full_url.startswith(('http://', 'https://')) or full_url.split('#')[0] == url.split('#')[0]:
                continue
            score = 0
            # Score based on URL
            if any(indicator in full_url.lower() for indicator in PAYMENT_INDICATORS):
                score += 2
            # Score based on class (handle list of classes)
            classes = tag.get('class') or []
            if classes:
                for cls in classes:
                    if isinstance(cls, str) and any(indicator in cls.lower() for indicator in PAYMENT_INDICATORS):
                        score += 1
                        break
            # Score based on text
            text = tag.string or ''
            if isinstance(text, str) and any(indicator in text.lower() for indicator in PAYMENT_INDICATORS):
                score += 1
            # Score based on onclick
            onclick = tag.get('onclick') or ''
            if isinstance(onclick, str) and any(indicator in onclick.lower() for indicator in PAYMENT_INDICATORS):
                score += 1
            # Score based on data attributes
            for attr in tag.attrs:
                if attr.startswith('data-'):
                    value = tag.get(attr) or ''
                    if isinstance(value, str) and any(indicator in value.lower() for indicator in PAYMENT_INDICATORS):
                        score += 1
                        break
            if score > 0:
                sources.append((full_url, score))
        # Sort by score and limit to top 5
        sources = [url for url, score in sorted(sources, key=lambda x: x[1], reverse=True)][:5]
        logger.info(f"Selected {len(sources)} sources for {url}: {sources}")
        return sources
    except Exception as e:
        logger.error(f"Error parsing sources for {url}: {str(e)}")
        return []

def detect_gateways(content):
    """Detect payment gateways in content."""
    if not content:
        return []
    content_lower = content.lower()
    detected_gateways = set()
    for gateway, patterns in GATEWAY_KEYWORDS.items():
        for pattern in patterns:
            if re.search(pattern, content_lower):
                logger.info(f"Detected {gateway} with pattern {pattern}")
                detected_gateways.add(gateway.capitalize())
                break
    return list(detected_gateways)

def crawl(url, max_depth=1, visited=None):
    """Crawl pages up to max_depth, only processing 200 status URLs."""
    if visited is None:
        visited = set()
    if url in visited or len(visited) > 50:
        return []
    visited.add(url)
    if max_depth < 1:
        return []
    scraper = cloudscraper.create_scraper()
    html_content = fetch_url(url, scraper)
    if not html_content:
        return []
    results = [html_content]
    sources = get_all_sources(url, html_content)
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, source, scraper): source for source in sources}
        for future in as_completed(future_to_url):
            source = future_to_url[future]
            try:
                content = future.result()
                if content:
                    results.append(content)
            except Exception as e:
                logger.error(f"Error fetching {source}: {str(e)}")
    if max_depth > 1:
        for source in sources:
            results.extend(crawl(source, max_depth - 1, visited))
    return results

def scan_website(url, max_depth):
    """Scan website for payment gateways."""
    start_time = time.time()
    logger.info(f"Starting scan for {url}")
    contents = crawl(url, max_depth)
    gateways = set()
    for content in contents:
        detected = detect_gateways(content)
        gateways.update(detected)
    time_taken = time.time() - start_time
    result = {
        "success": True,
        "result": f"🟢 Scan Results for {url}\n⏱️ Time Taken: {time_taken:.2f} seconds\n💳 Payment Gateways: {', '.join(gateways) if gateways else 'None'}",
        "data": {
            "url": url,
            "time_taken": time_taken,
            "payment_gateways": list(gateways)
        }
    }
    logger.info(f"Scan completed in {time_taken:.2f} seconds. Gateways: {gateways}")
    return result

def main():
    """Parse arguments and run scan."""
    parser = argparse.ArgumentParser(description="Console-based payment gateway scanner")
    parser.add_argument("url", help="URL to scan (e.g., https://humblebundle.com)")
    parser.add_argument("--depth", type=int, default=1, help="Crawl depth (default: 1)")
    args = parser.parse_args()

    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    try:
        urlparse(args.url)
    except ValueError:
        print("❌ Invalid URL format")
        sys.exit(1)

    # Run scan
    try:
        result = scan_website(args.url, args.depth)
        print(result["result"])
    except Exception as e:
        print(f"❌ Scan failed: {str(e)}")
        logger.error(f"Scan failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
