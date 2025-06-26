from threading import Lock
from fastapi import FastAPI, HTTPException
from pydantic import HttpUrl
import time
import socket
import tldextract
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import cloudscraper
import requests
import random
import re
import logging
import hashlib
from collections import deque
from multiprocessing import Pool, Manager

# Configure logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# Payment gateways
PAYMENT_GATEWAYS = [
    "stripe", "paypal", "paytm", "razorpay", "square", "adyen", "braintree",
    "authorize.net", "klarna", "checkout.com", "Shopify Payments", "worldpay",
    "2checkout", "Amazon pay", "Apple pay", "Google pay", "mollie", "opayo", "paddle"
]

# Captcha patterns
CAPTCHA_PATTERNS = {
    "reCaptcha": [
        "g-recaptcha", "recaptcha/api.js", "data-sitekey", "nocaptcha",
        "recaptcha.net", "www.google.com/recaptcha", "grecaptcha.execute",
        "grecaptcha.render", "grecaptcha.ready", "recaptcha-token"
    ],
    "hCaptcha": [
        "hcaptcha", "assets.hcaptcha.com", "hcaptcha.com/1/api.js",
        "data-hcaptcha-sitekey", "js.stripe.com/v3/hcaptcha-invisible", "hcaptcha-invisible", "hcaptcha.execute"
    ],
    "Turnstile": [
        "turnstile", "challenges.cloudflare.com", "cf-turnstile-response",
        "data-sitekey", "__cf_chl_", "cf_clearance"
    ],
    "Arkose Labs": [
        "arkose-labs", "funcaptcha", "client-api.arkoselabs.com",
        "fc-token", "fc-widget", "arkose", "press and hold", "funcaptcha.com"
    ],
    "GeeTest": [
        "geetest", "gt_captcha_obj", "gt.js", "geetest_challenge",
        "geetest_validate", "geetest_seccode"
    ],
    "BotDetect": [
        "botdetectcaptcha", "BotDetect", "BDC_CaptchaImage", "CaptchaCodeTextBox"
    ],
    "KeyCAPTCHA": [
        "keycaptcha", "kc_submit", "kc__widget", "s_kc_cid"
    ],
    "Anti Bot Detection": [
        "fingerprintjs", "js.challenge", "checking your browser",
        "verify you are human", "please enable javascript and cookies",
        "sec-ch-ua-platform"
    ],
    "Captcha": [
        "captcha-container", "captcha-box", "captcha-frame", "captcha_input",
        "id=\"captcha\"", "class=\"captcha\"", "iframe.+?captcha",
        "data-captcha-sitekey"
    ]
}

from threading import Lock

# Proxy management
proxy_pool = []
proxy_lock = Lock()

def fetch_proxies():
    url = "https://www.proxy-list.download/api/v1/get?type=https"
    try:
        res = requests.get(url, timeout=10)
        proxies = [p.strip() for p in res.text.splitlines() if p.strip()]
        return proxies
    except Exception as e:
        logger.error(f"Proxy fetch failed: {e}")
        return []

def test_proxy(proxy):
    try:
        test_url = "https://httpbin.org/ip"
        res = requests.get(test_url, proxies={"http": f"http://{proxy}", "https": f"http://{proxy}"}, timeout=5)
        return res.status_code == 200
    except:
        return False

def refresh_proxy_pool():
    proxies = fetch_proxies()
    valid_proxies = []
    for proxy in proxies:
        if test_proxy(proxy):
            valid_proxies.append(proxy)
    with proxy_lock:
        proxy_pool.clear()
        proxy_pool.extend(valid_proxies)
    logger.info(f"Proxy pool refreshed with {len(valid_proxies)} working proxies.")

def get_random_proxy():
    with proxy_lock:
        if not proxy_pool:
            refresh_proxy_pool()
        if not proxy_pool:
            return None
        proxy = random.choice(proxy_pool)
        if test_proxy(proxy):
            return proxy
        else:
            proxy_pool.remove(proxy)
            return get_random_proxy()


# Platform keywords
PLATFORM_KEYWORDS = {
    "woocommerce": "WooCommerce",
    "shopify": "Shopify",
    "magento": "Magento",
    "bigcommerce": "BigCommerce",
    "prestashop": "PrestaShop",
    "opencart": "OpenCart",
    "wix": "Wix",
    "squarespace": "Squarespace"
}

# Card keywords (regex)
CARD_KEYWORDS = [re.compile(pattern, re.IGNORECASE) for pattern in [
    r'visa', r'mastercard', r'amex', r'discover', r'diners', r'jcb', r'unionpay',
    r'maestro', r'rupay', r'cartasi', r'hipercard'
]]

# 3D Secure keywords (regex)
THREE_D_SECURE_KEYWORDS = [re.compile(pattern, re.IGNORECASE) for pattern in [
    r'three_d_secure', r'3dsecure', r'acs', r'acs_url', r'acsurl', r'redirect',
    r'secure-auth', r'three_d_secure_usage', r'challenge', r'3ds', r'3ds1', r'3ds2', r'tds', r'tdsecure',
    r'3d-secure', r'three-d', r'3dcheck', r'3d-auth', r'three-ds',
    r'stripe\.com/3ds', r'm\.stripe\.network', r'hooks\.stripe\.com/3ds',
    r'paddle_frame', r'paddlejs', r'secure\.paddle\.com', r'buy\.paddle\.com',
    r'idcheck', r'garanti\.com\.tr', r'adyen\.com/hpp', r'adyen\.com/checkout',
    r'adyenpayments\.com/3ds', r'auth\.razorpay\.com', r'razorpay\.com/3ds',
    r'secure\.razorpay\.com', r'3ds\.braintreegateway\.com', r'verify\.3ds',
    r'checkout\.com/3ds', r'checkout\.com/challenge', r'3ds\.paypal\.com',
    r'authentication\.klarna\.com', r'secure\.klarna\.com/3ds'
]]

# Gateway keywords (regex)
GATEWAY_KEYWORDS = {
    "stripe": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'stripe\.com', r'api\.stripe\.com/v1', r'js\.stripe\.com', r'stripe\.js', r'stripe\.min\.js',
        r'client_secret', r'pi_', r'payment_intent', r'data-stripe', r'stripe-payment-element',
        r'stripe-elements', r'stripe-checkout', r'hooks\.stripe\.com', r'm\.stripe\.network',
        r'stripe__input', r'stripe-card-element', r'stripe-v3ds', r'confirmCardPayment',
        r'createPaymentMethod', r'stripePublicKey', r'stripe\.handleCardAction',
        r'elements\.create', r'js\.stripe\.com/v3/hcaptcha-invisible', r'js\.stripe\.com/v3',
        r'stripe\.createToken', r'stripe-payment-request', r'stripe__frame',
        r'api\.stripe\.com/v1/payment_methods', r'js\.stripe\.com', r'api\.stripe\.com/v1/tokens',
        r'stripe\.com/docs', r'checkout\.stripe\.com', r'stripe-js', r'payment-method', r'stripe-redirect',
        r'stripe-payment', r'stripe\.network', r'stripe-checkout\.js', r'payment-element'
    ]],
    "paypal": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'api\.paypal\.com', r'paypal\.com', r'paypal-sdk\.com', r'paypal\.js', r'paypalobjects\.com', r'paypal_express_checkout', r'e\.PAYPAL_EXPRESS_CHECKOUT',
        r'paypal-button', r'paypal-checkout-sdk', r'paypal-sdk\.js', r'paypal-smart-button', r'paypal_express_checkout/api',
        r'paypal-rest-sdk', r'paypal-transaction', r'itch\.io/api-transaction/paypal', r'in-context-paypal-metadata',
        r'PayPal\.Buttons', r'paypal\.Buttons', r'data-paypal-client-id', r'paypal\.com/sdk/js',
        r'paypal\.Order\.create', r'paypal-checkout-component', r'api-m\.paypal\.com', r'paypal-funding',
        r'paypal-hosted-fields', r'paypal-transaction-id', r'paypal\.me', r'paypal\.com/v2/checkout',
        r'paypal-checkout', r'paypal\.com/api', r'sdk\.paypal\.com', r'gotopaypalexpresscheckout'
    ]],
    "braintree": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'api\.braintreegateway\.com/v1', r'braintreepayments\.com', r'js\.braintreegateway\.com',
        r'client_token', r'braintree\.js', r'braintree-hosted-fields', r'braintree-dropin', r'braintree-v3',
        r'braintree-client', r'braintree-data-collector', r'braintree-payment-form', r'braintree-3ds-verify',
        r'client\.create', r'braintree\.min\.js', r'assets\.braintreegateway\.com', r'braintree\.setup',
        r'data-braintree', r'braintree\.tokenize', r'braintree-dropin-ui', r'braintree\.com'
    ]],
    "adyen": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'checkoutshopper-live\.adyen\.com', r'adyen\.com/hpp', r'adyen\.js', r'data-adyen',
        r'adyen-checkout', r'adyen-payment', r'adyen-components', r'adyen-encrypted-data',
        r'adyen-cse', r'adyen-dropin', r'adyen-web-checkout', r'live\.adyen-services\.com',
        r'adyen\.encrypt', r'checkoutshopper-test\.adyen\.com', r'adyen-checkout__component',
        r'adyen\.com/v1', r'adyen-payment-method', r'adyen-action', r'adyen\.min\.js', r'adyen\.com'
    ]],
    "authorize.net": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'authorize\.net/gateway/transact\.dll', r'js\.authorize\.net/v1/Accept\.js', r'js\.authorize\.net',
        r'anet\.js', r'data-authorize', r'authorize-payment', r'apitest\.authorize\.net',
        r'accept\.authorize\.net', r'api\.authorize\.net', r'authorize-hosted-form',
        r'merchantAuthentication', r'data-api-login-id', r'data-client-key', r'Accept\.dispatchData',
        r'api\.authorize\.net/xml/v1', r'accept\.authorize\.net/payment', r'authorize\.net/profile'
    ]],
    "square": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'squareup\.com', r'js\.squarecdn\.com', r'square\.js', r'data-square', r'square-payment-form',
        r'square-checkout-sdk', r'connect\.squareup\.com', r'square\.min\.js', r'squarecdn\.com',
        r'squareupsandbox\.com', r'sandbox\.web\.squarecdn\.com', r'square-payment-flow', r'square\.card',
        r'squareup\.com/payments', r'data-square-application-id', r'square\.createPayment'
    ]],
    "klarna": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'klarna\.com', r'js\.klarna\.com', r'klarna\.js', r'data-klarna', r'klarna-checkout',
        r'klarna-onsite-messaging', r'playground\.klarna\.com', r'klarna-payments', r'klarna\.min\.js',
        r'klarna-order-id', r'klarna-checkout-container', r'klarna-load', r'api\.klarna\.com'
    ]],
    "checkout.com": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'api\.checkout\.com', r'cko\.js', r'data-checkout', r'checkout-sdk', r'checkout-payment',
        r'js\.checkout\.com', r'secure\.checkout\.com', r'checkout\.frames\.js', r'api\.sandbox\.checkout\.com',
        r'cko-payment-token', r'checkout\.init', r'cko-hosted', r'checkout\.com/v2', r'cko-card-token'
    ]],
    "razorpay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'checkout\.razorpay\.com', r'razorpay\.js', r'data-razorpay', r'razorpay-checkout',
        r'razorpay-payment-api', r'razorpay-sdk', r'razorpay-payment-button', r'razorpay-order-id',
        r'api\.razorpay\.com', r'razorpay\.min\.js', r'payment_box payment_method_razorpay',
        r'razorpay', r'cdn\.razorpay\.com', r'rzp_payment_icon\.svg', r'razorpay\.checkout',
        r'data-razorpay-key', r'razorpay_payment_id', r'checkout\.razorpay\.com/v1', r'razorpay-hosted'
    ]],
    "paytm": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'securegw\.paytm\.in', r'api\.paytm\.com', r'paytm\.js', r'data-paytm', r'paytm-checkout',
        r'paytm-payment-sdk', r'paytm-wallet', r'paytm\.allinonesdk', r'securegw-stage\.paytm\.in',
        r'paytm\.min\.js', r'paytm-transaction-id', r'paytm\.invoke', r'paytm-checkout-js',
        r'data-paytm-order-id'
    ]],
    "Shopify Payments": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'pay\.shopify\.com', r'data-shopify-payments', r'shopify-checkout-sdk', r'shopify-payment-api',
        r'shopify-sdk', r'shopify-express-checkout', r'shopify_payments\.js', r'checkout\.shopify\.com',
        r'shopify-payment-token', r'shopify\.card', r'shopify-checkout-api', r'data-shopify-checkout',
        r'shopify\.com/api'
    ]],
    "worldpay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'secure\.worldpay\.com', r'worldpay\.js', r'data-worldpay', r'worldpay-checkout',
        r'worldpay-payment-sdk', r'worldpay-secure', r'secure-test\.worldpay\.com', r'worldpay\.min\.js',
        r'worldpay\.token', r'worldpay-payment-form', r'access\.worldpay\.com', r'worldpay-3ds',
        r'data-worldpay-token'
    ]],
    "2checkout": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'www\.2checkout\.com', r'2co\.js', r'data-2checkout', r'2checkout-payment', r'secure\.2co\.com',
        r'2checkout-hosted', r'api\.2checkout\.com', r'2co\.min\.js', r'2checkout\.token', r'2co-checkout',
        r'data-2co-seller-id', r'2checkout\.convertplus', r'secure\.2co\.com/v2'
    ]],
    "Amazon pay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'payments\.amazon\.com', r'amazonpay\.js', r'data-amazon-pay', r'amazon-pay-button',
        r'amazon-pay-checkout-sdk', r'amazon-pay-wallet', r'amazon-checkout\.js', r'payments\.amazon\.com/v2',
        r'amazon-pay-token', r'amazon-pay-sdk', r'data-amazon-pay-merchant-id', r'amazon-pay-signin',
        r'amazon-pay-checkout-session'
    ]],
    "Apple pay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'apple-pay\.js', r'data-apple-pay', r'apple-pay-button', r'apple-pay-checkout-sdk',
        r'apple-pay-session', r'apple-pay-payment-request', r'ApplePaySession', r'apple-pay-merchant-id',
        r'apple-pay-payment', r'apple-pay-sdk', r'data-apple-pay-token', r'apple-pay-checkout',
        r'apple-pay-domain'
    ]],
    "Google pay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'pay\.google\.com', r'googlepay\.js', r'data-google-pay', r'google-pay-button',
        r'google-pay-checkout-sdk', r'google-pay-tokenization', r'payments\.googleapis\.com',
        r'google\.payments\.api', r'google-pay-token', r'google-pay-payment-method',
        r'data-google-pay-merchant-id', r'google-pay-checkout', r'google-pay-sdk'
    ]],
    "mollie": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'api\.mollie\.com', r'mollie\.js', r'data-mollie', r'mollie-checkout', r'mollie-payment-sdk',
        r'mollie-components', r'mollie\.min\.js', r'profile\.mollie\.com', r'mollie-payment-token',
        r'mollie-create-payment', r'data-mollie-profile-id', r'mollie-checkout-form', r'mollie-redirect'
    ]],
    "opayo": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'live\.opayo\.eu', r'opayo\.js', r'data-opayo', r'opoayo-checkout', r'opayo-payment-sdk',
        r'opayo-form', r'test\.opayo\.eu', r'opayo\.min\.js', r'opayo-payment-token', r'opayo-3ds',
        r'data-opayo-merchant-id', r'opayo-hosted', r'opayo\.api'
    ]],
    "paddle": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'checkout\.paddle\.com', r'paddle_button\.js', r'paddle\.js', r'data-paddle',
        r'paddle-checkout-sdk', r'paddle-product-id', r'api\.paddle\.com', r'paddle\.min\.js',
        r'paddle-checkout', r'data-paddle-vendor-id', r'paddle\.Checkout\.open', r'paddle-transaction-id',
        r'paddle-hosted'
    ]]
}

# Payment indicators
PAYMENT_INDICATORS = [
    "cart", "checkout", "payment", "buy", "purchase", "order", "billing", "subscribe",
    "shop", "store", "pricing", "add-to-cart", "pay-now", "secure-checkout", "complete-order",
    "transaction", "invoice", 'checkout2', "donate", "donation", "add-to-bag", "add-to-basket",
    "shop-now", "buy-now", "order-now", "proceed-to-checkout", "pay", "payment-method",
    "credit-card", "debit-card", "place-order", 'docs', "confirm-purchase", "get-started",
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

# User-Agent strings
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Mobile Safari/537.36'
]

# Create cloudscraper instance
def create_scraper():
    return cloudscraper.create_scraper(
        browser={'browser': 'chrome', 'platform': 'windows', 'mobile': False},
        delay=1.0
    )

# Validate URL
def is_valid_url(url, base_domain):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    if domain in SKIP_DOMAINS:
        return False
    if domain != base_domain and not any(gw in domain for gw in ['paypal.com', 'stripe.com', 'braintreegateway.com', 'adyen.com', 'authorize.net', 'squareup.com', 'klarna.com', 'checkout.com', 'razorpay.com', 'paytm.in', 'shopify.com', 'worldpay.com', '2co.com', 'amazon.com', 'apple.com', 'google.com', 'mollie.com', 'opayo.eu', 'paddle.com']):
        return False
    if any(path.endswith(ext) for ext in NON_HTML_EXTENSIONS):
        return False
    return True

# Check URL status
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
        proxy = get_random_proxy()
        proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None
        response = scraper.head(url, headers=headers, timeout=5, allow_redirects=True, proxies=proxies)

        return response.status_code == 200
    except requests.RequestException:
        return False

# Fetch URL content
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
        proxy = get_random_proxy()
        proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None
        response = scraper.get(url, headers=headers, timeout=30, allow_redirects=True, proxies=proxies)

        if response.status_code == 200:
            logger.debug(f"Fetched {url}: {response.text[:100]}")
            return response.text, url
        logger.debug(f"Non-200 status {response.status_code} for {url}")
        return "", url
    except requests.RequestException as e:
        logger.error(f"Error fetching {url}: {str(e)}")
        return "", url

# Get all sources with payment indicators
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
        logger.info(f"Selected {len(sources)} sources for {url}: {sources}")
        return sources
    except Exception as e:
        logger.error(f"Error parsing sources for {url}: {str(e)}")
        return []

# Detect features
def detect_features(html_content, file_url, detected_gateways):
    if not html_content or not html_content.strip():
        return set(), set(), set(), set(), False, set(), "False"
    detected_gateways_set = set()
    detected_3d = set()
    detected_captcha = set()
    detected_platforms = set()
    detected_cards = set()
    cf_detected = False

    content_lower = html_content.lower()

    # Payment gateways
    for gateway in PAYMENT_GATEWAYS:
        gateway_keywords = GATEWAY_KEYWORDS.get(gateway, [])
        for pattern in gateway_keywords:
            if pattern.search(content_lower) and gateway.capitalize() not in detected_gateways:
                logger.info(f"Detected {gateway} with pattern {pattern.pattern}")
                detected_gateways_set.add(gateway.capitalize())
                detected_gateways.append(gateway.capitalize())
                for tds_pattern in THREE_D_SECURE_KEYWORDS:
                    if tds_pattern.search(content_lower):
                        detected_3d.add(gateway.capitalize())
                        break
                break

    # Captchas
    for category, patterns in CAPTCHA_PATTERNS.items():
        if any(re.search(pattern, content_lower, re.IGNORECASE) for pattern in patterns):
            detected_captcha.add(f"{category} Found 🔒")

    # Platforms
    for keyword, name in PLATFORM_KEYWORDS.items():
        if keyword in content_lower:
            detected_platforms.add(name)

    # Cards
    for card_pattern in CARD_KEYWORDS:
        if card_pattern.search(content_lower):
            card_name = card_pattern.pattern.lstrip(r'\b').rstrip(r'\b').capitalize()
            detected_cards.add(card_name)

    # Cloudflare
    cloudflare_identifiers = ['cloudflare', 'cf-ray', 'cf-chl-bypass']
    if any(identifier in content_lower for identifier in cloudflare_identifiers):
        cf_detected = True

    # GraphQL
    graphql_detected = "True" if "graphql" in content_lower else "False"

    return detected_gateways_set, detected_3d, detected_captcha, detected_platforms, cf_detected, detected_cards, graphql_detected

# Crawl worker
def crawl_worker(args):
    url, max_depth, visited, content_hashes, base_domain, detected_gateways = args
    if url in visited or len(visited) > 50:
        return []
    visited.append(url)
    if max_depth < 1 or not is_valid_url(url, base_domain):
        return []
    scraper = create_scraper()
    html_content, fetched_url = fetch_url(url, scraper)
    if not html_content:
        return [(html_content, fetched_url)]
    content_hash = hashlib.md5(html_content.encode('utf-8')).hexdigest()
    if content_hash in content_hashes:
        return [(html_content, fetched_url)]
    content_hashes.append(content_hash)
    results = [(html_content, fetched_url)]
    sources = get_all_sources(fetched_url, html_content, base_domain)
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(fetch_url, source, scraper) for source in sources]
        for future in futures:
            content, source_url = future.result()
            if content:
                content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()
                if content_hash not in content_hashes:
                    content_hashes.append(content_hash)
                    results.append((content, source_url))
    if max_depth > 1:
        sub_args = [(source, max_depth - 1, visited, content_hashes, base_domain, detected_gateways) for source in sources]
        with Pool(processes=8) as pool:
            sub_results = pool.map(crawl_worker, sub_args)
            for sub_result in sub_results:
                results.extend(sub_result)
    return results

# Get IP address
def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "Unknown"

# Country detection
def get_country_from_tld_or_ip(url, ip):
    tld_country_map = {
        "in": "India", "ru": "Russia", "br": "Brazil", "cn": "China", "jp": "Japan",
        "fr": "France", "de": "Germany", "es": "Spain", "it": "Italy", "uk": "United Kingdom",
        "us": "United States", "ca": "Canada", "au": "Australia", "nl": "Netherlands",
        "tr": "Turkey", "ir": "Iran", "kr": "South Korea", "za": "South Africa",
        "mx": "Mexico", "pl": "Poland", "id": "Indonesia", "ae": "United Arab Emirates",
        "eg": "Egypt", "ng": "Nigeria", "th": "Thailand", "vn": "Vietnam"
    }
    try:
        tld = urlparse(url).hostname.split('.')[-1].lower()
        if tld in tld_country_map:
            return tld_country_map[tld]
    except:
        pass
    try:
        res = requests.get(f"https://ipapi.co/{ip}/country_name/", timeout=5)
        if res.status_code == 200:
            return res.text.strip()
    except:
        pass
    return "Unknown"

# Main scanning function
def scan_website(url: str, max_depth: int = 2) -> dict:
    try:
        # Validate URL
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = tldextract.extract(url)
        if not (parsed.domain and parsed.suffix) or url.isdigit() or not any(c.isalpha() for c in url):
            return {"success": False, "error": "Invalid URL! Please provide a valid website URL."}

        start_time = time.time()
        manager = Manager()
        visited = manager.list()
        content_hashes = manager.list()
        detected_gateways = manager.list()
        base_domain = urlparse(url).netloc.lower()

        # Crawl
        resources = crawl_worker((url, max_depth, visited, content_hashes, base_domain, detected_gateways))
        if not resources or not any(html_content for html_content, _ in resources):
            if "discord.com" in url.lower():
                return {"success": False, "error": "This site requires manual verification. Please check manually."}
            return {"success": False, "error": "Failed to scan the website or no valid content retrieved."}

        # Detect features
        detected_gateways_set = set()
        detected_3d = set()
        detected_captcha = set()
        detected_platforms = set()
        cf_detected = False
        detected_cards = set()
        graphql_detected = "False"

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(detect_features, html, file_url, detected_gateways): file_url for html, file_url in resources}
            for future in futures:
                gateways, gateways_3d, captcha, platforms, cf, cards, graphql = future.result()
                detected_gateways_set.update(gateways)
                detected_3d.update(gateways_3d)
                detected_captcha.update(captcha)
                detected_platforms.update(platforms)
                if cf:
                    cf_detected = True
                detected_cards.update(cards)
                if graphql == "True":
                    graphql_detected = "True"

        elapsed = round(time.time() - start_time, 2)
        ip_address = get_ip(urlparse(url).netloc)
        country_name = get_country_from_tld_or_ip(url, ip_address)

        result = (
            f"🟢 Scan Results for {url}\n"
            f"⏱️ Time Taken: {elapsed} seconds\n"
            f"💳 Payment Gateways: {', '.join(sorted(detected_gateways_set)) if detected_gateways_set else 'None'}\n"
            f"🔒 Captcha: {', '.join(sorted(detected_captcha)) if detected_captcha else 'Not Found 🥳'}\n"
            f"🛡️ Cloudflare: {'Found 🔒' if cf_detected else 'Not Found 🥳'}\n"
            f"📊 GraphQL: {graphql_detected}\n"
            f"🖥️ Platforms: {', '.join(sorted(detected_platforms)) if detected_platforms else 'Unknown'}\n"
            f"🌍 Country: {country_name}\n"
            f"🔐 3D Secure: {'ENABLED' if detected_3d else 'DISABLED'}\n"
            f"💳 Cards: {', '.join(sorted(detected_cards)) if detected_cards else 'None'}"
        )

        return {
            "success": True,
            "result": result,
            "data": {
                "url": url,
                "time_taken": elapsed,
                "payment_gateways": sorted(detected_gateways_set),
                "captcha": sorted(detected_captcha),
                "cloudflare": cf_detected,
                "graphql": graphql_detected,
                "platforms": sorted(detected_platforms),
                "country": country_name,
                "3d_secure": bool(detected_3d),
                "cards": sorted(detected_cards)
            }
        }

    except Exception as e:
        return {"success": False, "error": f"Unexpected error: {str(e)}"}

# Initialize FastAPI app
app = FastAPI()

@app.get("/sexy_api/gate")
async def gateway_hunter(url: HttpUrl):
    """
    API endpoint to scan a URL and return gateway results.
    Example: /sexy_api/gate?url=https://example.com
    """
    result = scan_website(str(url), max_depth=1)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])
    return result
