from fastapi import FastAPI, HTTPException, Request
from pydantic import HttpUrl
import os
import sys
import time
import socket
import tldextract
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import cloudscraper
import requests
import random
import ssl
import re
import logging

# Configure logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# [Copy your PAYMENT_GATEWAYS, CAPTCHA_PATTERNS, PLATFORM_KEYWORDS, CARD_KEYWORDS, THREE_D_SECURE_KEYWORDS, GATEWAY_KEYWORDS here]
# Updated keyword definitions
PAYMENT_GATEWAYS = [
    "stripe", "paypal", "paytm", "razorpay", "square", "adyen", "braintree",
    "authorize.net", "klarna", "checkout.com", "Shopify Payments", "worldpay",
    "2checkout", "amazon_pay", "apple_pay", "google_pay", "mollie", "opayo", "paddle"
]

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

CARD_KEYWORDS = [
    "visa", "mastercard", "amex", "discover", "diners", "jcb", "unionpay",
    "maestro", "mir", "rupay", "cartasi", "hipercard"
]

THREE_D_SECURE_KEYWORDS = [
    "three_d_secure", "3dsecure", "acs", "acs_url", "acsurl", "redirect",
    "secure-auth", "three_d_secure_usage", "challenge", "3ds", "3ds1", "3ds2", "tds", "tdsecure",
    "3d-secure", "three-d", "3dcheck", "3d-auth", "three-ds",
    "stripe.com/3ds", "m.stripe.network", "hooks.stripe.com/3ds",
    "paddle_frame", "paddlejs", "secure.paddle.com", "buy.paddle.com",
    "idcheck", "garanti.com.tr", "adyen.com/hpp", "adyen.com/checkout",
    "adyenpayments.com/3ds", "auth.razorpay.com", "razorpay.com/3ds",
    "secure.razorpay.com", "3ds.braintreegateway.com", "verify.3ds",
    "checkout.com/3ds", "checkout.com/challenge", "3ds.paypal.com",
    "authentication.klarna.com", "secure.klarna.com/3ds"
]

GATEWAY_KEYWORDS = {
    "stripe": [
        "stripe.com", "api.stripe.com/v1", "js.stripe.com", "stripe.js", "stripe.min.js",
        "client_secret", "pi_", "payment_intent", "data-stripe", "stripe-payment-element",
        "stripe-elements", "stripe-checkout", "hooks.stripe.com", "m.stripe.network",
        "stripe__input", "stripe-card-element", "stripe-v3ds", "confirmCardPayment",
        "createPaymentMethod", "stripePublicKey", "Stripe(", "stripePublicKey",
        # New additions
        "stripe.handleCardAction",  # Used in 3D Secure authentication flows
        "elements.create",          # Common in Stripe Elements for creating payment fields
        "js.stripe.com/v3/hcaptcha-invisible",
        "js.stripe.com/v3",
        "stripe.createToken",       # Tokenization for card details
        "stripe-payment-request",   # Payment Request API integration
        "stripe__frame",            # Found in Stripe iframe classes
        "api.stripe.com/v1/payment_methods",
        "js.stripe.com",
        "api.stripe.com/v1/tokens", # Common API endpoint for token creation
        "stripe.com/docs"           # Often referenced in inline scripts or comments
    ],
    "paypal": [
        "api.paypal.com", "paypal.com", "paypal-sdk.com", "paypal.js", "paypalobjects.com",
        "paypal-button", "paypal-checkout-sdk", "paypal-sdk.js", "paypal-smart-button",
        "paypal-rest-sdk", "paypal-transaction", "itch.io/api-transaction/paypal",
        "PayPal.Buttons", "paypal.Buttons", "data-paypal-client-id",
        # New additions
        "paypal.com/sdk/js",        # PayPal JavaScript SDK URL
        "paypal.Order.create",      # Used in PayPal Orders API
        "paypal-checkout-component",# PayPal checkout component class
        "api-m.paypal.com",         # Mobile API endpoint
        "paypal-funding",           # Funding source attribute (e.g., paypal-funding=card)
        "paypal-hosted-fields",     # Hosted fields for custom integrations
        "paypal-transaction-id"      # Transaction ID in responses or forms
    ],
    "braintree": [
        "api.braintreegateway.com/v1", "braintreepayments.com", "js.braintreegateway.com", "client_token",
        "braintree.js", "braintree-hosted-fields", "braintree-dropin", "braintree-v3",
        "braintree-client", "braintree-data-collector", "braintree-payment-form",
        "braintree-3ds-verify",
        # New additions
        "client.create",            # Braintree client initialization
        "braintree.min.js",         # Minified Braintree SDK
        "assets.braintreegateway.com", # Static assets for Braintree scripts
        "braintree.setup",          # Legacy setup method
        "data-braintree",           # HTML attribute for Braintree forms
        "braintree.tokenize",       # Tokenization method for payment data
        "braintree-dropin-ui"       # Drop-in UI component identifier
    ],
    "adyen": [
        "checkoutshopper-live.adyen.com", "adyen.com/hpp", "adyen.js", "data-adyen",
        "adyen-checkout", "adyen-payment", "adyen-components", "adyen-encrypted-data",
        "adyen-cse", "adyen-dropin", "adyen-web-checkout", "live.adyen-services.com",
        # New additions
        "adyen.encrypt",            # Adyen Client-Side Encryption (CSE)
        "checkoutshopper-test.adyen.com", # Sandbox endpoint
        "adyen-checkout__component", # Class for Adyen checkout components
        "adyen.com/v1",             # Common API version path
        "adyen-payment-method",     # Payment method identifier in forms
        "adyen-action",             # 3D Secure or redirect actions
        "adyen.min.js"              # Minified Adyen SDK
    ],
    "authorize.net": [
        "authorize.net/gateway/transact.dll", "js.authorize.net/v1/Accept.js", "js.authorize.net", "anet.js",
        "data-authorize", "authorize-payment", "apitest.authorize.net", "accept.authorize.net",
        "authorize.net/gateway/transact.dll:", "api.authorize.net", "authorize-hosted-form",
        # New additions
        "merchantAuthentication",    # XML/JSON authentication object
        "data-api-login-id",        # HTML attribute for API Login ID
        "data-client-key",          # HTML attribute for Public Client Key
        "Accept.dispatchData",      # Accept.js method for tokenization
        "api.authorize.net/xml/v1", # Full API endpoint path
        "accept.authorize.net/payment", # Hosted payment form URL
        "authorize.net/profile"      # Customer profile management endpoint
    ],
    "square": [
        "squareup.com", "js.squarecdn.com", "square.js", "data-square",
        "square-payment-form", "square-checkout-sdk",
        # New additions
        "connect.squareup.com",     # Square Connect API endpoint
        "square.min.js",            # Minified Square SDK
        "squarecdn.com",
        "squareupsandbox.com",
        "sandbox.web.squarecdn.com",
        "square-payment-flow",      # Payment flow identifier
        "square.card",              # Square Card API for tokenization
        "squareup.com/payments",    # Payment processing URL
        "data-square-application-id", # HTML attribute for Square App ID
        "square.createPayment"      # Method for creating payments
    ],
    "klarna": [
        "klarna.com", "js.klarna.com", "klarna.js", "data-klarna",
        "klarna-checkout", "klarna-onsite-messaging",
        # New additions
        "playground.klarna.com",    # Sandbox environment for testing
        "klarna-payments",          # Klarna Payments API identifier
        "klarna.min.js",            # Minified Klarna SDK
        "klarna-order-id",          # Order ID in API responses
        "klarna-checkout-container", # Container for checkout widget
        "klarna-load",              # Klarna SDK initialization method
        "api.klarna.com"            # Klarna API endpoint
    ],
    "checkout.com": [
        "api.checkout.com", "cko.js", "data-checkout", "checkout-sdk",
        "checkout-payment", "js.checkout.com", "secure.checkout.com",
        # New additions
        "checkout.frames.js",       # Checkout.com Frames SDK
        "api.sandbox.checkout.com", # Sandbox API endpoint
        "cko-payment-token",        # Token identifier for payments
        "checkout.init",            # SDK initialization method
        "cko-hosted",               # Hosted checkout identifier
        "checkout.com/v2",          # API version path
        "cko-card-token"            # Card tokenization attribute
    ],
    "razorpay": [
        "checkout.razorpay.com", "razorpay.js", "data-razorpay",
        "razorpay-checkout", "razorpay-payment-api", "razorpay-sdk",
        "razorpay-payment-button", "razorpay-order-id",
        # New additions
        "api.razorpay.com",         # Razorpay API endpoint
        "razorpay.min.js",          # Minified Razorpay SDK
        "payment_box payment_method_razorpay",
        "razorpay",
        "cdn.razorpay.com",
        "rzp_payment_icon.svg",
        "razorpay.checkout",        # Checkout initialization method
        "data-razorpay-key",        # HTML attribute for API key
        "razorpay_payment_id",      # Payment ID in responses
        "checkout.razorpay.com/v1", # Full checkout endpoint
        "razorpay-hosted"           # Hosted checkout identifier
    ],
    "paytm": [
        "securegw.paytm.in", "api.paytm.com", "paytm.js", "data-paytm",
        "paytm-checkout", "paytm-payment-sdk", "paytm-wallet",
        # New additions
        "paytm.allinonesdk",        # Paytm All-in-One SDK
        "securegw-stage.paytm.in",  # Staging environment endpoint
        "paytm.min.js",             # Minified Paytm SDK
        "paytm-transaction-id",     # Transaction ID identifier
        "paytm.invoke",             # SDK initialization method
        "paytm-checkout-js",        # Checkout JavaScript identifier
        "data-paytm-order-id"       # HTML attribute for order ID
    ],
    "Shopify Payments": [
        "pay.shopify.com", "data-shopify-payments", "shopify-checkout-sdk",
        "shopify-payment-api", "shopify-sdk", "shopify-express-checkout",
        # New additions
        "shopify_payments.js",      # Shopify Payments SDK
        "checkout.shopify.com",     # Shopify checkout endpoint
        "shopify-payment-token",    # Payment token identifier
        "shopify.card",             # Card payment method
        "shopify-checkout-api",     # Checkout API identifier
        "data-shopify-checkout",    # HTML attribute for checkout
        "shopify.com/api"           # General Shopify API reference
    ],
    "worldpay": [
        "secure.worldpay.com", "worldpay.js", "data-worldpay",
        "worldpay-checkout", "worldpay-payment-sdk", "worldpay-secure",
        # New additions
        "secure-test.worldpay.com", # Sandbox environment endpoint
        "worldpay.min.js",          # Minified Worldpay SDK
        "worldpay.token",           # Tokenization method
        "worldpay-payment-form",    # Payment form identifier
        "access.worldpay.com",      # Access Worldpay API endpoint
        "worldpay-3ds",             # 3D Secure identifier
        "data-worldpay-token"       # HTML attribute for token
    ],
    "2checkout": [
        "www.2checkout.com", "2co.js", "data-2checkout", "2checkout-payment",
        "secure.2co.com", "2checkout-hosted",
        # New additions
        "api.2checkout.com",        # 2Checkout API endpoint
        "2co.min.js",               # Minified 2Checkout SDK
        "2checkout.token",          # Tokenization method
        "2co-checkout",             # Checkout identifier
        "data-2co-seller-id",       # HTML attribute for seller ID
        "2checkout.convertplus",    # ConvertPlus checkout method
        "secure.2co.com/v2"         # API version path
    ],
    "amazon_pay": [
        "payments.amazon.com", "amazonpay.js", "data-amazon-pay",
        "amazon-pay-button", "amazon-pay-checkout-sdk", "amazon-pay-wallet",
        # New additions
        "amazon-checkout.js",       # Amazon Pay checkout script
        "payments.amazon.com/v2",   # Amazon Pay API version
        "amazon-pay-token",         # Payment token identifier
        "amazon-pay-sdk",           # SDK identifier
        "data-amazon-pay-merchant-id", # HTML attribute for merchant ID
        "amazon-pay-signin",        # Sign-in integration
        "amazon-pay-checkout-session" # Checkout session identifier
    ],
    "apple_pay": [
        "apple-pay.js", "data-apple-pay", "apple-pay-button",
        "apple-pay-checkout-sdk", "apple-pay-session", "apple-pay-payment-request",
        # New additions
        "ApplePaySession",          # Apple Pay JavaScript API
        "apple-pay-merchant-id",    # Merchant ID attribute
        "apple-pay-payment",        # Payment processing identifier
        "apple-pay-sdk",            # Apple Pay SDK reference
        "data-apple-pay-token",     # HTML attribute for token
        "apple-pay-checkout",       # Checkout integration
        "apple-pay-domain"          # Domain registration for Apple Pay
    ],
    "google_pay": [
        "pay.google.com", "googlepay.js", "data-google-pay",
        "google-pay-button", "google-pay-checkout-sdk", "google-pay-tokenization",
        # New additions
        "payments.googleapis.com",  # Google Pay API endpoint
        "google.payments.api",      # Google Payments API reference
        "google-pay-token",         # Tokenization identifier
        "google-pay-payment-method", # Payment method identifier
        "data-google-pay-merchant-id", # HTML attribute for merchant ID
        "google-pay-checkout",      # Checkout integration
        "google-pay-sdk"            # Google Pay SDK reference
    ],
    "mollie": [
        "api.mollie.com", "mollie.js", "data-mollie", "mollie-checkout",
        "mollie-payment-sdk", "mollie-components",
        # New additions
        "mollie.min.js",            # Minified Mollie SDK
        "profile.mollie.com",       # Mollie profile API endpoint
        "mollie-payment-token",     # Payment token identifier
        "mollie-create-payment",    # Payment creation method
        "data-mollie-profile-id",   # HTML attribute for profile ID
        "mollie-checkout-form",     # Checkout form identifier
        "mollie-redirect"           # Redirect payment method
    ],
    "opayo": [
        "live.opayo.eu", "opayo.js", "data-opayo", "opayo-checkout",
        "opayo-payment-sdk", "opayo-form",
        # New additions
        "test.opayo.eu",            # Sandbox environment endpoint
        "opayo.min.js",             # Minified Opayo SDK
        "opayo-payment-token",      # Payment token identifier
        "opayo-3ds",                # 3D Secure identifier
        "data-opayo-merchant-id",   # HTML attribute for merchant ID
        "opayo-hosted",             # Hosted form identifier
        "opayo.api"                 # Opayo API reference
    ],
    "paddle": [
        "checkout.paddle.com", "paddle_button.js", "paddle.js", "data-paddle",
        "paddle-checkout-sdk", "paddle-product-id",
        # New additions
        "api.paddle.com",           # Paddle API endpoint
        "paddle.min.js",            # Minified Paddle SDK
        "paddle-checkout",          # Checkout identifier
        "data-paddle-vendor-id",    # HTML attribute for vendor ID
        "paddle.Checkout.open",     # Checkout initialization method
        "paddle-transaction-id",    # Transaction ID identifier
        "paddle-hosted"             # Hosted checkout identifier
    ]
}

# List of User-Agent strings
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Mobile Safari/537.36',
]

# Create cloudscraper instance
def create_scraper():
    scraper = cloudscraper.create_scraper(
        browser={'custom': random.choice(USER_AGENTS)}
    )
    scraper.mount('https://', requests.adapters.HTTPAdapter(max_retries=3))
    scraper.ssl_context = ssl.create_default_context()
    scraper.ssl_context.check_hostname = False
    scraper.ssl_context.verify_mode = ssl.CERT_NONE
    return scraper

# Fetch HTML content with cloudscraper
def fetch_url(url, max_retries=3):
    scraper = create_scraper()
    for attempt in range(max_retries):
        try:
            response = scraper.get(url, timeout=30)
            response.raise_for_status()
            html_content = response.text
            if not html_content.strip():
                return None, url
            return html_content, url
        except requests.RequestException as e:
            logger.error(f"[!] Error on attempt {attempt + 1} for {url}: {e}")
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
    return None, url

# Fetch secondary resources
def fetch_resource(url, max_retries=3):
    scraper = create_scraper()
    for attempt in range(max_retries):
        try:
            response = scraper.get(url, timeout=15)
            response.raise_for_status()
            html_content = response.text
            if not html_content.strip():
                return None, url
            return html_content, url
        except requests.RequestException as e:
            logger.error(f"[!] Error on attempt {attempt + 1} for {url}: {e}")
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
    return None, url

# Get all external resources
def get_all_sources(url, html_content):
    if not html_content or not html_content.strip():
        return []
    soup = BeautifulSoup(html_content, 'html.parser')
    sources = []
    for script in soup.find_all('script'):
        src = script.get('src')
        if src:
            full_url = urljoin(url, src)
            sources.append(full_url)
    for link in soup.find_all('link', rel='stylesheet'):
        href = link.get('href')
        if href:
            full_url = urljoin(url, href)
            sources.append(full_url)
    for iframe in soup.find_all('iframe'):
        src = iframe.get('src')
        if src:
            full_url = urljoin(url, src)
            sources.append(full_url)
    return sources

# Crawl main page and resources
def crawl(url, max_depth=2, visited=None):
    if visited is None:
        visited = set()
    if url in visited or max_depth < 0:
        return []
    visited.add(url)
    html_content, fetched_url = fetch_url(url)
    resources = []
    if html_content:
        resources.append((html_content, fetched_url))
        sources = get_all_sources(fetched_url, html_content)
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(fetch_resource, source): source for source in sources if urlparse(source).netloc}
            for future in as_completed(futures):
                resource_content, resource_url = future.result()
                if resource_content:
                    resources.append((resource_content, resource_url))
    return resources

# Detect features
def detect_features(html_content, file_url):
    if not html_content or not html_content.strip():
        return set(), set(), set(), set(), False, set(), "False"
    detected_gateways = set()
    detected_3d = set()
    detected_captcha = set()
    detected_platforms = set()
    detected_cards = set()
    cf_detected = False

    content_lower = html_content.lower()

    for gateway in PAYMENT_GATEWAYS:
        gateway_keywords = GATEWAY_KEYWORDS.get(gateway, [])
        if any(kw in content_lower for kw in gateway_keywords):
            detected_gateways.add(gateway.capitalize())
            if any(tds_kw in content_lower for tds_kw in THREE_D_SECURE_KEYWORDS):
                detected_3d.add(gateway.capitalize())

    for category, patterns in CAPTCHA_PATTERNS.items():
        if any(re.search(pattern, content_lower, re.IGNORECASE) for pattern in patterns):
            detected_captcha.add(f"{category} Found ✅")

    for keyword, name in PLATFORM_KEYWORDS.items():
        if keyword in content_lower:
            detected_platforms.add(name)

    for card in CARD_KEYWORDS:
        if card in content_lower:
            detected_cards.add(card.capitalize())

    cloudflare_identifiers = ['cloudflare', 'cf-ray', 'cf-chl-bypass']
    if any(identifier in content_lower for identifier in cloudflare_identifiers):
        cf_detected = True

    graphql_detected = "True" if "graphql" in content_lower else "False"

    return detected_gateways, detected_3d, detected_captcha, detected_platforms, cf_detected, detected_cards, graphql_detected

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

# Main scanning function for API
def scan_website(url: str) -> dict:
    try:
        # Validate URL
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = tldextract.extract(url)
        if not (parsed.domain and parsed.suffix) or url.isdigit() or not any(c.isalpha() for c in url):
            return {"success": False, "error": "Invalid URL! Please provide a valid website URL."}

        start_time = time.time()
        resources = crawl(url)
        if not resources:
            if "discord.com" in url.lower():
                return {"success": False, "error": "This site requires manual verification. Please check manually."}
            return {"success": False, "error": "Failed to scan the website or no valid content retrieved."}

        detected_gateways = set()
        detected_3d = set()
        detected_captcha = set()
        detected_platforms = set()
        cf_detected = False
        detected_cards = set()
        graphql_detected = "False"

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(detect_features, html, file_url): file_url for html, file_url in resources}
            for future in as_completed(futures):
                gateways, gateways_3d, captcha, platforms, cf, cards, graphql = future.result()
                detected_gateways.update(gateways)
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
            f"💳 Payment Gateways: {', '.join(sorted(detected_gateways)) if detected_gateways else 'None'}\n"
            f"🔒 Captcha: {', '.join(sorted(detected_captcha)) if detected_captcha else 'Not Found 🔥'}\n"
            f"☁️ Cloudflare: {'Found ✅' if cf_detected else 'Not Found 🔥'}\n"
            f"📊 GraphQL: {graphql_detected}\n"
            f"🏬 Platforms: {', '.join(sorted(detected_platforms)) if detected_platforms else 'Unknown'}\n"
            f"🌍 Country: {country_name}\n"
            f"🔐 3D Secure: {'ENABLED' if detected_3d else 'DISABLED'}"
        )

        return {
            "success": True,
            "result": result,
            "data": {
                "url": url,
                "time_taken": elapsed,
                "payment_gateways": sorted(detected_gateways),
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
    result = scan_website(str(url))
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])
    return result