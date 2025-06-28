from seleniumwire import webdriver
import undetected_chromedriver as uc
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException, WebDriverException
from urllib.parse import urlparse
import threading
import time
import logging
import os
import tempfile
from contextlib import contextmanager
import random
from fastapi import FastAPI

# Logging setup
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logging.getLogger('seleniumwire').setLevel(logging.WARNING)
logging.getLogger('undetected_chromedriver').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

# Helper functions
@contextmanager
def temp_chromedriver():
    temp_driver = tempfile.NamedTemporaryFile(suffix='_chromedriver', delete=False)
    temp_driver_path = temp_driver.name
    temp_driver.close()
    try:
        os.system(f"cp /usr/local/bin/chromedriver {temp_driver_path}")
        os.chmod(temp_driver_path, 0o755)
        yield temp_driver_path
    finally:
        try:
            os.unlink(temp_driver_path)
            logger.debug(f"[Cleanup] Deleted temporary ChromeDriver: {temp_driver_path}")
        except Exception as e:
            logger.warning(f"[Cleanup Error] Failed to delete temp ChromeDriver {temp_driver_path}: {e}")

def extract_deep_html(driver):
    html_chunks = []
    try:
        # Main page HTML
        html_chunks.append(driver.page_source)
        
        # Extract iframes
        try:
            iframes = driver.find_elements(By.TAG_NAME, "iframe")
            for i, iframe in enumerate(iframes):
                try:
                    driver.switch_to.frame(iframe)
                    html_chunks.append(driver.page_source)
                    driver.switch_to.default_content()
                except Exception as e:
                    logger.warning(f"[Deep HTML] Failed to access iframe #{i}: {e}")
        except Exception as e:
            logger.warning(f"[Deep HTML] Error iterating iframes: {e}")
        
        # Extract Shadow DOMs
        try:
            shadow_doms = driver.execute_script("""
                return Array.from(document.querySelectorAll('*'))
                    .filter(el => el.shadowRoot)
                    .map(el => el.shadowRoot.innerHTML);
            """)
            html_chunks.extend(shadow_doms)
        except Exception as e:
            logger.warning(f"[Deep HTML] Failed to read Shadow DOMs: {e}")
        
        return html_chunks
    except Exception as e:
        logger.error(f"[Deep HTML] Unexpected error: {e}")
        return html_chunks

def create_selenium_wire_driver():
    max_retries = 3
    for attempt in range(max_retries):
        try:
            logger.info(f"[UDC] Initializing undetected-chromedriver with SeleniumWire (Attempt {attempt + 1}/{max_retries})")
            options = Options()
            options.add_argument("--headless=new")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument("--disable-extensions")
            options.add_argument("--window-size=1920,1080")
            options.add_argument("--disable-blink-features=AutomationControlled")
            options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36")
            options.add_argument("--disable-site-isolation-trials")
            options.add_argument("--disable-features=IsolateOrigins,site-per-process")
            options.add_argument("--disable-background-networking")

            seleniumwire_options = {
                'verify_ssl': False,
                'enable_har': True,
                'request_storage_base_dir': '/tmp/seleniumwire-storage',
                'timeout': 10,
                'port': random.randint(49152, 65535),
                'addr': '127.0.0.1'
            }

            with temp_chromedriver() as temp_driver_path:
                service = Service(executable_path=temp_driver_path, port=random.randint(49152, 65535))
                uc_driver = uc.Chrome(
                    options=options,
                    service=service,
                    version_main=138,
                    use_subprocess=True,
                    driver_executable_path=temp_driver_path
                )
                driver = webdriver.Chrome(
                    service=uc_driver.service,
                    options=options,
                    seleniumwire_options=seleniumwire_options
                )
                uc_driver.quit()
                driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
                    "source": """
                        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                        window.navigator.chrome = { runtime: {} };
                        Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3] });
                        Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
                    """
                })
                try:
                    driver.get("about:blank")
                    driver.requests
                    logger.debug("[UDC] Network capture verified")
                except AttributeError as e:
                    logger.error(f"[UDC] Network capture failed: {e}")
                    raise
                logger.info("[UDC] Undetected Chrome initialized with SeleniumWire")
                return driver
        except Exception as e:
            logger.error(f"[UDC Init Error] Failed to create driver on attempt {attempt + 1}: {e}")
            if attempt == max_retries - 1:
                raise
            time.sleep(1)

def fetch_url_selenium(url, timeout=15):
    driver = None
    try:
        driver = create_selenium_wire_driver()
        driver.get(url)
        WebDriverWait(driver, timeout).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        html_chunks = extract_deep_html(driver)
        combined_html = "\n".join(html_chunks)
        final_url = driver.current_url
        return combined_html, final_url
    except (TimeoutException, WebDriverException) as e:
        logger.error(f"[Selenium Error] Fetching {url}: {e}")
        return "", url
    except Exception as e:
        logger.error(f"[Unexpected Error] Fetching {url}: {e}")
        return "", url
    finally:
        if driver:
            try:
                driver.quit()
            except Exception as e:
                logger.warning(f"[Selenium Quit Error] Failed to quit driver: {e}")

def scan_website_v2(url, max_depth=2, timeout=None):
    start_time = time.time()
    visited = []
    content_hashes = []
    detected_gateways = []

    detected_gateways_set = set()
    detected_3d = set()
    detected_captcha = set()
    detected_platforms = set()
    cf_detected = False
    detected_cards = set()
    graphql_detected = "False"

    base_domain = urlparse(url).netloc

    def process(html, page_url):
        nonlocal detected_gateways_set, detected_3d, detected_captcha, detected_platforms, cf_detected, detected_cards, graphql_detected
        gw_set, tds, captcha, platforms, cf, cards, gql = detect_features(html, page_url, detected_gateways)
        detected_gateways_set |= gw_set
        detected_3d |= tds
        detected_captcha |= captcha
        detected_platforms |= platforms
        detected_cards |= cards
        if cf: cf_detected = True
        if gql == "True": graphql_detected = "True"

    def crawl_and_scrape():
        if timeout and time.time() - start_time > timeout:
            logger.info("[Timeout] Reached timeout limit, stopping scan early.")
            return
        args = (url, max_depth, visited, content_hashes, base_domain, detected_gateways)
        results = crawl_worker(args)
        for html, page_url in results:
            if timeout and time.time() - start_time > timeout:
                logger.info("[Timeout] Scraper loop exited early during processing.")
                return
            process(html, page_url)

    def crawl_and_network():
        nonlocal detected_gateways_set, detected_3d, detected_captcha, detected_platforms, cf_detected, detected_cards, graphql_detected
        driver = None
        try:
            logger.info(f"[Debug] Processing URL: {url} with UDC")
            driver = create_selenium_wire_driver()
            logger.info("[Debug] UDC SeleniumWire driver initialized")
            try:
                driver.get(url)
                WebDriverWait(driver, 15).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
                logger.info("[Debug] Page loaded successfully")
            except TimeoutException as e:
                logger.warning(f"[Debug] Page load timeout for {url}: {e}")
                html = driver.page_source.lower()
                if "cloudflare" in html or "please wait" in html or "checking your browser" in html:
                    logger.info("[Debug] Cloudflare challenge detected, UDC should handle it")
                raise TimeoutException(f"Page load failed for {url}")

            if timeout and time.time() - start_time > timeout:
                logger.info("[Timeout] Reached timeout limit, stopping scan early.")
                return

            try:
                driver.execute_script("""
                window.__capturedFetches = [];
                const originalFetch = window.fetch;
                window.fetch = async function(...args) {
                    const response = await originalFetch(...args);
                    const clone = response.clone();
                    try {
                        const bodyText = await clone.text();
                        window.__capturedFetches.push({
                            url: args[0],
                            method: (args[1] && args[1].method) || 'GET',
                            body: (args[1] && args[1].body) || '',
                            response: bodyText
                        });
                    } catch (e) {}
                    return response;
                };
                """)
                time.sleep(4)
            except Exception as e:
                logger.warning(f"[Fetch Hook Error] Failed to inject fetch hook: {e}")

            try:
                fetch_logs = driver.execute_script("return window.__capturedFetches || []")
                for entry in fetch_logs:
                    combined = f"{entry['url']} {entry['body']} {entry['response']}".lower()
                    gw_set, tds, cap, plat, cf, cards, gql = detect_features(combined, entry['url'], detected_gateways)
                    detected_gateways_set |= gw_set
                    detected_3d |= tds
                    detected_captcha |= cap
                    detected_platforms |= plat
                    detected_cards |= cards
                    if cf: cf_detected = True
                    if gql == "True": graphql_detected = "True"
            except Exception as e:
                logger.warning(f"[Fetch Hook Error] Failed to retrieve fetch logs: {e}")

            try:
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                time.sleep(2)
            except Exception as e:
                logger.warning(f"[Scroll Error] Failed to scroll page: {e}")

            try:
                clickable_keywords = ["buy", "subscribe", "checkout", "payment", "plan", "join", "start"]
                buttons = driver.find_elements(By.TAG_NAME, "button") + driver.find_elements(By.TAG_NAME, "a")
                for btn in buttons:
                    text = btn.text.strip().lower()
                    if any(kw in text for kw in clickable_keywords):
                        btn.click()
                        time.sleep(3)
            except Exception as e:
                logger.warning(f"[Click Error] Failed to click buttons: {e}")

            try:
                for req in driver.requests:
                    if not req.response:
                        continue
                    req_url = req.url.lower()
                    if any(bad in req_url for bad in ignore_if_url_contains):
                        continue
                    body = (req.body or b"").decode("utf-8", errors="ignore")
                    combined_content = (req_url + " " + body).lower()

                    if (
                        "client_secret" in combined_content or
                        "publishable_key" in combined_content or
                        "checkout.stripe.com" in combined_content or
                        ("js.stripe.com" in combined_content and "stripe" in combined_content)
                    ):
                        logger.info(f"[Net Gateway Match] STRIPE-like signal in {req.url}")
                        gw_set, tds, cap, plat, cf, cards, gql = detect_features(combined_content, req.url, detected_gateways)
                        detected_gateways_set |= gw_set
                        detected_3d |= tds
                        detected_captcha |= cap
                        detected_platforms |= plat
                        detected_cards |= cards
                        if cf: cf_detected = True
                        if gql == "True": graphql_detected = "True"
                    elif "paypal.com/sdk/js" in combined_content or "paypal" in req_url:
                        logger.info(f"[Net Gateway Match] PAYPAL-like signal in {req.url}")
                        gw_set, tds, cap, plat, cf, cards, gql = detect_features(combined_content, req.url, detected_gateways)
                        detected_gateways_set |= gw_set
                        detected_3d |= tds
                        detected_captcha |= cap
                        detected_platforms |= plat
                        detected_cards |= cards
                        if cf: cf_detected = True
                        if gql == "True": graphql_detected = "True"
                    elif any(p in req_url for p in network_payment_url_keywords):
                        logger.info(f"[Net Gateway Signal] Generic payment activity in {req.url}")
                        gw_set, tds, cap, plat, cf, cards, gql = detect_features(combined_content, req.url, detected_gateways)
                        detected_3d |= tds
                        detected_captcha |= cap
                        detected_platforms |= plat
                        detected_cards |= cards
                        if cf: cf_detected = True
                        if gql == "True": graphql_detected = "True"
            except AttributeError as e:
                logger.error(f"[Network Capture Error] Failed to access driver.requests: {e}")
            except Exception as e:
                logger.error(f"[Network Capture Error] Unexpected error in network capture: {e}")

        except Exception as e:
            logger.error(f"[SeleniumWire Error] Exception for URL {url}: {e}")
        finally:
            if driver:
                try:
                    driver.quit()
                    logger.info("[Debug] UDC SeleniumWire driver closed")
                except Exception as e:
                    logger.warning(f"[Selenium Quit Error] Failed to quit driver: {e}")

    t1 = threading.Thread(target=crawl_and_scrape)
    t2 = threading.Thread(target=crawl_and_network)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    ip = get_ip(base_domain)
    country_name = get_country_from_tld_or_ip(url, ip)

    return {
        "url": url,
        "payment_gateways": sorted(detected_gateways_set),
        "3d_secure": sorted(detected_3d),
        "captcha": sorted(detected_captcha),
        "platforms": sorted(detected_platforms),
        "cloudflare": cf_detected,
        "graphql": graphql_detected,
        "cards": sorted(detected_cards),
        "country": country_name,
        "ip": ip
    }

# FastAPI endpoint
app = FastAPI()

@app.get("/sexy_api/v2/gate")
async def gate(url: str, timeout: int = None):
    result = scan_website_v2(url, max_depth=2, timeout=timeout)
    return result
