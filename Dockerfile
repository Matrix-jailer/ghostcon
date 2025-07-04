# Use official Python slim image
FROM python:3.11-slim

# Install system dependencies for Playwright, Chrome, and scraping tools
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    curl \
    gnupg \
    gnupg2 \
    ca-certificates \
    fonts-liberation \
    libappindicator3-1 \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdbus-1-3 \
    libgdk-pixbuf2.0-0 \
    libnspr4 \
    libnss3 \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libu2f-udev \
    xdg-utils \
    net-tools \
    iproute2 \
    dnsutils \
    libxss1 \
    libgbm1 \
    --no-install-recommends && rm -rf /var/lib/apt/lists/*

# Add Google Chrome repo and install Chrome
RUN curl -fsSL https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /etc/apt/trusted.gpg.d/google.gpg && \
    echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list && \
    apt-get update && apt-get install -y google-chrome-stable && \
    rm -rf /var/lib/apt/lists/*

# Install ChromeDriver version 138 (for Chrome 138)
RUN wget -O /tmp/chromedriver.zip https://storage.googleapis.com/chrome-for-testing-public/138.0.7204.49/linux64/chromedriver-linux64.zip && \
    unzip /tmp/chromedriver.zip -d /usr/local/bin/ && \
    mv /usr/local/bin/chromedriver-linux64/chromedriver /usr/local/bin/chromedriver && \
    chmod +x /usr/local/bin/chromedriver && \
    rm -rf /tmp/chromedriver.zip

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ✅ Install Playwright and its browsers (Chromium, Firefox, WebKit)
RUN apt-get update && apt-get install -y wget && \
    pip install playwright && \
    playwright install --with-deps

# Copy your app code
COPY . .

# Set environment and port
ENV PORT=8000
EXPOSE 8000

# Start the app
CMD ["uvicorn", "GhostAPIPRO:app", "--host", "0.0.0.0", "--port", "8000"]
