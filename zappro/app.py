from flask import Flask, render_template, request
from zapv2 import ZAPv2
import time

app = Flask(__name__)

# OWASP ZAP API key and setup
API_KEY = 'gcdujoem61icdtgikikr7q2s6s'
ZAP_URL = 'http://localhost:8080'
zap = ZAPv2(apikey=API_KEY, proxies={'http': ZAP_URL, 'https': ZAP_URL})

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url_to_scan = request.form['url']
    scan_type = request.form['scan_type']

    # Start a new session in ZAP
    zap.core.new_session('my_session', overwrite=True)

    if scan_type == 'spider':
        # Start the spider to crawl the target website
        spider_scan_id = zap.spider.scan(url_to_scan)

        # Validate spider_scan_id and check if it's a valid scan
        if not spider_scan_id.isdigit():
            return f"Error: The spider scan ID is invalid - {spider_scan_id}"

        # Wait for the spider scan to complete
        while True:
            spider_status = zap.spider.status(spider_scan_id)
            if spider_status.isdigit() and int(spider_status) >= 100:
                break
            elif spider_status == 'does_not_exist':
                return f"Error: Spider scan ID does not exist. Scan might have failed."
            time.sleep(5)

    if scan_type == 'active':
        # Start the active scan to find vulnerabilities
        active_scan_id = zap.ascan.scan(url_to_scan)

        # Validate active_scan_id and check if it's a valid scan
        if not active_scan_id.isdigit():
            return f"Error: The active scan ID is invalid - {active_scan_id}"

        # Wait for the active scan to complete
        while True:
            active_status = zap.ascan.status(active_scan_id)
            if active_status.isdigit() and int(active_status) >= 100:
                break
            elif active_status == 'does_not_exist':
                return f"Error: Active scan ID does not exist. Scan might have failed."
            time.sleep(5)

    # Retrieve the alerts found during the scan
    alerts = zap.core.alerts()

    return render_template('results.html', url=url_to_scan, alerts=alerts)

if __name__ == '__main__':
    app.run(debug=True, port=5566)
