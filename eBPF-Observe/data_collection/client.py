import requests
import time
import json
import sys

SERVER_URL = "http://127.0.0.1:8080"
REQUEST_INTERVAL_MS = 200
TIMEOUT_MS = 5000
metrics = []
request_id = 0

while True:
    request_id += 1
    start_time = time.time()
    try:
        response = requests.get(
            SERVER_URL,
            timeout=TIMEOUT_MS / 1000.0
        )
        end_time = time.time()
        latency_ms = (end_time - start_time) * 1000
        result = "success"
        status_code = response.status_code
    except requests.exceptions.Timeout:
        end_time = time.time()
        latency_ms = (end_time - start_time) * 1000
        result = "timeout"
        status_code = None
    except Exception as e:
        end_time = time.time()
        latency_ms = (end_time - start_time) * 1000
        result = f"error: {str(e)}"
        status_code = None
    
    metric = {
        "request_id": request_id,
        "start_time": start_time,
        "end_time": end_time,
        "latency_ms": latency_ms,
        "result": result,
        "status_code": status_code
    }
    metrics.append(metric)
    
    # Print progress to stderr (not part of JSON output)
    print(f"Request {request_id}: {latency_ms:.2f} ms - {result}", file=sys.stderr)
    time.sleep(REQUEST_INTERVAL_MS / 1000.0)
    
    if request_id == 10:
        break

# Output only JSON to stdout
print(json.dumps(metrics, indent=2))
