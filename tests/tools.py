import sys
import json
import hmac
import requests
from hashlib import sha256

def request_with_hmac(url, key):
    data = {
        'test': 'test data'
    }

    sig = hmac.new(key.encode('utf-8'), msg=json.dumps(data).encode('utf-8'), digestmod=sha256).hexdigest()

    headers = {
        'X-Hub-Signature-256': f'sha256={sig}'
    }
    print(data)
    print(headers)
    return requests.get(url, data=json.dumps(data), headers=headers)


if __name__ == "__main__":
    url = sys.argv[1]
    key = sys.argv[2]

    r = request_with_hmac(url, key)

    print(r.status_code, r.text)