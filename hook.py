import os
import re
import logging
import ansible_runner
from hashlib import sha256
from functools import wraps
from flask import request, abort
from flask import Flask, request
from hmac import HMAC, compare_digest

import hashlib
import hmac

secret_token = "8a7sb6dsab7dauaa8smasm09d"

def verify_sig(request, secret_token):
    """Verify that the payload was sent from GitHub by validating SHA256.

    Raise and return 403 if not authorized.

    Args:
        request: Flask request object
        secret_token: GitHub app webhook token (WEBHOOK_SECRET)
        signature_header: header received from GitHub (x-hub-signature-256)
    """
    print('verifying')
    # sig_header = req.headers.get('X-Hub-Signature-256').split('sha256=')[-1].strip()

    # if not sig_header:
    #     raise HTTPException(status_code=403, detail="x-hub-signature-256 header is missing!")
    
    # hash_object = hmac.new(secret_token.encode('utf-8'), msg=request.data, digestmod=sha256)
    # expected_signature = "sha256=" + hash_object.hexdigest()
    # if not hmac.compare_digest(expected_signature, signature_header):
    #     raise HTTPException(status_code=403, detail="Request signatures didn't match!")



# def validate_data(validator_func):
#     @wraps(validator_func)
#     def wrapper(*args, **kwargs):
#         if not validator_func(request.json):
#             abort(400, 'Invalid request data')
#         return validator_func(*args, **kwargs)
#     return wrapper

# @app.route('/api/endpoint', methods=['POST'])
# @validate_data(request)
# def handle_data():
#     # ...


# class InvalidAuthorization(Exception):
#     def __str__(self):
#         return "Could not validate hook Authorization :("

# class ServerError(Exception):
#     def __str__(self):
#         return "Could not connect to server."

app = Flask(__name__)

def verify(req):
    print("verifying")
    s = b'869557cf13a3c3bac286eeb6a450a4a9b180c97d784a9c71'
    recv = req.headers.get('X-Hub-Signature-256').split('sha256=')[-1].strip()
    if not recv:
        print("not recieved")
        return
    else:
        print('headers pulled', recv)
    sign = HMAC(key=s, msg=req.data, digestmod=sha256).hexdigest()
    print('verifying sig')
    verified = compare_digest(recv, sign)
    if not verified:
        exit()
        raise InvalidAuthorization
    return verified

@app.route('/pwnvault/push/main', methods = ['POST'])
@verify_sig(request, secret_token)
def hooklistener():
    # try:
    print('hook received, verifying.')

        # v = verify(request)

        # print(v)
        # if v:
        #     print('verified')
        #     r = ansible_runner.run(private_data_dir='/home/ans/', playbook='deploy.yml')
        #     print(r.stdout)
        #     print(r.stderr)
        # response = r.get(
        #     f"http://127.0.0.1:3000/api/v1/repos/nyx/netcrack/git/commits/{j['after']}",
        #     headers = auth
        # )
        # if response.status_code in [404, 500]:
        #     raise ServerError

        # files_list = json.loads(response.text)['files']
        # for file_info in files_list:
        #     filename = file_info['filename']
        #     if filename.endswith('.md'):
        # # md_list = get_changed_md_files(response.text)

        # # if not md_list:
        # #     raise RegexReturnedNothing
        # # # Send list (l) off to be verified and parsed
        # # for md in md_list:
        #         file_git_url = f"http://127.0.0.1:3000/nyx/netcrack/raw/branch/main/{filename}"
        #         response = r.get(file_git_url)
        #         if response.status_code == 200:
        #             print(filename, response.text, 200)

    # except ServerError:
    #     pass

    # except InvalidAuthorization:
    #     pass

    # return 'Git pull success', 200

if __name__ == "__main__":
    app.run(debug=True)
