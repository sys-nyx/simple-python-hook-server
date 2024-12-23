import hmac
import hashlib
from hashlib import sha256
from functools import wraps
from flask import Flask, request, abort


#### https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries ##
def verify_signature(flask_route):
    """Verify that the payload was sent from GitHub by validating SHA256.

    Call Flask abort with 403 if not authorized, 400 if missing signature
    """

    @wraps(flask_route)
    def validate_route(*args, **kwargs):
        if not kwargs:
            kwargs["request_path"] = "/"

        secret_token = ""

        sig_header = request.headers.get('X-Hub-Signature-256')
        if not sig_header:
            return abort(400, "")

        request_sig = sig_header.split('sha256=')[-1].strip()

        expected_sig = hmac.new(
### Use the flask request object here ###################################################
            secret_token.encode('utf-8'),
            msg=request.data, 
            digestmod=sha256
            ).hexdigest()
        
        sig_match = hmac.compare_digest(expected_sig, request_sig)

        if sig_match:
            return flask_route(*args, **kwargs)

        else:
            abort(403)

    return validate_route
