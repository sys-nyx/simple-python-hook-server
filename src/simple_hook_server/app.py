import os
import sys
import hmac
import time
import logging
import hashlib
import argparse
import importlib
from hashlib import sha256
from functools import wraps
from flask import Flask, request, abort, current_app

# class hookConfig:
#     allow_paths = [
#         '/',
#     ]

#     disallow_paths = [
#         '/test'
#     ]
#### https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries ##
def verify_signature(flask_route):
    """Verify that the payload was sent from GitHub by validating SHA256.

    Call Flask abort with 403 if not authorized, 400 if missing signature
    """

    @wraps(flask_route)
    def validate_route(*args, **kwargs):
        print(current_app.config['FUNCTION_PATHS'])

        if not kwargs:
            kwargs["request_path"] = "/"
        # TODO: Pull list of tokens from config file
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


def import_config(config_path: str) -> object: 
    """
    Load and import a module from 
    """
    spec = importlib.util.spec_from_file_location('hookConf', config_path)
    spec.submodule_search_locations = [os.path.dirname(config_path)]
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
### Expects
    return module.hookConfig

app = Flask(__name__)
### To capture all possible paths, both '/' and '/<request_path> must be defined as routes or 
### requests to the root url will 404. 
### https://stackoverflow.com/questions/15117416/capture-arbitrary-path-in-flask-route
@app.route('/')
@app.route('/<path:request_path>', methods=['GET', 'POST'])
@verify_signature
def global_hook(request_path):
    return 'Success', 200



@app.route('/test/<other_var>', methods=['GET', 'POST'])
def test_hook(other_var):
    print(current_app.config["ALLOWED_PATHS"])
    return 'Success', 200



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c','--config', type=str, help="Path to file containing a flask config object.")
    args = parser.parse_args()
    if args.config:
        config_obj = import_config(args.config)
        app.config.from_object(config_obj())

    app.run(debug=True)
