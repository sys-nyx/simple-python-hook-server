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



def print_action(*args, **kwargs):
    """
    Default function meant to demonstrate the functionality 

    """
    print(request)
    print(current_app)
    print(args, kwargs)

def root_action(*args, **kwargs):
    print("Root Actions")
    print(args, kwargs)

class BaseConfig:
    LPORT = 5001
    LHOST = "127.0.0.1"
    HOOK_SECRETS = [
        "secret-key1",
        "secret-key2",
        "secret-key3",
        "secret-key4",
        "secret-key5",
        "secret-key6",
        "secret-key7",
        "secret-key8",
        "secret-key9",
        "secret-key0",
        "secret-key10",
        ]

    DEBUG = True

    GLOBAL_PRE_ACTIONS = [
        print_action
    ]

    PATH_ACTIONS = {
        "/": [root_action]
    }

def generate_sig(key, request):
    return hmac.new(key.encode('utf-8'),msg=request.data,digestmod=sha256).hexdigest()

#### https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries ###
def verify_signature(flask_route):
    """Verify that the payload was sent from GitHub by validating SHA256.

    Call Flask abort with 403 if not authorized, 400 if missing signature
    """

    @wraps(flask_route)
    def validate_route(*args, **kwargs):

### Assign '/' to kwargs if empty, so that a path always gets passed to request_path var in the global hook ###
        if not kwargs:
            kwargs["request_path"] = "/"

        sig_header = request.headers.get('X-Hub-Signature-256')
        if not sig_header:
            return abort(400, "")

        request_sig = sig_header.split('sha256=')[-1].strip()

### Generate potential signatures from list of keys ###
        possible_sigs = list(
            map(
                lambda s: generate_sig(s, request), current_app.config['HOOK_SECRETS']
                )
            )
### Compare recieved signature to list of acceptable signatures
        if any(
            list(
                map(
                    lambda p: hmac.compare_digest(p, request_sig), possible_sigs
                    )
                )
            ):
            return flask_route(*args, **kwargs)


    return validate_route


def import_config(config_path: str) -> object: 
    """
    Load and import a module from 
    """
    spec = importlib.util.spec_from_file_location(config_path)
    spec.submodule_search_locations = [os.path.dirname(config_path)]
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
### Expects
    return module.hookConfig

def call_func(f, *args):
    if callable(f):
        f(args)

app = Flask(__name__)
app.config.from_object(BaseConfig)
### To capture all possible paths, both '/' and '/<request_path> must be defined as routes or 
### requests to the root url will 404. 
### https://stackoverflow.com/questions/15117416/capture-arbitrary-path-in-flask-route
@app.route('/')
@app.route('/<path:request_path>', methods=['GET', 'POST'])
@verify_signature
def global_hook(request_path):
    any(call_func(a, current_app, request) for a in current_app.config["GLOBAL_PRE_ACTIONS"])



    return 'Success', 200

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c','--config', type=str, help="Path to file containing a flask config object.")
    args = parser.parse_args()


### Apply the basic config and then the custom config, this way the base config (and flasks default config) are
### overwritten by the custom one 
    if args.config:
        config_obj = import_config(args.config)
        app.config.from_object(config_obj())

    app.run(host=app.config['LHOST'], port=app.config['LPORT'], debug=app.config['DEBUG'])
