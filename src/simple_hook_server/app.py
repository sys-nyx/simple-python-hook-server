import os
import sys
import hmac
import time
import logging
import hashlib
import argparse
import importlib
import ipaddress
import dns.resolver
from hashlib import sha256
from functools import wraps
from flask import Flask, request, abort, current_app

class BaseActions:
    """
    This class is meant to provide 
    """
    def print_request_info(*args, **kwargs):
        """
        Default function meant to demonstrate the functionality 

        """
        print(args, kwargs)

    def root_path_action(*args, **kwargs):
        print("Root Path Action")

class BaseConfig:

    LPORT = 5001 # Port to listen on. 
    LHOST = "127.0.0.1" # Address or interface to listen on.
    ALLOWED_HOSTS = [
        "localhost"
    ]
    RESOLVE_HOSTNAMES = True
###########################################################################
###########################################################################
# Make sure to overwrite the following sections by defining a 
# list of secrets and custom actions in a custom config file.
    HOOK_SECRETS = [
        "super-secret-key-1",
        "super-secret-key-2",
        "super-secret-key-3"
        ]

    DEBUG = True

    GLOBAL_PREPATH_ACTIONS = [
        BaseActions.print_request_info,
        'This is a reminder to update your config!!!'
    ]

    PATH_SPECIFIC_ACTIONS = {
        "/": [
            BaseActions().root_path_action
            ]
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
### Compare recieved signature to list of acceptable signatures. If any match, retunr the flask route.
        if any(
            list(
                map(
                    lambda p: hmac.compare_digest(p, request_sig), possible_sigs
                    )
                )
            ):
            return flask_route(*args, **kwargs)

        return abort(401)
    return validate_route

def import_config(config_path: str) -> object: 
    """
    Load and import a module from 
    """
    spec = importlib.util.spec_from_file_location('Config', config_path)
    spec.submodule_search_locations = [os.path.dirname(config_path)]
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
# Expects name of class definied in config file to be "Config"
    return module.Config

class Result(object):
    def __init__(self, func, *args, **kwargs):
        self.func = func
        self.result = func(*args,**kwargs)
    def __repr__(self):
        return f"<results for func {self.func.__name__} result={self.result}>"

class Results(object):
    def __init__(self, result_obj):
        self.results = {}
        if result_obj.result:
            self.results.update(result_obj.func.__name__, result_obj)

def call_func(f, *args, **kwargs):
    if callable(f):
        return Result(f, args, kwargs)


def is_ipaddress(ip):
    try:
        ip = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return True

app = Flask(__name__)
app.config.from_object(BaseConfig)

# To capture all possible paths, both '/' and '/<request_path> must be defined as routes or 
# requests to the root url will 404. 
# https://stackoverflow.com/questions/15117416/capture-arbitrary-path-in-flask-route
@app.route('/')
@app.route('/<path:request_path>', methods=['GET', 'POST'])
@verify_signature
def global_hook(request_path):
    """
    Global hook
    """
    results = []
    results = [
        call_func(
            a, 
            current_app, 
            request, 
            results=results
            ) 
            for a in current_app.config["GLOBAL_PREPATH_ACTIONS"] if callable(a)
        ]


    if request_path in current_app.config["PATH_SPECIFIC_ACTIONS"].keys():
        results = results + [
            call_func(
                a, 
                current_app, 
                request, 
                results=results
                ) 
                for a in current_app.config["PATH_SPECIFIC_ACTIONS"][request_path] if callable(a)
            ]
    return 'Success', 200

@app.before_request
def block_m():
    ip = request.environ.get('REMOTE_ADDR')
    ips = [h for h in current_app.config["ALLOWED_HOSTS"] if is_ipaddress(h)]
    for a in current_app.config["ALLOWED_HOSTS"]:
        resolved_names = [h.to_text() for h in dns.resolver.resolve(a, 'A') if not is_ipaddress(a)]
    allowed_ips = ips + resolved_names

    if ip not in allowed_ips:
        abort(403)





if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c','--config', type=str, help="Path to file containing a flask config object.")
    args = parser.parse_args()


### Apply the basic config and then the custom config, this way the base config (and flasks default config) are
### overwritten by the custom one 
    if args.config:
        config_obj = import_config(args.config)
        app.config.from_object(config_obj)

        if not all(map(callable, app.config["GLOBAL_PREPATH_ACTIONS"])):
            print("""\N{ESC}[31mThere seems to be an error in your configuration. One or more functions specified in GLOBAL_PREPATH_ACTIONS can not be called. It wil be ignored.\u001b[0m""")
            for a in app.config["GLOBAL_PREPATH_ACTIONS"]:
                if not callable(a):
                    app.config["GLOBAL_PREPATH_ACTIONS"].remove(a)

    app.run(
        host=app.config['LHOST'], 
        port=app.config['LPORT'], 
        debug=app.config['DEBUG'])
