from flask import current_app, request

class SimpleActionsLib: 

    def s_print(*args, **kwargs):
        print('args: ', args)
        print('kwargs :', kwargs)
    
    def return_something(*args, **kwargs):
        a = 1
        return a

def deploy(*args, **kwargs):
    print("app deployed")
    return args

class Config(object):
    LHOST: str = "127.0.0.1"
    LPORT: int = 5002
    HOOK_SECRETS: list[str] = ['super-secret-key-4']
    ALLOWED_HOSTS: [
        "127.0.0.1",
        'localhost'
    ]
    GLOBAL_PREPATH_ACTIONS: list[object] = [
        SimpleActionsLib.s_print,
        SimpleActionsLib.return_something,
# This one will cause an errors because its not callable
        'test'
    ]
# Assign actions to specific url paths using a dictionary with each path being a key pointing to a list
    PATH_SPECIFIC_ACTIONS: dict = {
        'push/main': [
            deploy
            ]
    }