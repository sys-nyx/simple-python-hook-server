from verify import verify_signature
from flask import Flask, request, abort

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
@verify_signature
def test_hook(other_var):
    return 'Success', 200


if __name__ == "__main__":
    app.run(debug=True)
