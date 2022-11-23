import hashlib
import os
from web3 import Web3
from flask import Flask, json, request, abort
import datetime
from dotenv import load_dotenv
import os
from flask_cors import CORS
from functools import wraps
from werkzeug.utils import secure_filename
import firebase_admin
from firebase_admin import credentials, auth

load_dotenv()

# Flask constructor takes the name of
# current module (__name__) as 	argument.
app = Flask(__name__)
CORS(app)

app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000
app.config['UPLOAD_EXTENSIONS'] = ['.pdf']

alchemy_url = os.environ['alchemy_url']
w3 = Web3(Web3.HTTPProvider(alchemy_url))

abi_open_json = open('./abi.json')
abi = json.load(abi_open_json)

sender_address = os.environ["sender_address"]
contract_address = os.environ["contract_address"]
private_key = os.environ["wallet_private_key"]
contract = w3.eth.contract(address=contract_address, abi=abi)

# Connect to firebase
fb_cert = {
    "type": os.environ["type"],
    "project_id": os.environ["project_id"],
    "private_key_id": os.environ["private_key_id"],
    "private_key": os.environ["private_key"].replace('\\n', '\n'),
    "client_email": os.environ["client_email"],
    "client_id": os.environ["client_id"],
    "auth_uri": os.environ["auth_uri"],
    "token_uri": os.environ["token_uri"],
    "auth_provider_x509_cert_url": os.environ["auth_provider_x509_cert_url"],
    "client_x509_cert_url": os.environ["client_x509_cert_url"]
}

cred = credentials.Certificate(fb_cert)
firebase = firebase_admin.initialize_app(cred)

# Use to authenticate each route with a token


def check_token(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if not request.headers.get('authorization'):
            return {'message': 'No token provided'}, 400
        try:
            user = auth.verify_id_token(request.headers['authorization'])
            request.user = user
        except:
            return {'message': 'Invalid token provided.'}, 400
        return f(*args, **kwargs)
    return wrap

# Function for getting the hash of file


def hash_file(filename):
    h = hashlib.sha256()

    with open(filename, 'rb') as file:
        chunk = 0
        while chunk != b'':
            chunk = file.read(1024)
            h.update(chunk)

    return h.hexdigest()

# Routes


@app.route('/')
@check_token
def index():
    response = {"message": "API Working"}
    return response


@ app.route('/add', methods=['POST', 'GET'])
@check_token
def addHash():
    try:
        file = request.files.get('file')
        filename = secure_filename(file.filename)

        if filename != '':
            file_ext = os.path.splitext(filename)[1]
            if file_ext not in app.config['UPLOAD_EXTENSIONS']:
                abort(400)
            file.save(file.filename)

        fileHash = hash_file(file.filename)

        addHash = contract.functions.add(fileHash).buildTransaction(
            {
                'from': sender_address,
                'nonce': w3.eth.get_transaction_count(sender_address),
            })

        signed_tx = w3.eth.account.sign_transaction(
            addHash, private_key=private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        print(tx_receipt)

        response = {
            "message": "Success!",
            "link": "https://goerli.etherscan.io/tx/"+tx_hash.hex(),
        }
        os.unlink(file.filename)
    except Exception as e:
        print(e)
        response = str(e)
        os.unlink(file.filename)

    return response


@ app.route('/verify', methods=['POST', 'GET'])
def verify():
    try:
        file = request.files.get('file')
        filename = secure_filename(file.filename)

        if filename != '':
            file_ext = os.path.splitext(filename)[1]
            if file_ext not in app.config['UPLOAD_EXTENSIONS']:
                abort(400)
            file.save(file.filename)

        fileHash = hash_file(file.filename)

        verify = contract.functions.verify(fileHash).call()

        if verify == 0:
            response = {"message": "file hash does not exist"}
        else:
            dt = datetime.datetime.fromtimestamp(
                int(verify)).strftime('%Y-%m-%d %H:%M:%S')
            response = {
                "time": dt,
                "message": f"Valid!, file hash {fileHash} was added."
            }
        os.unlink(file.filename)
    except:
        response = {"message": "Please check the file type, only \".pdf\" file extensions are allowed, or maybe there is a problem interacting with the smart contract."}
    return response


# main driver function
if __name__ == '__main__':
    # run() method of Flask class runs the application
    # on the local development server.
    app.run(host=os.getenv('IP', '0.0.0.0'),
            port=int(os.getenv('PORT', 8888)))
