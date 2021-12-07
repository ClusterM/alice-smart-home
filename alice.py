# coding: utf8

import config
from flask import Flask
from flask import request
from flask import render_template
from flask import send_from_directory
from flask import redirect
from flask import jsonify
from flask import has_request_context
import sys
import os
import requests
import urllib
import json
import random
import string
from time import time
import importlib
import logging
import traceback

last_code = None
last_code_user = None
last_code_time = None
# Path to device plugins
sys.path.insert(0, config.DEVICES_DIRECTORY)

# Logging

logger = logging.getLogger()
old_factory = logging.getLogRecordFactory()
def record_factory(*args, **kwargs):
    record = old_factory(*args, **kwargs)
    record.remote_addr = '-'
    record.user = '-'
    if has_request_context():
        record.remote_addr = request.remote_addr
        if hasattr(request, 'user_id'):
            record.user = request.user_id
    return record
logging.setLogRecordFactory(record_factory)
log_handler = logging.FileHandler(config.LOG_FILE, 'a') if hasattr(config, 'LOG_FILE') else StreamHandler()
log_handler.setFormatter(
    logging.Formatter(
        fmt=config.LOG_FORMAT if hasattr(config, 'LOG_FORMAT') else "[%(asctime)s] [%(levelname)s] [%(remote_addr)s] [%(user)s]: %(message)s",
        datefmt=config.LOG_DATE_FORMAT if hasattr(config, 'LOG_DATE_FORMAT') else "%Y-%m-%d %H:%M:%S",
    )
)
logger.addHandler(log_handler)
if hasattr(config, 'LOG_LEVEL'): logger.setLevel(config.LOG_LEVEL)

app = Flask(__name__)
logger.info("Started.")

# Function to load user info
def get_user(user_id):
    request.user_id = user_id
    filename = os.path.join(config.USERS_DIRECTORY, user_id + ".json")
    if os.path.isfile(filename) and os.access(filename, os.R_OK):
        with open(filename, mode='r') as f:
            text = f.read()
            data = json.loads(text)
            return data
    else:
        logger.warning(f"user not found")
        return None

# Function to retrieve token from header
def get_token():
    auth = request.headers.get('Authorization')
    parts = auth.split(' ', 2)
    if len(parts) == 2 and parts[0].lower() == 'bearer':
        return parts[1]
    else:
        logger.warning(f"invalid token: {auth}")
        return None

# Function to check current token, returns username
def check_token():
    access_token = get_token()
    access_token_file = os.path.join(config.TOKENS_DIRECTORY, access_token)
    if os.path.isfile(access_token_file) and os.access(access_token_file, os.R_OK):
        with open(access_token_file, mode='r') as f:
            user_id = f.read()
            request.user_id = user_id
            return user_id
    else:
        return None

# Function to load device info
def get_device(device_id):
    filename = os.path.join(config.DEVICES_DIRECTORY, device_id + ".json")
    if os.path.isfile(filename) and os.access(filename, os.R_OK):
        with open(filename, mode='r') as f:
            text = f.read()
            data = json.loads(text)
            data['id'] = device_id
            return data
    else:
        return None

# Random string generator
def random_string(stringLength=8):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for i in range(stringLength))

@app.route('/css/<path:path>')
def send_css(path):
    return send_from_directory('css', path)

# OAuth entry point
@app.route('/auth/', methods=['GET', 'POST'])
def auth():
    try:
        global last_code, last_code_user, last_code_time
        if request.method == 'GET':
            # Ask user for login and password
            return render_template('login.html')
        elif request.method == 'POST':
            if ("username" not in request.form
                or "password" not in request.form
                or "state" not in request.args
                or "response_type" not in request.args
                or request.args["response_type"] != "code"
                or "client_id" not in request.args
                or request.args["client_id"] != config.CLIENT_ID):
                    if "username" in request.form:
                        request.user_id = request.form['username']
                    logger.error("invalid auth request")
                    return "Invalid request", 400
            # Check login and password
            user = get_user(request.form["username"])
            if user == None or user["password"] != request.form["password"]:
                logger.warning("invalid password")
                return render_template('login.html', login_failed=True)

            # Generate random code and remember this user and time
            last_code = random_string(8)
            last_code_user = request.form["username"]
            last_code_time = time()

            params = {'state': request.args['state'], 
                      'code': last_code,
                      'client_id': config.CLIENT_ID}
            logger.info("code generated")
            return redirect(request.args["redirect_uri"] + '?' + urllib.parse.urlencode(params))
    except:
        ex_type, ex_value, ex_traceback = sys.exc_info()       
        logger.error(f"Exception {ex_type.__name__}: {ex_value}\r\n{traceback.format_exc()}")
        return f"Exception {ex_type.__name__}: {ex_value}", 500

# OAuth, token request
@app.route('/token/', methods=['POST'])
def token():
    try:
        global last_code, last_code_user, last_code_time
        request.user_id = last_code_user
        if ("client_secret" not in request.form
            or request.form["client_secret"] != config.CLIENT_SECRET
            or "client_id" not in request.form
            or request.form["client_id"] != config.CLIENT_ID
            or "code" not in request.form):
                logger.error("invalid token request")
                return "Invalid request", 400
        # Check code
        if request.form["code"] != last_code:
            logger.warning("invalid code")
            return "Invalid code", 403
        # Check time
        if time() - last_code_time > 10:
            logger.warning("code is too old")
            return "Code is too old", 403
        # Generate and save random token with username
        access_token = random_string(32)
        access_token_file = os.path.join(config.TOKENS_DIRECTORY, access_token)
        with open(access_token_file, mode='wb') as f:
            f.write(last_code_user.encode('utf-8'))
        logger.info("access granted")
        # Return just token without any expiration time
        return jsonify({'access_token': access_token})
    except:
        ex_type, ex_value, ex_traceback = sys.exc_info()       
        logger.error(f"Exception {ex_type.__name__}: {ex_value}\r\n{traceback.format_exc()}")
        return f"Exception {ex_type.__name__}: {ex_value}", 500

# Just placeholder for root
@app.route('/')
def root():
    return "Your smart home is ready."

# Script must response 200 OK on this request
@app.route('/v1.0', methods=['GET', 'POST'])
def main_v10():
    return "OK"

# Method to revoke token
@app.route('/v1.0/user/unlink', methods=['POST'])
def unlink():
    try:
        user_id = check_token()
        access_token = get_token()
        request_id = request.headers.get('X-Request-Id')
        access_token_file = os.path.join(config.TOKENS_DIRECTORY, access_token)
        if os.path.isfile(access_token_file) and os.access(access_token_file, os.R_OK):
            os.remove(access_token_file)
            logger.info(f"token {access_token} revoked", access_token)
        return jsonify({'request_id': request_id})
    except:
        ex_type, ex_value, ex_traceback = sys.exc_info()       
        logger.error(f"Exception {ex_type.__name__}: {ex_value}\r\n{traceback.format_exc()}")
        return f"Exception {ex_type.__name__}: {ex_value}", 500

# Devices list
@app.route('/v1.0/user/devices', methods=['GET'])
def devices_list():
    try:
        user_id = check_token()
        if user_id == None:
            return "Access denied", 403
        request_id = request.headers.get('X-Request-Id')
        logger.debug(f"devices request #{request_id}")
        # Load user info
        user = get_user(user_id)
        devices = []
        # Load config for each device available for this user
        for device_id in user["devices"]:
            device = get_device(device_id)
            devices.append(device)
        result = {'request_id': request_id, 'payload': {'user_id': user_id, 'devices': devices}}
        logger.debug(f"devices response #{request_id}: \r\n{json.dumps(result, indent=4)}")
        return jsonify(result)
    except Exception as ex:
        ex_type, ex_value, ex_traceback = sys.exc_info()       
        logger.error(f"Exception {ex_type.__name__}: {ex_value}\r\n{traceback.format_exc()}")
        return f"Exception {ex_type.__name__}: {ex_value}", 500

# Method to query current device status
@app.route('/v1.0/user/devices/query', methods=['POST'])
def query():
    try:
        user_id = check_token()
        if user_id == None:
            return "Access denied", 403
        request_id = request.headers.get('X-Request-Id')
        user = get_user(user_id)
        r = request.get_json()
        logger.debug(f"query request #{request_id}: \r\n{json.dumps(r, indent=4)}")
        devices_request = r["devices"]
        result = {'request_id': request_id, 'payload': {'devices': []}}
        # For each requested device...
        for device in devices_request:
            # Check that user can access this device
            if not device["id"] in user["devices"]:
                return "Access denied", 403
            new_device = {'id': device['id'], 'capabilities': []}
            # Load device config
            device_info = get_device(device['id'])
            # Load device module
            device_module = importlib.import_module(device['id'])
            # Get query method
            query_method = getattr(device_module, device["id"] + "_query")
            # Call it for every requested capability
            for capability in device_info['capabilities']:
                # But skip it if it's not retrievable
                if not capability.get("retrievable", True): continue
                # Pass parameters: capability type and instance (if any)
                capability_type = capability['type']
                parameters = capability.get("parameters", None)
                instance = parameters.get("instance", None) if parameters != None else None
                r = query_method(capability_type, instance)
                if type(r) == tuple:
                    value, instance = r
                else:
                    value = r
                if not instance: logger.error(f"'instance' is empty for device {device['id']}, please set it in the JSON file or in the query method")
                new_device['capabilities'].append({
                    'type': capability_type,
                    'state': {
                        "instance": instance,
                        "value": value
                    }
                })
            result['payload']['devices'].append(new_device)
        logger.debug(f"query response #{request_id}: \r\n{json.dumps(result, indent=4)}")
        return jsonify(result)
    except Exception as ex:
        ex_type, ex_value, ex_traceback = sys.exc_info()       
        logger.error(f"Exception {ex_type.__name__}: {ex_value}\r\n{traceback.format_exc()}")
        return f"Exception {ex_type.__name__}: {ex_value}", 500

# Method to execute some action with devices
@app.route('/v1.0/user/devices/action', methods=['POST'])
def action():
    try:
        user_id = check_token()
        if user_id == None:
            return "Access denied", 403
        request_id = request.headers.get('X-Request-Id')
        user = get_user(user_id)
        r = request.get_json()
        logger.debug(f"action request #{request_id}: \r\n{json.dumps(r, indent=4)}")
        devices_request = r["payload"]["devices"]
        result = {'request_id': request_id, 'payload': {'devices': []}}
        # For each requested device...
        for device in devices_request:
            # Check that user can access this device
            if not device["id"] in user["devices"]:
                return "Access denied", 403
            new_device = {'id': device['id'], 'capabilities': []}
            # Load device module
            device_module = importlib.import_module(device['id'])
            # Get action method
            action_method = getattr(device_module, device["id"] + "_action")
            # Call it for every requested capability
            for capability in device['capabilities']:
                # Pass parameters: capability type, instance, new value and relative parameter (if any)
                capability_type = capability['type']
                state = capability['state']
                instance = state.get("instance", None)
                value = state.get("value", None)
                relative = state.get("relative", False)
                try:
                    new_device['capabilities'].append({
                        'type': capability['type'],
                        'state': {
                            "instance": instance,
                            "action_result": {
                                "status": action_method(capability_type, instance, value, relative)
                            }
                        }
                    })
                except Exception as ex:
                    ex_type, ex_value, ex_traceback = sys.exc_info()
                    logger.error(f"Exception {ex_type.__name__}: {ex_value}\r\n{traceback.format_exc()}")
                    new_device['capabilities'].append({
                        'type': capability['type'],
                        'state': {
                            "instance": instance,
                            "action_result": {
                                "status": "ERROR",
                                "error_code": "INTERNAL_ERROR",
                                "error_message": f"Exception {ex_type.__name__}: {ex_value}\r\n{traceback.format_exc()}"
                            }
                        }
                    })
            result['payload']['devices'].append(new_device)
        logger.debug(f"action response #{request_id}: \r\n{json.dumps(result, indent=4)}")
        return jsonify(result)
    except Exception as ex:
        ex_type, ex_value, ex_traceback = sys.exc_info()
        logger.error(f"Exception {ex_type.__name__}: {ex_value}\r\n{traceback.format_exc()}")
        return f"Exception {ex_type.__name__}: {ex_value}", 500
