from flask import Flask, request, jsonify
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
import base64
from datetime import datetime
import time
import my_pb2
import output_pb2
from urllib.parse import urlparse, parse_qs
import json

app = Flask(__name__)
SESSION = requests.Session()
KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# Platform Mapping
PLATFORM_MAP = {
    3: "Facebook",
    4: "Guest",
    5: "VK",
    8: "Google",
    11: "X (Twitter)",
    10: "AppleId",
}

def log_info(message):
    print(f"[INFO] {message}")

def log_error(message):
    print(f"[ERROR] {message}")

def log_debug(message):
    print(f"[DEBUG] {message}")

def getGuestAccessToken(uid, password):
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": str(uid),
        "password": str(password),
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    response = SESSION.post("https://100067.connect.garena.com/oauth/guest/token/grant",
                            headers=headers, data=data, verify=False)
    data_response = response.json()
    if data_response.get("success") is True:
        resp = data_response.get("response", {})
        if resp.get("error") == "auth_error":
            return {"error": "auth_error"}
    return {"access_token": data_response.get("access_token"), "open_id": data_response.get("open_id")}

def check_guest(uid, password):
    token_data = getGuestAccessToken(uid, password)
    if token_data.get("error") == "auth_error":
        return uid, None, None, True
    access_token = token_data.get("access_token")
    open_id = token_data.get("open_id")
    if access_token and open_id:
        log_debug(f"UID {uid}: Access token and obtained open_id via API")
        return uid, access_token, open_id, False
    log_error(f"UID {uid}: Login failed, token missing.")
    return uid, None, None, False

def get_token_inspect_data(access_token):
    try:
        resp = SESSION.get(
            f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}",
            timeout=15,
            verify=False
        )
        data = resp.json()
        if 'open_id' in data and 'platform' in data and 'uid' in data:
            return data
    except Exception as e:
        log_error(f"Error inspecting token: {e}")
    return None

def login(uid, access_token, open_id, platform_type):
    log_debug(f"Starting login for UID {uid} with platform_type {platform_type}")
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    game_data = my_pb2.GameData()
    game_data.timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    game_data.game_name = "Free Fire"
    game_data.game_version = 1
    game_data.version_code = "1.118.1"
    game_data.os_info = "iOS 18.4"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1170
    game_data.screen_height = 2532
    game_data.dpi = "460"
    game_data.cpu_info = "Apple A15 Bionic"
    game_data.total_ram = 6144
    game_data.gpu_name = "Apple GPU (5-core)"
    game_data.gpu_version = "Metal 3"
    game_data.user_id = uid
    game_data.ip_address = "172.190.111.97"
    game_data.language = "en"
    game_data.open_id = open_id
    game_data.access_token = access_token
    game_data.platform_type = platform_type
    game_data.field_99 = str(platform_type)
    game_data.field_100 = str(platform_type)
    serialized_data = game_data.SerializeToString()
    padded_data = pad(serialized_data, AES.block_size)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted_data = cipher.encrypt(padded_data)
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "X-GA": "v1 1",
        "X-Unity-Version": "2018.4.11f1",
        "ReleaseVersion": "OB52",
        "Content-Length": str(len(encrypted_data))
    }
    try:
        response = SESSION.post(url, data=encrypted_data, headers=headers, timeout=30, verify=False)
        if response.status_code == 200:
            jwt_msg = output_pb2.Garena_420()
            jwt_msg.ParseFromString(response.content)
            if jwt_msg.token:
                log_debug(f"Login successful for UID {uid}, token: {jwt_msg.token[:10]}...")
                return jwt_msg.token
        else:
            error_text = response.content.decode().strip()
            log_debug(f"API MajorLogin retornou status {response.status_code}: {error_text}")
            if error_text == "BR_PLATFORM_INVALID_PLATFORM":
                return {"error": "INVALID_PLATFORM", "message": "this account is registered on another platform"}
            elif error_text == "BR_GOP_TOKEN_AUTH_FAILED":
                return {"error": "INVALID_TOKEN", "message": "AccessToken invalid."}
            elif error_text == "BR_PLATFORM_INVALID_OPENID":
                return {"error": "INVALID_OPENID", "message": "OpenID invalid."}
    except Exception as e:
        log_error(f"UID {uid}: Error in JWT request - {e}")
    return None

def extract_eat_info(eat_token):
    """
    Extract information from EAT token by calling the support callback URL
    """
    try:
        url = f"https://api-otrss.garena.com/support/callback/?access_token={eat_token}"
        response = SESSION.get(url, allow_redirects=True, timeout=30, verify=False)
        
        # Check if we got redirected to help.garena.com
        if "help.garena.com" in response.url:
            parsed_url = urlparse(response.url)
            query_params = parse_qs(parsed_url.query)
            
            access_token = query_params.get('access_token', [None])[0]
            region = query_params.get('region', [None])[0]
            account_id = query_params.get('account_id', [None])[0]
            nickname = query_params.get('nickname', [None])[0]
            
            return {
                "access_token": access_token,
                "region": region,
                "game_uid": account_id,
                "nickname": nickname
            }
        else:
            # Try to parse as JSON if it's not a redirect
            try:
                data = response.json()
                return {
                    "access_token": data.get('access_token'),
                    "region": data.get('region'),
                    "game_uid": data.get('account_id') or data.get('game_uid'),
                    "nickname": data.get('nickname')
                }
            except:
                return None
    except Exception as e:
        log_error(f"Error extracting EAT info: {e}")
        return None

@app.route("/token", methods=["GET"])
def get_jwt():
    guest_uid = request.args.get("uid")
    guest_password = request.args.get("password")
    
    if guest_uid and guest_password:
        uid, access_token, open_id, err_flag = check_guest(guest_uid, guest_password)
        if err_flag:
            return jsonify({
                "success": False,
                "message": "invalid guest_uid, guest_password",
                "credits": "TELEGRAM @exucoder1 and @raihanpaid and @raihanpaid"
            }), 400
        if not access_token or not open_id:
            return jsonify({
                "success": False,
                "message": "unregistered or banned account.",
                "detail": "jwt not found in response.",
                "credits": "TELEGRAM @exucoder1 and @raihanpaid"
            }), 500
        jwt_token = login(uid, access_token, open_id, 4)
        if isinstance(jwt_token, dict):
            jwt_token["credits"] = "TELEGRAM @exucoder1 and @raihanpaid"
            return jsonify(jwt_token), 400
        if not jwt_token:
            return jsonify({
                "success": False,
                "message": "unregistered or banned account.",
                "detail": "jwt not found in response.",
                "credits": "TELEGRAM @exucoder1 and @raihanpaid"
            }), 500
        return jsonify({
            "success": True, 
            "token": jwt_token,
            "platform_type": 4,
            "platform_name": "Guest",
            "credits": "TELEGRAM @exucoder1 and @raihanpaid"
        })

    access_token = request.args.get("access_token")
    if access_token:
        token_data = get_token_inspect_data(access_token)
        if not token_data:
            return jsonify({
                "error": "INVALID_TOKEN",
                "message": "AccessToken invalid.",
                "credits": "TELEGRAM @exucoder1 and @raihanpaid"
            }), 400
        open_id = token_data["open_id"]
        platform_type = token_data["platform"]
        uid = str(token_data["uid"])
        jwt_token = login(uid, access_token, open_id, platform_type)
        if isinstance(jwt_token, dict):
            jwt_token["credits"] = "TELEGRAM @exucoder1 and @raihanpaid"
            return jsonify(jwt_token), 400
        if not jwt_token:
            return jsonify({
                "success": False,
                "message": "unregistered or banned account.",
                "detail": "jwt not found in response.",
                "credits": "TELEGRAM @exucoder1 and @raihanpaid"
            }), 500
        
        platform_name = PLATFORM_MAP.get(platform_type, "Unknown")
        return jsonify({
            "success": True, 
            "token": jwt_token,
            "platform_type": platform_type,
            "platform_name": platform_name,
            "credits": "TELEGRAM @exucoder1 and @raihanpaid"
        })

    return jsonify({
        "success": False,
        "message": "missing access_token (or guest_uid + guest_password)",
        "credits": "TELEGRAM @exucoder1 and @raihanpaid"
    }), 400

@app.route("/eat_info", methods=["GET"])
def get_eat_info():
    """
    Extract information from EAT token
    """
    eat_token = request.args.get("eat_token")
    if not eat_token:
        return jsonify({
            "success": False,
            "message": "eat_token parameter is required",
            "credits": "TELEGRAM @exucoder1 and @raihanpaid"
        }), 400
    
    info = extract_eat_info(eat_token)
    if not info:
        return jsonify({
            "success": False,
            "message": "Failed to extract information from EAT token",
            "credits": "TELEGRAM @exucoder1 and @raihanpaid"
        }), 400
    
    return jsonify({
        "success": True,
        "data": info,
        "credits": "TELEGRAM @exucoder1 and @raihanpaid"
    })

@app.route("/eat_to_access", methods=["GET"])
def eat_to_access():
    """
    Convert EAT token to access_token and get user info
    """
    eat_token = request.args.get("eat_token")
    if not eat_token:
        return jsonify({
            "success": False,
            "message": "eat_token parameter is required",
            "credits": "TELEGRAM @exucoder1 and @raihanpaid"
        }), 400
    
    # Extract info from EAT
    info = extract_eat_info(eat_token)
    if not info or not info.get("access_token"):
        return jsonify({
            "success": False,
            "message": "Invalid EAT token or failed to extract info",
            "credits": "TELEGRAM @exucoder1 and @raihanpaid"
        }), 400
    
    # Get platform info from the access_token
    token_data = get_token_inspect_data(info["access_token"])
    if token_data:
        platform_type = token_data.get("platform")
        platform_name = PLATFORM_MAP.get(platform_type, "Unknown")
        info["platform_type"] = platform_type
        info["platform_name"] = platform_name
        info["uid"] = token_data.get("uid")
        info["open_id"] = token_data.get("open_id")
    
    return jsonify({
        "success": True,
        "data": info,
        "credits": "TELEGRAM @exucoder1 and @raihanpaid"
    })

@app.route("/eat_to_jwt", methods=["GET"])
def eat_to_jwt():
    """
    Convert EAT token directly to JWT
    """
    eat_token = request.args.get("eat_token")
    if not eat_token:
        return jsonify({
            "success": False,
            "message": "eat_token parameter is required",
            "credits": "TELEGRAM @exucoder1 and @raihanpaid"
        }), 400
    
    # Extract info from EAT
    info = extract_eat_info(eat_token)
    if not info or not info.get("access_token"):
        return jsonify({
            "success": False,
            "message": "Invalid EAT token or failed to extract info",
            "credits": "TELEGRAM @exucoder1 and @raihanpaid"
        }), 400
    
    # Get platform info
    token_data = get_token_inspect_data(info["access_token"])
    if not token_data:
        return jsonify({
            "error": "INVALID_TOKEN",
            "message": "AccessToken invalid.",
            "credits": "TELEGRAM @exucoder1 and @raihanpaid"
        }), 400
    
    open_id = token_data["open_id"]
    platform_type = token_data["platform"]
    uid = str(token_data["uid"])
    
    # Get JWT token
    jwt_token = login(uid, info["access_token"], open_id, platform_type)
    
    if isinstance(jwt_token, dict):
        jwt_token["credits"] = "TELEGRAM @exucoder1 and @raihanpaid"
        return jsonify(jwt_token), 400
    if not jwt_token:
        return jsonify({
            "success": False,
            "message": "Failed to get JWT token",
            "credits": "TELEGRAM @exucoder1 and @raihanpaid"
        }), 500
    
    platform_name = PLATFORM_MAP.get(platform_type, "Unknown")
    
    return jsonify({
        "success": True,
        "jwt_token": jwt_token,
        "user_info": {
            "game_uid": info.get("game_uid"),
            "nickname": info.get("nickname"),
            "region": info.get("region"),
            "uid": uid,
            "open_id": open_id
        },
        "platform": {
            "type": platform_type,
            "name": platform_name
        },
        "credits": "TELEGRAM @exucoder1 and @raihanpaid"
    })

@app.route("/platforms", methods=["GET"])
def get_platforms():
    """
    Get all supported platforms
    """
    return jsonify({
        "success": True,
        "platforms": PLATFORM_MAP,
        "credits": "TELEGRAM @exucoder1 and @raihanpaid"
    })

@app.route("/inspect_token", methods=["GET"])
def inspect_token():
    """
    Inspect any access_token to get details
    """
    access_token = request.args.get("access_token")
    if not access_token:
        return jsonify({
            "success": False,
            "message": "access_token parameter is required",
            "credits": "TELEGRAM @exucoder1 and @raihanpaid"
        }), 400
    
    token_data = get_token_inspect_data(access_token)
    if not token_data:
        return jsonify({
            "success": False,
            "message": "Invalid or expired token",
            "credits": "TELEGRAM @exucoder1 and @raihanpaid"
        }), 400
    
    platform_type = token_data.get("platform")
    platform_name = PLATFORM_MAP.get(platform_type, "Unknown")
    
    token_data["platform_name"] = platform_name
    return jsonify({
        "success": True,
        "data": token_data,
        "credits": "TELEGRAM @exucoder1 and @raihanpaid"
    })

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "online",
        "service": "Garena Token Converter API",
        "endpoints": {
            "/token": "Get JWT from access_token or guest credentials",
            "/eat_info": "Extract info from EAT token",
            "/eat_to_access": "Convert EAT to access_token with user info",
            "/eat_to_jwt": "Convert EAT directly to JWT",
            "/inspect_token": "Inspect any access_token",
            "/platforms": "Get supported platforms list"
        },
        "credits": "TELEGRAM @exucoder1 and @raihanpaid"
    })

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "detail": "Not Found",
        "credits": "TELEGRAM @exucoder1 and @raihanpaid"
    }), 404

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    log_info(f"Starting the service on port {port}")
    log_info("API Service Credits: TELEGRAM @exucoder1 and @raihanpaid")
    app.run(host="0.0.0.0", port=port, debug=False)