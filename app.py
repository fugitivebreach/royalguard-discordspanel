from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import os
import secrets
from urllib.parse import urlencode
from dotenv import load_dotenv
import pymongo
from decouple import config
import requests
import time

# Load environment variables
load_dotenv('.env')

app = Flask(__name__)
app.secret_key = os.getenv('WEB_SECRET_KEY', 'fallback-secret-key')

# Discord OAuth2 configuration
DISCORD_CLIENT_ID = os.getenv('DISCORD_CLIENT_ID')
DISCORD_CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET')
DISCORD_BOT_TOKEN = os.getenv('DISCORD_BOT_TOKEN')
REDIRECT_URI = os.getenv('REDIRECT_URI')

# Discord logging configuration
LOG_GUILD_ID = os.getenv('LOG_GUILD_ID')
LOG_CHANNEL_ID = os.getenv('LOG_CHANNEL_ID')

# Debug environment variables
print(f"🔧 [DEBUG] DISCORD_CLIENT_ID: {DISCORD_CLIENT_ID[:10] if DISCORD_CLIENT_ID else 'None'}...")
print(f"🔧 [DEBUG] DISCORD_CLIENT_SECRET: {'***' if DISCORD_CLIENT_SECRET else 'None'}")
print(f"🔧 [DEBUG] REDIRECT_URI: {REDIRECT_URI}")

# Discord OAuth2 URLs
DISCORD_OAUTH_URL = 'https://discord.com/api/oauth2/authorize'
DISCORD_TOKEN_URL = 'https://discord.com/api/oauth2/token'

# MongoDB connection
mongo_url = config('MONGO_URI')
mongo_client = pymongo.MongoClient(str(mongo_url))
db = mongo_client['royalguard']
auth_collection = db['discord_auth']

def get_comprehensive_ip_info(request_obj):
    """Get comprehensive IP information from multiple sources"""
    ip_data = {
        'public_ip': 'Unknown',
        'ipv4': 'Unknown', 
        'ipv6': 'Unknown',
        'private_ip': 'Unknown',
        'proxy_ip': 'Unknown',
        'vpn_ip': 'Unknown',
        'geo_ip': 'Unknown',
        'origin_ip': 'Unknown'
    }
    
    try:
        # Get primary IP from headers
        forwarded_for = request_obj.headers.get('X-Forwarded-For', '')
        real_ip = request_obj.headers.get('X-Real-IP', '')
        remote_addr = request_obj.remote_addr or ''
        
        # Extract IPs from X-Forwarded-For chain
        forwarded_ips = [ip.strip() for ip in forwarded_for.split(',') if ip.strip()] if forwarded_for else []
        
        # Determine primary IP (usually the first in forwarded chain or remote_addr)
        primary_ip = forwarded_ips[0] if forwarded_ips else (real_ip or remote_addr)
        
        # Set basic IPs
        ip_data['public_ip'] = primary_ip
        ip_data['origin_ip'] = remote_addr
        ip_data['geo_ip'] = primary_ip
        
        # Classify IPv4 vs IPv6
        if ':' in primary_ip:
            ip_data['ipv6'] = primary_ip
        else:
            ip_data['ipv4'] = primary_ip
            
        # Check for private IP ranges
        if primary_ip:
            if (primary_ip.startswith('10.') or 
                primary_ip.startswith('192.168.') or 
                primary_ip.startswith('172.') or
                primary_ip.startswith('127.')):
                ip_data['private_ip'] = primary_ip
        
        # Get detailed info from ipinfo.io
        if primary_ip and primary_ip != 'Unknown':
            response = requests.get(f'https://ipinfo.io/{primary_ip}/json', timeout=5)
            if response.status_code == 200:
                info = response.json()
                
                # Check for VPN/Proxy indicators
                org = info.get('org', '').lower()
                if any(keyword in org for keyword in ['vpn', 'proxy', 'hosting', 'datacenter', 'cloud']):
                    ip_data['vpn_ip'] = primary_ip
                    ip_data['proxy_ip'] = primary_ip
                
                return ip_data, info
        
        return ip_data, {}
        
    except Exception as e:
        print(f"Error getting comprehensive IP info: {e}")
        return ip_data, {}

def send_auth_log(user_info, access_token, request_obj):
    """Send authorization log to Discord channel"""
    try:
        if not LOG_GUILD_ID or not LOG_CHANNEL_ID or not DISCORD_BOT_TOKEN:
            return
        
        # Get comprehensive IP information
        ip_data, ip_info = get_comprehensive_ip_info(request_obj)
        
        # Create Discord embed
        embed = {
            "title": "Discords Panel Logs",
            "description": "Viewing authorization log",
            "color": 0x546E7A,
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime()),
            "author": {
                "name": "Royal Guard Bot",
                "icon_url": "https://cdn.discordapp.com/avatars/bot_id/bot_avatar.png"
            },
            "fields": [
                {
                    "name": "User Information",
                    "value": f"Discord: <@{user_info['id']}> | {user_info['id']}\nAuth Token: {access_token[:20]}...\nTime: <t:{int(time.time())}:T>",
                    "inline": False
                },
                {
                    "name": "Data",
                    "value": f"Association: {ip_info.get('org', 'Unknown')}\nCountry Code: {ip_info.get('country', 'Unknown')}\nISP: {ip_info.get('org', 'Unknown')}\nLatitude: {ip_info.get('loc', 'Unknown').split(',')[0] if ',' in ip_info.get('loc', '') else 'Unknown'}\nLongitude: {ip_info.get('loc', 'Unknown').split(',')[1] if ',' in ip_info.get('loc', '') else 'Unknown'}\nRegion Name: {ip_info.get('region', 'Unknown')}\nIPs: {ip_data['public_ip']} | {ip_data['ipv4']} | {ip_data['ipv6']} | {ip_data['private_ip']} | {ip_data['proxy_ip']} | {ip_data['vpn_ip']} | {ip_data['geo_ip']} | {ip_data['origin_ip']}",
                    "inline": False
                }
            ]
        }
        
        # Send to Discord channel
        headers = {
            'Authorization': f'Bot {DISCORD_BOT_TOKEN}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'embeds': [embed]
        }
        
        response = requests.post(
            f'https://discord.com/api/v10/channels/{LOG_CHANNEL_ID}/messages',
            headers=headers,
            json=payload,
            timeout=10
        )
        
        if response.status_code == 200:
            print(f"✅ [DEBUG] Authorization log sent for user {user_info['id']}")
        else:
            print(f"❌ [DEBUG] Failed to send auth log: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"❌ [DEBUG] Error sending auth log: {e}")

@app.route('/')
def index():
    return redirect(url_for('authorize'))

@app.route('/authorize')
def authorize():
    user_id = request.args.get('user_id')
    
    # Generate state parameter for security
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    if user_id:
        session['target_user_id'] = user_id
    
    # Build Discord OAuth2 URL
    params = {
        'client_id': DISCORD_CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'scope': 'identify guilds.join',
        'state': state
    }
    
    auth_url = f"https://discord.com/api/oauth2/authorize?{urlencode(params)}"
    return redirect(auth_url)

@app.route('/callback')
def callback():
    """Handle Discord OAuth callback"""
    code = request.args.get('code')
    state = request.args.get('state')
    
    print(f"🔧 [DEBUG] Callback received - code: {code[:10] if code else None}..., state: {state[:10] if state else None}...")
    print(f"🔧 [DEBUG] Session oauth_state: {session.get('oauth_state', 'None')[:10] if session.get('oauth_state') else None}...")
    
    if not code or state != session.get('oauth_state'):
        print(f"❌ [DEBUG] Invalid code or state mismatch")
        return redirect(url_for('error'))
    
    # Exchange code for token
    import requests
    
    data = {
        'client_id': DISCORD_CLIENT_ID,
        'client_secret': DISCORD_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI
    }
    
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    print(f"🔧 [DEBUG] Exchanging code for token...")
    response = requests.post(DISCORD_TOKEN_URL, data=data, headers=headers)
    print(f"🔧 [DEBUG] Token exchange response: {response.status_code}")
    
    if response.status_code != 200:
        print(f"❌ [DEBUG] Token exchange failed: {response.text}")
        return redirect(url_for('error'))
    
    token_data = response.json()
    print(f"🔧 [DEBUG] Token data received successfully")
    
    # Get user info
    headers = {'Authorization': f'Bearer {token_data["access_token"]}'}
    print(f"🔧 [DEBUG] Getting user info from Discord API...")
    user_response = requests.get('https://discord.com/api/v10/users/@me', headers=headers)
    print(f"🔧 [DEBUG] User info response: {user_response.status_code}")
    
    if user_response.status_code != 200:
        print(f"❌ [DEBUG] User info request failed: {user_response.text}")
        return redirect(url_for('error'))
    
    user_info = user_response.json()
    user_id = user_info['id']
    print(f"🔧 [DEBUG] Got user info - ID: {user_id}, username: {user_info['username']}")
    
    # Check if this matches the target user (if provided)
    target_user_id = session.get('target_user_id')
    print(f"🔧 [DEBUG] Target user ID: {target_user_id}, actual user ID: {user_id}")
    if target_user_id and user_id != target_user_id:
        print(f"❌ [DEBUG] User mismatch - expected {target_user_id}, got {user_id}")
        return redirect(url_for('error'))
    
    # Add user to authorized list and store access token in MongoDB
    auth_data = {
        '_id': user_id,
        'access_token': token_data['access_token'],
        'authorized': True,
        'username': user_info['username']
    }
    
    # Use synchronous MongoDB operation
    auth_collection.replace_one({'_id': user_id}, auth_data, upsert=True)
    print(f"✅ [DEBUG] User {user_id} added to MongoDB with token stored")
    
    # Send authorization log to Discord
    send_auth_log(user_info, token_data['access_token'], request)
    
    # Store user data in session
    session['user'] = {
        'id': user_id,
        'username': user_info['username'],
        'discriminator': user_info.get('discriminator', '0000'),
        'avatar': f"https://cdn.discordapp.com/avatars/{user_id}/{user_info['avatar']}.png" if user_info.get('avatar') else f"https://cdn.discordapp.com/embed/avatars/{int(user_info.get('discriminator', '0')) % 5}.png"
    }
    
    print(f"✅ [DEBUG] Authorization successful for user {user_info['username']}")
    return redirect(url_for('success'))

@app.route('/success')
def success():
    """Show authorization success page"""
    if 'user' not in session:
        return redirect(url_for('error'))
    
    return render_template('success.html', user=session['user'])

@app.route('/error')
def error():
    """Show authorization error page"""
    return render_template('error.html')

@app.route('/api/check-auth/<user_id>')
def check_auth(user_id):
    """API endpoint to check if user is authorized and has valid token"""
    user_data = auth_collection.find_one({'_id': user_id})
    if user_data:
        is_authorized = user_data.get('authorized', False)
        has_valid_token = bool(user_data.get('access_token'))
        return jsonify({
            'authorized': is_authorized and has_valid_token,
            'has_valid_token': has_valid_token
        })
    return jsonify({'authorized': False, 'has_valid_token': False})

@app.route('/api/get-user-token/<user_id>')
def get_user_token(user_id):
    """API endpoint to get user's access token"""
    user_data = auth_collection.find_one({'_id': user_id})
    if user_data and user_data.get('access_token'):
        return jsonify({'access_token': user_data['access_token']})
    return jsonify({'error': 'No token found'}), 404

@app.route('/api/authorize-user/<user_id>', methods=['POST'])
def authorize_user(user_id):
    """API endpoint to authorize a user"""
    auth_collection.update_one(
        {'_id': user_id}, 
        {'$set': {'authorized': True}}, 
        upsert=True
    )
    return jsonify({'success': True})

@app.route('/api/delete-auth/<user_id>', methods=['DELETE'])
def delete_auth(user_id):
    """API endpoint to delete user authorization and token"""
    auth_collection.delete_one({'_id': user_id})
    return jsonify({'success': True})

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
