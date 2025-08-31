from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import os
import json
import requests
import secrets
from urllib.parse import urlencode
from dotenv import load_dotenv

# Load environment variables
load_dotenv('.env')

app = Flask(__name__)
app.secret_key = os.getenv('WEB_SECRET_KEY', 'fallback-secret-key')

# Discord OAuth2 configuration
DISCORD_CLIENT_ID = os.getenv('DISCORD_CLIENT_ID')
DISCORD_CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET')
DISCORD_BOT_TOKEN = os.getenv('DISCORD_BOT_TOKEN')
REDIRECT_URI = os.getenv('REDIRECT_URI')

# Server configuration
SERVER_IDS = os.getenv('SERVER_IDS', '').split(',')
SERVER_NAMES = os.getenv('SERVER_NAMES', '').split(',')

def get_server_invite(server_id):
    """Get an invite code for a server using Discord API"""
    headers = {
        'Authorization': f'Bot {DISCORD_BOT_TOKEN}',
        'Content-Type': 'application/json'
    }
    
    try:
        # Get server channels
        channels_response = requests.get(
            f'https://discord.com/api/v10/guilds/{server_id}/channels',
            headers=headers
        )
        
        if channels_response.status_code != 200:
            print(f"Failed to get channels for server {server_id}: {channels_response.status_code}")
            return None
            
        channels = channels_response.json()
        
        # Find a text channel (type 0)
        text_channel = None
        for channel in channels:
            if channel.get('type') == 0:  # Text channel
                text_channel = channel
                break
        
        if not text_channel:
            print(f"No text channels found in server {server_id}")
            return None
        
        # Create invite for the text channel
        invite_data = {
            'max_age': 0,  # Never expires
            'max_uses': 0,  # Unlimited uses
            'temporary': False,
            'unique': False
        }
        
        invite_response = requests.post(
            f'https://discord.com/api/v10/channels/{text_channel["id"]}/invites',
            headers=headers,
            json=invite_data
        )
        
        if invite_response.status_code == 200:
            invite = invite_response.json()
            return invite.get('code')
        else:
            print(f"Failed to create invite for server {server_id}: {invite_response.status_code}")
            return None
            
    except Exception as e:
        print(f"Error getting invite for server {server_id}: {e}")
        return None

# Build servers list - defer invite fetching to avoid startup crashes
SERVERS = []
for i in range(len(SERVER_IDS)):
    server_id = SERVER_IDS[i].strip()
    if server_id:  # Only add non-empty server IDs
        server_name = SERVER_NAMES[i].strip() if i < len(SERVER_NAMES) else f"Server {server_id}"
        
        SERVERS.append({
            'id': server_id,
            'name': server_name,
            'invite_code': None  # Will be fetched when needed
        })

# Create config structure for compatibility
config = {
    'discord': {
        'client_id': DISCORD_CLIENT_ID,
        'client_secret': DISCORD_CLIENT_SECRET,
        'bot_token': DISCORD_BOT_TOKEN,
        'redirect_uri': REDIRECT_URI
    },
    'web': {
        'port': int(os.getenv('PORT', 5000))
    },
    'servers': SERVERS
}

# Discord OAuth2 URLs
DISCORD_API_BASE = 'https://discord.com/api/v10'
DISCORD_OAUTH_URL = 'https://discord.com/api/oauth2/authorize'
DISCORD_TOKEN_URL = 'https://discord.com/api/oauth2/token'

class DiscordOAuth:
    def __init__(self, client_id, client_secret, redirect_uri):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
    
    def get_oauth_url(self):
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'scope': 'identify guilds guilds.join',
            'state': secrets.token_urlsafe(32)
        }
        session['oauth_state'] = params['state']
        return f"{DISCORD_OAUTH_URL}?{urlencode(params)}"
    
    def exchange_code(self, code):
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri
        }
        
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        response = requests.post(DISCORD_TOKEN_URL, data=data, headers=headers)
        
        if response.status_code == 200:
            return response.json()
        return None
    
    def get_user_info(self, access_token):
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(f'{DISCORD_API_BASE}/users/@me', headers=headers)
        
        if response.status_code == 200:
            return response.json()
        return None
    
    def get_user_guilds(self, access_token):
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(f'{DISCORD_API_BASE}/users/@me/guilds', headers=headers)
        
        print(f"Get user guilds response: {response.status_code}")
        if response.status_code != 200:
            print(f"Error response: {response.text}")
        
        if response.status_code == 200:
            return response.json()
        return None
    
    def join_guild(self, access_token, guild_id, user_id, bot_token):
        headers = {
            'Authorization': f'Bot {bot_token}',
            'Content-Type': 'application/json'
        }
        
        data = {
            'access_token': access_token
        }
        
        try:
            print(f"Attempting to join guild {guild_id} for user {user_id}")
            response = requests.put(
                f'{DISCORD_API_BASE}/guilds/{guild_id}/members/{user_id}',
                headers=headers,
                json=data
            )
            
            print(f"Discord API response: {response.status_code}")
            print(f"Discord API response text: {response.text}")
            
            if response.status_code == 403:
                print("Bot lacks permission to add members to this server")
                return False
            elif response.status_code == 404:
                print("Guild not found or bot not in guild")
                return False
            elif response.status_code == 400:
                print("Bad request - possibly invalid access token or user already in guild")
                return False
            elif response.status_code in [200, 201, 204]:
                print("Successfully added user to guild")
                return True
            else:
                print(f"Unexpected status code: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"Exception in join_guild: {e}")
            return False

# Initialize Discord OAuth
discord_oauth = DiscordOAuth(
    config['discord']['client_id'],
    config['discord']['client_secret'],
    config['discord']['redirect_uri']
)

@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login')
def login():
    return redirect(discord_oauth.get_oauth_url())

@app.route('/callback')
def callback():
    code = request.args.get('code')
    state = request.args.get('state')
    
    if not code or state != session.get('oauth_state'):
        return redirect(url_for('index'))
    
    # Exchange code for token
    token_data = discord_oauth.exchange_code(code)
    if not token_data:
        return redirect(url_for('index'))
    
    # Get user info
    user_info = discord_oauth.get_user_info(token_data['access_token'])
    if not user_info:
        return redirect(url_for('index'))
    
    # Store user data in session
    session['user'] = {
        'id': user_info['id'],
        'username': user_info['username'],
        'discriminator': user_info['discriminator'],
        'avatar': f"https://cdn.discordapp.com/avatars/{user_info['id']}/{user_info['avatar']}.png" if user_info['avatar'] else f"https://cdn.discordapp.com/embed/avatars/{int(user_info['discriminator']) % 5}.png"
    }
    session['access_token'] = token_data['access_token']
    
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('index'))
    
    return render_template('dashboard.html', user=session['user'])

@app.route('/api/servers')
def api_servers():
    try:
        if 'user' not in session or 'access_token' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        
        # Get user's current guilds
        user_guilds = discord_oauth.get_user_guilds(session['access_token'])
        if user_guilds is None:
            print("Failed to fetch user guilds")
            return jsonify({'error': 'Failed to fetch user guilds'}), 500
        
        user_guild_ids = [guild['id'] for guild in user_guilds]
        
        # Get available servers from config and fetch invite codes dynamically
        available_servers = []
        for server in config.get('servers', []):
            try:
                # Fetch invite code if not already cached
                invite_code = server.get('invite_code')
                if not invite_code:
                    print(f"Attempting to get invite for server {server['id']}")
                    invite_code = get_server_invite(server['id'])
                    if not invite_code:
                        print(f"Failed to get invite for server {server['id']}")
                        invite_code = "unavailable"
                    else:
                        print(f"Successfully got invite for server {server['id']}: {invite_code}")
                
                available_servers.append({
                    'id': server['id'],
                    'name': server['name'],
                    'icon': server.get('icon'),
                    'member_count': 'Unknown',
                    'joined': server['id'] in user_guild_ids,
                    'invite_code': invite_code
                })
            except Exception as e:
                print(f"Error processing server {server['id']}: {e}")
                # Continue with other servers even if one fails
                available_servers.append({
                    'id': server['id'],
                    'name': server['name'],
                    'icon': server.get('icon'),
                    'member_count': 'Unknown',
                    'joined': server['id'] in user_guild_ids,
                    'invite_code': "error"
                })
        
        return jsonify({'servers': available_servers})
    
    except Exception as e:
        print(f"Error in api_servers: {e}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/join-server', methods=['POST'])
def api_join_server():
    try:
        if 'user' not in session or 'access_token' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
            
        server_id = data.get('server_id')
        
        if not server_id:
            return jsonify({'error': 'Server ID required'}), 400
        
        print(f"Join server request for server_id: {server_id}, user: {session['user']['id']}")
        
        # Validate bot token exists
        if not config['discord']['bot_token']:
            print("Bot token is missing")
            return jsonify({'error': 'Bot token not configured'}), 500
        
        # Check if user is already in the server first
        user_guilds = discord_oauth.get_user_guilds(session['access_token'])
        if user_guilds:
            user_guild_ids = [guild['id'] for guild in user_guilds]
            if server_id in user_guild_ids:
                return jsonify({'success': True, 'message': 'Already a member of this server'})
        
        # Join the server using bot token
        success = discord_oauth.join_guild(
            session['access_token'],
            server_id,
            session['user']['id'],
            config['discord']['bot_token']
        )
        
        if success:
            return jsonify({'success': True, 'message': 'Successfully joined server'})
        else:
            return jsonify({'error': 'Failed to join server. The bot may not have permission to add members to this server, or the user may already be banned.'}), 500
            
    except Exception as e:
        print(f"Exception in api_join_server: {e}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
