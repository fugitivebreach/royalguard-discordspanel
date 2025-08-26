from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import requests
import json
import os
from urllib.parse import urlencode
import secrets
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Load configuration from environment variables
config = {
    'discord': {
        'client_id': os.getenv('DISCORD_CLIENT_ID'),
        'client_secret': os.getenv('DISCORD_CLIENT_SECRET'),
        'bot_token': os.getenv('DISCORD_BOT_TOKEN'),
        'redirect_uri': os.getenv('REDIRECT_URI', 'http://localhost:5000/callback')
    },
    'web': {
        'secret_key': os.getenv('WEB_SECRET_KEY', 'dev-secret-key'),
        'port': int(os.getenv('PORT', 5000)),
        'url': os.getenv('WEB_URL', 'http://localhost:5000')
    }
}

# Parse server configuration from environment variables
def load_servers_from_env():
    server_ids = os.getenv('SERVER_IDS', '').split(',')
    server_names = os.getenv('SERVER_NAMES', '').split(',')
    server_invite_codes = os.getenv('SERVER_INVITE_CODES', '').split(',')
    
    servers = []
    for i, server_id in enumerate(server_ids):
        if server_id.strip():
            servers.append({
                'id': server_id.strip(),
                'name': server_names[i].strip() if i < len(server_names) else f'Server {i+1}',
                'icon': None,
                'invite_code': server_invite_codes[i].strip() if i < len(server_invite_codes) else None
            })
    return servers

config['servers'] = load_servers_from_env()

app.secret_key = config['web']['secret_key']

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
            'scope': 'identify guilds.join',
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
        
        response = requests.put(
            f'{DISCORD_API_BASE}/guilds/{guild_id}/members/{user_id}',
            headers=headers,
            json=data
        )
        
        return response.status_code in [200, 201, 204]

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
    if 'user' not in session or 'access_token' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Get user's current guilds
    user_guilds = discord_oauth.get_user_guilds(session['access_token'])
    if user_guilds is None:
        return jsonify({'error': 'Failed to fetch user guilds'}), 500
    
    user_guild_ids = [guild['id'] for guild in user_guilds]
    
    # Get available servers from config
    available_servers = []
    for server in config.get('servers', []):
        available_servers.append({
            'id': server['id'],
            'name': server['name'],
            'icon': server.get('icon'),
            'member_count': 'Unknown',
            'joined': server['id'] in user_guild_ids,
            'invite_code': server.get('invite_code')
        })
    
    return jsonify({'servers': available_servers})

@app.route('/api/join-server', methods=['POST'])
def api_join_server():
    if 'user' not in session or 'access_token' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    server_id = data.get('server_id')
    
    if not server_id:
        return jsonify({'error': 'Server ID required'}), 400
    
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
        return jsonify({'error': 'Failed to join server'}), 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=config['web']['port'])
