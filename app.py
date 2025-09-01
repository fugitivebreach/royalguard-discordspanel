from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import os
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

# Discord OAuth2 URLs
DISCORD_OAUTH_URL = 'https://discord.com/api/oauth2/authorize'
DISCORD_TOKEN_URL = 'https://discord.com/api/oauth2/token'

# Store authorized users (in production, use a database)
authorized_users = set()

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
    
    if not code or state != session.get('oauth_state'):
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
    response = requests.post(DISCORD_TOKEN_URL, data=data, headers=headers)
    
    if response.status_code != 200:
        return redirect(url_for('error'))
    
    token_data = response.json()
    
    # Get user info
    headers = {'Authorization': f'Bearer {token_data["access_token"]}'}
    user_response = requests.get('https://discord.com/api/v10/users/@me', headers=headers)
    
    if user_response.status_code != 200:
        return redirect(url_for('error'))
    
    user_info = user_response.json()
    user_id = user_info['id']
    
    # Check if this matches the target user (if provided)
    target_user_id = session.get('target_user_id')
    if target_user_id and user_id != target_user_id:
        return redirect(url_for('error'))
    
    # Add user to authorized list
    authorized_users.add(user_id)
    
    # Store user data in session
    session['user'] = {
        'id': user_id,
        'username': user_info['username'],
        'discriminator': user_info.get('discriminator', '0000'),
        'avatar': f"https://cdn.discordapp.com/avatars/{user_id}/{user_info['avatar']}.png" if user_info.get('avatar') else f"https://cdn.discordapp.com/embed/avatars/{int(user_info.get('discriminator', '0')) % 5}.png"
    }
    
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
    """API endpoint to check if user is authorized"""
    return jsonify({'authorized': user_id in authorized_users})

@app.route('/api/authorize-user/<user_id>', methods=['POST'])
def authorize_user(user_id):
    """API endpoint to authorize a user"""
    authorized_users.add(user_id)
    return jsonify({'success': True})

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
