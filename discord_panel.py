import discord
from discord.ext import commands
from discord import app_commands
import os
import json
import requests
from dotenv import load_dotenv
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from configuration import config

class DiscordPanel(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.authorized_users = set()  # Track authorized users
    
    def load_servers_config(self):
        """Load servers from discords_config.json"""
        try:
            with open('configuration/discords_config.json', 'r') as f:
                config_data = json.load(f)
            return config_data.get('servers', [])
        except Exception as e:
            print(f"Error loading servers config: {e}")
            return []
    
    async def get_server_name(self, server_id):
        """Get server name from Discord API"""
        try:
            guild = self.bot.get_guild(int(server_id))
            if guild:
                return guild.name
            return f"Server {server_id}"
        except Exception as e:
            print(f"Error getting server name for {server_id}: {e}")
            return f"Server {server_id}"
    
    async def is_user_in_server(self, user_id, server_id):
        """Check if user is already in a server"""
        try:
            guild = self.bot.get_guild(int(server_id))
            if guild:
                member = guild.get_member(int(user_id))
                return member is not None
            return False
        except Exception as e:
            print(f"Error checking if user {user_id} is in server {server_id}: {e}")
            return False
    
    async def check_user_authorization(self, user_id):
        """Check if user is authorized via the web API"""
        try:
            load_dotenv('.env')
            web_url = os.getenv('WEB_URL', 'https://royalguard-discordspanel.up.railway.app')
            
            response = requests.get(f"{web_url}/api/check-auth/{user_id}")
            if response.status_code == 200:
                data = response.json()
                return data.get('authorized', False)
            return False
        except Exception as e:
            print(f"Error checking authorization for user {user_id}: {e}")
            return False
    
    async def handle_panel_button(self, interaction: discord.Interaction):
        """Handle the Discords Panel button interaction"""
        user_id = str(interaction.user.id)
        
        # Load web URL from environment 
        load_dotenv('.env')
        web_url = os.getenv('WEB_URL', 'https://royalguard-discordspanel.up.railway.app')
        
        # Check if user is authorized
        is_authorized = await self.check_user_authorization(user_id)
        
        if not is_authorized:
            # User not authorized - show authorization button
            embed = discord.Embed(
                title="Discords Panel",
                description="Please use the link button below to authorize access to our Discords Panel.",
                color=discord.Color.dark_blue()
            )
            embed.set_author(
                name=interaction.user.name,
                icon_url=interaction.user.avatar.url if interaction.user.avatar else interaction.user.default_avatar.url
            )
            
            view = discord.ui.View(timeout=300)
            auth_button = discord.ui.Button(
                label="Authorize Access",
                style=discord.ButtonStyle.link,
                url=f"{web_url}/authorize"
            )
            view.add_item(auth_button)
            
            await interaction.response.send_message(embed=embed, view=view, ephemeral=True)
            return
        
        # User is authorized - show server selection
        servers = self.load_servers_config()
        available_servers = []
        
        for server_config in servers:
            server_id = server_config['server_id']
            is_member = await self.is_user_in_server(user_id, server_id)
            
            if not is_member:
                server_name = await self.get_server_name(server_id)
                available_servers.append({
                    'id': server_id,
                    'name': server_name
                })
        
        if not available_servers:
            # User has joined all servers
            embed = discord.Embed(
                title="No Available Servers",
                description="You have already joined all the servers available to you!",
                color=discord.Color.dark_gold()
            )
            embed.set_author(
                name=interaction.user.name,
                icon_url=interaction.user.avatar.url if interaction.user.avatar else interaction.user.default_avatar.url
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
        
        # Show server selection dropdown
        embed = discord.Embed(
            title="Discords Panel",
            description="Please use the dropdown below to choose what servers you would like to join. You may need to authorize access to join servers if you haven't used this service in a while.",
            color=discord.Color.dark_blue()
        )
        embed.set_author(
            name=interaction.user.display_name,
            icon_url=interaction.user.avatar.url if interaction.user.avatar else interaction.user.default_avatar.url
        )
        
        view = ServerSelectView(available_servers, self)
        await interaction.response.send_message(embed=embed, view=view, ephemeral=True)
    
    @commands.Cog.listener()
    async def on_ready(self):
        """Automatically send panels when bot starts up"""
        print("Discord Panel cog loaded - sending panels...")
        
        # Load web URL from environment
        load_dotenv('.env')
        web_url = os.getenv('WEB_URL', 'https://royalguard-discordspanel.up.railway.app')
        
        # Use DISCORD_PANELS from config.py
        for channel_id, message_id in config.DISCORD_PANELS.items():
            try:
                channel = self.bot.get_channel(int(channel_id))
                if not channel:
                    print(f"❌ Channel {channel_id} not found")
                    continue
                
                # Check permissions
                permissions = channel.permissions_for(channel.guild.me)
                if not permissions.send_messages or not permissions.embed_links:
                    print(f"❌ Missing permissions in {channel.name}")
                    continue
                
                # Create embed and view
                bot_user = self.bot.user
                panel_embed = discord.Embed(
                    title="Discords Panel",
                    description="Use the button below to access our Discords Panel.",
                    color=discord.Color.dark_blue()
                )
                panel_embed.set_author(
                    name=bot_user.name, 
                    icon_url=bot_user.avatar.url if bot_user.avatar else bot_user.default_avatar.url
                )
                
                # Create view with button
                view = discord.ui.View(timeout=None)
                button = discord.ui.Button(
                    label='Discords Panel', 
                    style=discord.ButtonStyle.blurple,
                    custom_id='discord_panel_button'
                )
                button.callback = self.handle_panel_button
                view.add_item(button)
                
                if message_id and message_id != "None":
                    # Try to edit existing message
                    try:
                        existing_message = await channel.fetch_message(int(message_id))
                        await existing_message.edit(embed=panel_embed, view=view)
                        print(f"✅ Updated Discord panel message in {channel.name} on startup")
                    except discord.NotFound:
                        # Message not found, send new one
                        new_message = await channel.send(embed=panel_embed, view=view)
                        print(f"📤 Sent new Discord panel message in {channel.name} on startup (ID: {new_message.id})")
                else:
                    # Send new message
                    new_message = await channel.send(embed=panel_embed, view=view)
                    print(f"📤 Sent new Discord panel message in {channel.name} on startup (ID: {new_message.id})")
                
            except Exception as e:
                print(f"❌ Error setting up panel in channel {channel_id} on startup: {e}")

class ServerSelectView(discord.ui.View):
    def __init__(self, servers, cog):
        super().__init__(timeout=300)
        self.servers = servers
        self.cog = cog
        
        # Create select menu
        options = []
        for server in servers:
            options.append(discord.SelectOption(
                label=server['name'],
                description=f"Join the {server['name']} server",
                value=server['id']
            ))
        
        select = discord.ui.Select(
            placeholder="Select Discord Server",
            options=options,
            custom_id="server_select"
        )
        select.callback = self.server_select_callback
        self.add_item(select)
    
    async def server_select_callback(self, interaction: discord.Interaction):
        selected_server_id = interaction.data['values'][0]
        
        # Find the selected server
        selected_server = None
        for server in self.servers:
            if server['id'] == selected_server_id:
                selected_server = server
                break
        
        if not selected_server:
            await interaction.response.send_message("Error: Server not found.", ephemeral=True)
            return
        
        # Check if user is already in the server
        user_id = str(interaction.user.id)
        is_member = await self.cog.is_user_in_server(user_id, selected_server_id)
        
        if is_member:
            # User already joined
            embed = discord.Embed(
                title="Warning - Already Joined",
                description=f"You have already joined the `{selected_server['name']}` server!",
                color=discord.Color.dark_gold()
            )
            embed.set_author(
                name=interaction.user.name,
                icon_url=interaction.user.avatar.url if interaction.user.avatar else interaction.user.default_avatar.url
            )
            await interaction.response.edit_message(embed=embed, view=None)
        else:
            # Try to add user to server
            try:
                guild = self.cog.bot.get_guild(int(selected_server_id))
                if guild:
                    # Create invite for the server
                    invite = await guild.text_channels[0].create_invite(max_age=300, max_uses=1)
                    
                    embed = discord.Embed(
                        title="Discords Panel",
                        description=f"Successfully joined `{selected_server['name']}` server!",
                        color=discord.Color.dark_blue()
                    )
                    embed.set_author(
                        name=interaction.user.display_name,
                        icon_url=interaction.user.avatar.url if interaction.user.avatar else interaction.user.default_avatar.url
                    )
                    
                    # Send invite link in DM
                    try:
                        await interaction.user.send(f"Here's your invite to {selected_server['name']}: {invite.url}")
                    except discord.Forbidden:
                        embed.add_field(name="Invite Link", value=invite.url, inline=False)
                    
                    await interaction.response.edit_message(embed=embed, view=None)
                else:
                    await interaction.response.send_message("Error: Could not access server.", ephemeral=True)
            except Exception as e:
                print(f"Error creating invite for server {selected_server_id}: {e}")
                await interaction.response.send_message("Error: Could not create server invite.", ephemeral=True)

async def setup(bot):
    await bot.add_cog(DiscordPanel(bot))
