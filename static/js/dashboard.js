// Dashboard JavaScript functionality
class DiscordPanel {
    constructor() {
        this.servers = [];
        this.userToken = localStorage.getItem('discord_token');
        this.init();
    }

    async init() {
        await this.loadServers();
    }

    async loadServers() {
        const serversGrid = document.getElementById('serversGrid');
        serversGrid.innerHTML = '<div class="loading">Loading servers...</div>';

        try {
            const response = await fetch('/api/servers');

            if (!response.ok) {
                throw new Error('Failed to load servers');
            }

            const data = await response.json();
            this.servers = data.servers;
            this.renderServers();
        } catch (error) {
            console.error('Error loading servers:', error);
            serversGrid.innerHTML = `
                <div class="error">
                    Failed to load servers. Please try refreshing the page.
                </div>
            `;
        }
    }

    renderServers() {
        const serversGrid = document.getElementById('serversGrid');
        
        if (this.servers.length === 0) {
            serversGrid.innerHTML = `
                <div class="error">
                    No servers available to join.
                </div>
            `;
            return;
        }

        serversGrid.innerHTML = this.servers.map(server => `
            <div class="server-card">
                <div class="server-header">
                    <div class="server-icon">
                        ${server.icon ? 
                            `<img src="https://cdn.discordapp.com/icons/${server.id}/${server.icon}.png" alt="${server.name}">` :
                            server.name.charAt(0).toUpperCase()
                        }
                    </div>
                    <div class="server-info">
                        <h3>${this.escapeHtml(server.name)}</h3>
                        <p>${server.member_count || 'Unknown'} members</p>
                    </div>
                </div>
                <button class="join-button" onclick="discordPanel.joinServer('${server.id}')" ${server.joined ? 'disabled' : ''}>
                    ${server.joined ? 'Already Joined' : 'Join Server'}
                </button>
            </div>
        `).join('');
    }

    async joinServer(serverId) {
        const button = event.target;
        const originalText = button.textContent;
        
        button.disabled = true;
        button.textContent = 'Joining...';

        try {
            const response = await fetch('/api/join-server', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ server_id: serverId })
            });

            const result = await response.json();

            if (response.ok) {
                button.textContent = 'Joined!';
                button.style.background = '#57f287';
                
                // Update server status
                const server = this.servers.find(s => s.id === serverId);
                if (server) {
                    server.joined = true;
                }
                
                setTimeout(() => {
                    button.textContent = 'Already Joined';
                }, 2000);
            } else {
                throw new Error(result.error || 'Failed to join server');
            }
        } catch (error) {
            console.error('Error joining server:', error);
            button.textContent = 'Failed to Join';
            button.style.background = '#ed4245';
            
            setTimeout(() => {
                button.textContent = originalText;
                button.style.background = '#57f287';
                button.disabled = false;
            }, 3000);
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Logout function
function logout() {
    localStorage.removeItem('discord_token');
    window.location.href = '/logout';
}

// Initialize the dashboard when the page loads
const discordPanel = new DiscordPanel();
