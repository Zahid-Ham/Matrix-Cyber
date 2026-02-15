from flask import Flask, request, render_template_string, redirect, url_for
import sqlite3
import subprocess
import platform
SHARED_LISTENER_SCRIPT = """
<script>
    // Matrix Sandbox Auto-Fill Listener v2.1
    window.addEventListener('message', (event) => {
        // console.log("Sandbox: Received message", event.data);
        
        if (event.data.action === 'fill-input') {
            const selector = `input[name="${event.data.field}"]`;
            let target = document.querySelector(selector);
            // console.log("Sandbox: Searching for input", selector, "Found:", target);

            if (!target) {
                target = document.querySelector('input[name="username"]') || 
                         document.querySelector('input[name="q"]') || 
                         document.querySelector('input[name="target"]') ||
                         document.querySelector('input[name="msg"]') || 
                         document.querySelector('input');
            }

            if (target) {
                target.value = event.data.payload;
                target.focus();
                
                // Visual feedback
                const originalBg = target.style.backgroundColor;
                const originalBorder = target.style.border;
                target.style.transition = "all 0.2s";
                target.style.backgroundColor = "rgba(14, 165, 233, 0.2)"; // Brand accent
                target.style.borderColor = "#0ea5e9";
                target.style.transform = "scale(1.02)";

                setTimeout(() => {
                    target.style.backgroundColor = originalBg;
                    target.style.borderColor = "#334155";
                    target.style.transform = "scale(1)";
                    
                    if (event.data.submit && target.form) {
                        const submitBtn = target.form.querySelector('button[type="submit"]');
                        if (submitBtn) {
                            submitBtn.click();
                        } else {
                            target.form.submit();
                        }
                    }
                }, 600);
            }
        } else if (event.data.action === 'get-content') {
            console.log("Sandbox: Sending page content to parent...");
            event.source.postMessage({
                action: 'content-response',
                content: document.body.innerText
            }, event.origin);
        }
    });
</script>
"""

app = Flask(__name__)

# Sandbox environment - Intentionally Vulnerable
# DO NOT DEPLOY IN PRODUCTION

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('DROP TABLE IF EXISTS users')
    c.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    c.execute("INSERT INTO users (username, password) VALUES ('admin', 'Sup3rS3cr3tP@ssw0rd')")
    c.execute("INSERT INTO users (username, password) VALUES ('guest', 'guest123')")
    conn.commit()
    conn.close()

init_db()

# Improved Corporate Theme & Injected Sandbox Script
BASE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Matrix Financial | Secure Portal</title>
    <style>
        :root { --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --accent: #0ea5e9; --success: #10b981; --danger: #ef4444; --border: #334155; }
        * { box-sizing: border-box; }
        body { font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--text); margin: 0; min-height: 100vh; display: flex; flex-direction: column; }
        
        header { 
            background: rgba(30, 41, 59, 0.8); 
            backdrop-filter: blur(10px); 
            border-bottom: 1px solid var(--border); 
            padding: 1rem 2rem; 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            position: sticky; top: 0; z-index: 10;
        }
        
        .logo { font-weight: 800; font-size: 1.5rem; color: var(--text); letter-spacing: -0.5px; display: flex; align-items: center; gap: 0.5rem; }
        .logo span { color: var(--accent); }
        
        nav { display: flex; gap: 1.5rem; }
        nav a { color: #94a3b8; text-decoration: none; font-weight: 500; transition: color 0.2s; font-size: 0.95rem; }
        nav a:hover, nav a.active { color: var(--accent); }
        
        main { flex: 1; padding: 3rem 2rem; max-width: 1200px; margin: 0 auto; width: 100%; animate: fadeIn 0.5s ease; }
        
        .hero { text-align: center; margin-bottom: 4rem; }
        .hero h1 { font-size: 3rem; margin-bottom: 1rem; background: linear-gradient(to right, #fff, #94a3b8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .hero p { color: #94a3b8; font-size: 1.2rem; max-width: 600px; margin: 0 auto; }
        
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem; }
        
        .card { 
            background: var(--card); 
            border: 1px solid var(--border); 
            border-radius: 12px; 
            padding: 2rem; 
            transition: transform 0.2s, box-shadow 0.2s; 
        }
        .card:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(0,0,0,0.2); border-color: var(--accent); }
        
        .card h3 { color: var(--text); margin-top: 0; font-size: 1.25rem; display: flex; align-items: center; gap: 0.5rem; }
        .card p { color: #94a3b8; line-height: 1.6; }
        .card .action { margin-top: 1.5rem; display: block; text-align: center; background: var(--border); color: var(--text); padding: 0.75rem; border-radius: 6px; text-decoration: none; font-weight: 600; transition: all 0.2s; }
        .card .action:hover { background: var(--accent); color: white; }
        
        /* Form Styles */
        .login-container { max-width: 400px; margin: 2rem auto; }
        input { width: 100%; padding: 0.875rem; margin: 0.5rem 0 1.5rem; background: #020617; border: 1px solid var(--border); color: white; border-radius: 6px; font-size: 1rem; transition: border-color 0.2s; }
        input:focus { outline: none; border-color: var(--accent); }
        label { color: #94a3b8; font-size: 0.875rem; font-weight: 500; }
        button { width: 100%; padding: 0.875rem; background: var(--accent); color: white; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 1rem; transition: opacity 0.2s; }
        button:hover { opacity: 0.9; }

        .alert { padding: 1rem; border-radius: 6px; margin-top: 1rem; border-left: 4px solid; }
        .alert.error { background: rgba(239, 68, 68, 0.1); border-color: var(--danger); color: #fca5a5; }
        .alert.success { background: rgba(16, 185, 129, 0.1); border-color: var(--success); color: #6ee7b7; }
        
        code { background: #020617; padding: 0.2rem 0.4rem; border-radius: 4px; color: #fbbf24; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; }
        
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
    </style>
    <script>
        // Matrix Sandbox Auto-Fill Listener v2.0
        window.addEventListener('message', (event) => {
            console.log("Sandbox: Received message", event.data);
            
            if (event.data.action === 'fill-input') {
                const selector = `input[name="${event.data.field}"]`;
                let target = document.querySelector(selector);
                console.log("Sandbox: Searching for input", selector, "Found:", target);

                if (!target) {
                    console.warn("Sandbox: Target not found, trying heuristics...");
                    target = document.querySelector('input[name="username"]') || 
                             document.querySelector('input[name="q"]') || 
                             document.querySelector('input[name="target"]') || 
                             document.querySelector('input');
                }

                if (target) {
                    console.log("Sandbox: Filling input with payload:", event.data.payload);
                    target.value = event.data.payload;
                    target.focus();
                    
                    // Visual feedback
                    const originalBg = target.style.backgroundColor;
                    const originalBorder = target.style.border;
                    target.style.transition = "all 0.2s";
                    target.style.backgroundColor = "rgba(14, 165, 233, 0.2)"; // Brand accent
                    target.style.borderColor = "#0ea5e9";
                    target.style.transform = "scale(1.02)";

                    setTimeout(() => {
                        target.style.backgroundColor = originalBg;
                        target.style.borderColor = "#334155";
                        target.style.transform = "scale(1)";
                        
                        if (event.data.submit && target.form) {
                            console.log("Sandbox: Auto-submitting form...");
                            const submitBtn = target.form.querySelector('button[type="submit"]');
                            if (submitBtn) {
                                console.log("Sandbox: Clicking submit button");
                                submitBtn.click();
                            } else {
                                console.log("Sandbox: Calling form.submit()");
                                target.form.submit();
                            }
                        }
                    }, 600);
                } else {
                    console.error("Sandbox: No suitable input found to fill.");
                }
            }
        });
    </script>
</head>
<body>
    <header>
        <div class="logo">MATRIX<span>FINANCIAL</span></div>
        <nav>
            <a href="/">Dashboard</a>
            <a href="/login" class="{active_login}">Employee Portal</a>
            <a href="/search" class="{active_search}">Document Vault</a>
            <a href="/ping" class="{active_ping}">SysAdmin</a>
        </nav>
    </header>
    
    <!-- Browser Navigation Toolbar (User Requested) -->
    <div style="background: #0f172a; border-bottom: 1px solid var(--border); padding: 0.5rem 2rem; display: flex; gap: 0.5rem; align-items: center;">
        <button onclick="history.back()" style="background: var(--card); border: 1px solid var(--border); color: var(--text); padding: 0.25rem 0.75rem; border-radius: 4px; cursor: pointer; font-size: 0.9rem;">
            ← Back
        </button>
        <button onclick="history.forward()" style="background: var(--card); border: 1px solid var(--border); color: var(--text); padding: 0.25rem 0.75rem; border-radius: 4px; cursor: pointer; font-size: 0.9rem;">
            Forward →
        </button>
        <div style="width: 1px; height: 20px; background: var(--border); margin: 0 0.5rem;"></div>
        <a href="/" style="text-decoration: none;">
            <button style="background: var(--card); border: 1px solid var(--border); color: var(--text); padding: 0.25rem 0.75rem; border-radius: 4px; cursor: pointer; font-size: 0.9rem; display: flex; align-items: center; gap: 0.4rem;">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>
                Home
            </button>
        </a>
        <span style="margin-left: auto; color: #64748b; font-size: 0.8rem; font-family: monospace;">SECURE_CONNECTION_ESTABLISHED_V4</span>
    </div>

    <main>
        <!--CONTENT-->
    </main>
</body>
</html>
"""

def render_page(content, active=""):
    # Simple active state replacement
    html = BASE_HTML
    if active == "login": html = html.replace("{active_login}", "active")
    if active == "search": html = html.replace("{active_search}", "active")
    if active == "ping": html = html.replace("{active_ping}", "active")
    
    # Clean up unused placeholders
    html = html.replace("{active_login}", "").replace("{active_search}", "").replace("{active_ping}", "")
    
    return render_template_string(html.replace('<!--CONTENT-->', content))

@app.route('/')
def index():
    template = """
        <div class="hero">
            <h1>Global Markets Dashboard</h1>
            <p>Secure real-time access to global financial data, internal reports, and system diagnostics.</p>
        </div>
        
        <div class="grid">
            <div class="card">
                <h3>📈 Market Indices</h3>
                <div style="font-family: monospace; font-size: 1.1rem; margin-top: 1rem;">
                    <div style="display:flex; justify-content:space-between; margin-bottom:0.5rem;">
                        <span>S&P 500</span> <span style="color:#10b981;">+1.2%</span>
                    </div>
                    <div style="display:flex; justify-content:space-between; margin-bottom:0.5rem;">
                        <span>NASDAQ</span> <span style="color:#ef4444;">-0.4%</span>
                    </div>
                    <div style="display:flex; justify-content:space-between;">
                        <span>FTSE 100</span> <span style="color:#10b981;">+0.8%</span>
                    </div>
                </div>
                <div style="margin-top: 1rem; height: 4px; background: #334155; border-radius: 2px; overflow: hidden;">
                    <div style="width: 60%; height: 100%; background: #10b981;"></div>
                </div>
            </div>
            
            <div class="card">
                <h3>🔒 Restricted Access</h3>
                <p>Employee portal for payroll, HR, and administrative functions. Authorized personnel only.</p>
                <a href="/login" class="action">Employee Login</a>
            </div>
            
            <div class="card">
                <h3>📂 Corporate Archives</h3>
                <p>Searchable index of public filings, quarterly reports, and meeting minutes.</p>
                <a href="/search" class="action">Search Documents</a>
            </div>
        </div>
    """
    return render_page(template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ""
    query_debug = ""
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # VULNERABILITY: SQL Injection
        query = f"SELECT * FROM users WHERE username = '{username}'"
        
        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute(query)
            user = c.fetchone()
            conn.close()
            
            if user:
                # SUCCESS: Render Secure Dashboard
                flag_display = ""
                if user[1] == 'admin':
                    flag_display = """
                    <div class="alert success" style="margin-top: 2rem; border-left: 4px solid #10b981;">
                        <h3 style="margin: 0; color: #10b981;">CRITICAL ASSET ACCESSED</h3>
                        <p style="margin: 0.5rem 0 0 0;">FLAG: <strong>MATRIX{SQL_INJECTION_MASTER}</strong></p>
                    </div>
                    """
                
                dashboard_template = f"""
                    <div class="hero" style="text-align: left; margin-bottom: 2rem;">
                        <h1 style="font-size: 2.5rem;">Secure Employee Dashboard</h1>
                        <p style="color: #94a3b8;">Welcome back, <span style="color: var(--accent);">{user[1]}</span>. Your session is active.</p>
                    </div>

                    {flag_display}

                    <div class="grid" style="margin-top: 3rem;">
                        <div class="card">
                            <div style="display:flex; justify-content:space-between; align-items:center;">
                                <h3>📂 Document Vault</h3>
                                <span style="background:rgba(14, 165, 233, 0.1); color:var(--accent); padding:0.2rem 0.6rem; border-radius:12px; font-size:0.8rem;">Authorized</span>
                            </div>
                            <p>Access classified internal documents and reports.</p>
                            <a href="/search" class="action">Open Vault</a>
                        </div>

                        <div class="card">
                            <div style="display:flex; justify-content:space-between; align-items:center;">
                                <h3>⚡ Server Admin</h3>
                                <span style="background:rgba(16, 185, 129, 0.1); color:#10b981; padding:0.2rem 0.6rem; border-radius:12px; font-size:0.8rem;">Online</span>
                            </div>
                            <p>Manage infrastructure and run system diagnostics.</p>
                            <a href="/ping" class="action">Launch Console</a>
                        </div>
                        
                        <div class="card" style="opacity: 0.7;">
                            <h3>💸 Payroll Systems</h3>
                            <p>Manage employee salaries and benefits.</p>
                            <button disabled style="margin-top:1.5rem; width:100%; padding:0.75rem; background:#334155; border:none; border-radius:6px; cursor:not-allowed;">Maintenance Mode</button>
                        </div>
                    </div>
                """
                return render_page(dashboard_template, "login")
            else:
                message = "Invalid credentials."
        except Exception as e:
            message = f"Database Error: {str(e)}"
            
        query_debug = query

    template = f"""
        <div class="login-container">
            <div class="card">
                <h2 style="text-align:center; margin-bottom:2rem; color:var(--text);">Employee Sign In</h2>
                <form method="POST">
                    <label>Username / Employee ID</label>
                    <input type="text" name="username" placeholder="e.g. j.doe or admin" required autocomplete="off">
                    
                    <label>Password</label>
                    <input type="password" name="password" placeholder="••••••••" autocomplete="off">
                    
                    <button type="submit">Authentication Required</button>
                </form>
                {f'<div class="alert {"success" if "Welcome" in message else "error"}">{message}</div>' if message else ''}
                {f'<div style="margin-top:1.5rem; border-top:1px solid #334155; padding-top:1rem; font-size:0.8rem; color:#64748b;">Process Log:<br><code>{query_debug}</code></div>' if query_debug else ''}
            </div>
        </div>
    """
    return render_page(template, "login")

@app.route('/search', methods=['GET'])
def search():
    q = request.args.get('q', '')
    
    # VULNERABILITY: Reflected XSS
    
    template = f"""
        <div class="hero" style="text-align: left; margin-bottom: 2rem;">
            <h1 style="font-size: 2.5rem;">Document Vault</h1>
            <p style="color: #94a3b8;">Search classified internal documents and reports.</p>
        </div>

        <div class="card">
            <form method="GET" style="position: relative; display: flex; gap: 1rem;">
                <input type="text" name="q" placeholder="Enter keywords (e.g. 'quarterly report', 'merged assets')..." value="{q.replace('"', '&quot;') if q else ''}" style="margin-bottom: 0;">
                <button type="submit" style="width: auto; padding: 0 2rem; white-space: nowrap;">Search Archives</button>
            </form>
            
            {f'<div class="alert success" style="margin-top: 1.5rem; background:rgba(14, 165, 233, 0.1); border-color:var(--accent); color:#fff;"><span style="color:var(--accent)">Results for:</span> <b>{q}</b><br><br>No matching records found in the active index.</div>' if q else ''}
            
            <div style="margin-top: 2rem; border-top: 1px solid var(--border); padding-top: 1rem; color: #64748b; font-size: 0.9rem;">
                <p><strong>Security Notice:</strong> All search queries are logged for audit purposes.</p>
            </div>
        </div>
    """
    return render_page(template, "search")

@app.route('/xss-lab', methods=['GET', 'POST'])
def xss_lab():
    """
    Immersive XSS Lab: Matrix Comms Relay
    """
    messages = []
    # Simulate a persistence layer for the session (in-memory list for demo)
    # In a real reflection, we often just reflect the *current* input, but a chat log is better for "stored" feel
    # For Reflected XSS, we'll just reflect the query param 'msg'
    
    msg = request.args.get('msg', '')
    
    # Pre-seed some "lore" messages
    chat_history = [
        {"user": "Morpheus", "text": "The line is not secure. We need to re-key encryption.", "time": "10:42 AM"},
        {"user": "Trinity", "text": "Agents are monitoring the main nodes.", "time": "10:43 AM"},
        {"user": "Operator", "text": "I'm seeing signal interference in Sector 7.", "time": "10:45 AM"}
    ]
    
    if msg:
        chat_history.append({"user": "Guest", "text": msg, "time": "Now"})

    chat_html = ""
    for m in chat_history:
        # VULNERABILITY: No escaping of m['text']
        chat_html += f"""
        <div class="message {'self' if m['user'] == 'Guest' else ''}">
            <div class="meta">{m['user']} • {m['time']}</div>
            <div class="content">{m['text']}</div>
        </div>
        """

    template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Matrix Comms Relay</title>
        <style>
            :root {{ --bg: #000; --term: #0d1117; --green: #00ff41; --dim: #008f11; }}
            body {{ background: var(--bg); color: var(--green); font-family: 'Consolas', 'Monaco', monospace; margin: 0; display: flex; flex-direction: column; height: 100vh; overflow: hidden; }}
            
            header {{ padding: 1rem; border-bottom: 1px solid var(--dim); display: flex; justify-content: space-between; align-items: center; background: #050505; }}
            .status {{ font-size: 0.8rem; letter-spacing: 2px; animation: blink 2s infinite; }}
            
            .chat-window {{ flex: 1; overflow-y: auto; padding: 2rem; display: flex; flex-direction: column; gap: 1rem; scroll-behavior: smooth; }}
            
            .message {{ max-width: 80%; border-left: 3px solid var(--dim); padding-left: 1rem; }}
            .message.self {{ align-self: flex-end; border-left: none; border-right: 3px solid var(--green); padding-left: 0; padding-right: 1rem; text-align: right; }}
            
            .meta {{ font-size: 0.7rem; color: #444; margin-bottom: 0.2rem; text-transform: uppercase; }}
            .content {{ font-size: 1.1rem; text-shadow: 0 0 5px rgba(0, 255, 65, 0.3); word-break: break-all; }}
            
            .input-area {{ padding: 1.5rem; background: #050505; border-top: 1px solid var(--dim); display: flex; gap: 1rem; }}
            input {{ flex: 1; background: #111; border: 1px solid var(--dim); color: var(--green); padding: 1rem; font-family: inherit; font-size: 1rem; }}
            input:focus {{ outline: none; border-color: var(--green); box-shadow: 0 0 10px rgba(0, 255, 65, 0.2); }}
            button {{ background: var(--dim); color: #000; border: none; padding: 0 2rem; font-weight: bold; cursor: pointer; transition: all 0.2s; }}
            button:hover {{ background: var(--green); box-shadow: 0 0 15px var(--green); }}
            
            /* Glitch effect for XSS visualization */
            @keyframes blink {{ 0% {{ opacity: 1; }} 50% {{ opacity: 0.5; }} 100% {{ opacity: 1; }} }}
        </style>
        {SHARED_LISTENER_SCRIPT}
    </head>
    <body onload="window.scrollTo(0, document.body.scrollHeight);">
        <header>
            <div>// SECURE RELAY_NODE_V9</div>
            <div class="status">ENCRYPTION: UNSTABLE</div>
        </header>
        
        <div class="chat-window" id="chat">
            {chat_html}
        </div>
        
        <form class="input-area" method="GET">
            <input type="text" name="msg" placeholder="Broadcast message to network..." autofocus autocomplete="off">
            <button type="submit">TRANSMIT</button>
        </form>
        
        <script>
            // Auto-scroll to bottom of chat
            const chat = document.getElementById('chat');
            chat.scrollTop = chat.scrollHeight;
        </script>
    </body>
    </html>
    """
    return render_template_string(template)

@app.route('/rce-lab', methods=['GET'])
def rce_lab():
    """
    Immersive RCE Lab: Grid Infrastructure Control
    """
    target = request.args.get('target', '')
    cmd_output = ""
    
    if target:
        # VULNERABILITY: Command Injection
        # Windows/Linux agnostic ping command
        cmd = f"ping -c 1 {target}" if platform.system() != "Windows" else f"ping -n 1 {target}"
        try:
            # We capture both stdout and stderr
            cmd_output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            cmd_output = cmd_output.decode('utf-8', errors='replace')
        except subprocess.CalledProcessError as e:
            cmd_output = e.output.decode('utf-8', errors='replace')
        except Exception as e:
            cmd_output = f"SYSTEM_ERROR: {str(e)}"

    template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Infrastructure Control</title>
        <style>
            :root {{ --bg: #0a0a0a; --panel: #111; --border: #333; --accent: #f59e0b; --text: #e5e5e5; }}
            body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; min-height: 100vh; display: grid; place-items: center; }}
            
            .console {{ width: 90%; max-width: 1000px; height: 80vh; background: var(--panel); border: 1px solid var(--border); display: flex; flex-direction: column; box-shadow: 0 20px 50px rgba(0,0,0,0.5); }}
            
            .header {{ padding: 0.75rem 1.5rem; background: #1a1a1a; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }}
            .title {{ font-weight: 600; font-size: 0.9rem; color: #888; text-transform: uppercase; letter-spacing: 1px; }}
            .indicators {{ display: flex; gap: 0.5rem; }}
            .dot {{ wudth: 10px; height: 10px; borderRadius: 50%; background: #333; }}
            .dot.active {{ background: var(--accent); box-shadow: 0 0 10px var(--accent); }}
            
            .viewport {{ flex: 1; display: flex; }}
            
            .sidebar {{ width: 200px; border-right: 1px solid var(--border); padding: 1.5rem; display: flex; flex-direction: column; gap: 1rem; }}
            .menu-item {{ padding: 0.75rem; color: #666; cursor: not-allowed; border-radius: 4px; border: 1px solid transparent; }}
            .menu-item.active {{ color: var(--accent); background: rgba(245, 158, 11, 0.1); border-color: rgba(245, 158, 11, 0.2); }}
            
            .main-area {{ flex: 1; padding: 2rem; display: flex; flex-direction: column; gap: 2rem; }}
            
            .tool-panel {{ background: #000; border: 1px solid var(--border); padding: 1.5rem; border-radius: 6px; }}
            
            .input-group {{ display: flex; gap: 1rem; margin-top: 1rem; }}
            input {{ flex: 1; background: #111; border: 1px solid #444; color: white; padding: 0.75rem; font-family: 'Consolas', monospace; }}
            input:focus {{ outline: none; border-color: var(--accent); }}
            button {{ background: var(--accent); color: black; border: none; padding: 0 1.5rem; font-weight: bold; cursor: pointer; }}
            button:hover {{ opacity: 0.9; }}
            
            .terminal-output {{ 
                flex: 1; 
                background: #0d0d0d; 
                border: 1px solid var(--border); 
                border-radius: 6px; 
                padding: 1rem; 
                font-family: 'Consolas', monospace; 
                font-size: 0.9rem; 
                color: #aaa; 
                overflow-y: auto; 
                min-height: 200px;
                white-space: pre-wrap;
            }}
            .prompt {{ color: var(--accent); margin-right: 0.5rem; }}
        </style>
        {SHARED_LISTENER_SCRIPT}
    </head>
    <body>
        <div class="console">
            <div class="header">
                <div class="title">Grid Diagnostics /// Admin_Level_4</div>
                <div class="indicators">
                    <div style="width:8px; height:8px; border-radius:50%; background:#333;"></div>
                    <div style="width:8px; height:8px; border-radius:50%; background:#333;"></div>
                    <div style="width:8px; height:8px; border-radius:50%; background:var(--accent); box-shadow: 0 0 10px var(--accent);"></div>
                </div>
            </div>
            
            <div class="viewport">
                <div class="sidebar">
                    <div class="menu-item active">Connectivity</div>
                    <div class="menu-item">Power Flow</div>
                    <div class="menu-item">Load Balance</div>
                    <div class="menu-item">Emergency Dump</div>
                </div>
                
                <div class="main-area">
                    <div class="tool-panel">
                        <h2 style="margin:0; font-size:1.2rem; display: flex; align-items: center; gap: 0.5rem;">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="16"></line><line x1="8" y1="12" x2="16" y2="12"></line></svg>
                            Network Probe
                        </h2>
                        <p style="color:#666; font-size: 0.9rem;">Test reachability of grid substations.</p>
                        
                        <form method="GET" class="input-group">
                            <input type="text" name="target" placeholder="192.168.x.x" value="{target}">
                            <button type="submit">EXECUTE</button>
                        </form>
                    </div>
                    
                    <div class="terminal-output">
                        <div><span class="prompt">admin@grid-con:~$</span> System Diagnostics Service v2.4 initialized...</div>
                        {f'<div><span class="prompt">admin@grid-con:~$</span> ping {target}</div><div style="color:#e5e5e5; margin-top:0.5rem;">{cmd_output}</div>' if cmd_output else ''}
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(template)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
