from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Matrix RCE Lab</title>
    <style>
        body { background-color: #0f0f0f; color: #ff3333; font-family: monospace; padding: 20px; }
        input { background: #333; border: 1px solid #ff3333; color: #ff3333; padding: 5px; }
        button { background: #ff3333; color: #000; border: none; padding: 5px 10px; cursor: pointer; }
        pre { background: #222; padding: 10px; border: 1px solid #444; }
    </style>
</head>
<body>
    <h1>⚡ Command Injection (RCE) Lab</h1>
    <p>Ping a server to check connectivity.</p>
    <p>Hint: Try chaining commands like <code>127.0.0.1; ls</code></p>
    <form action="/ping" method="GET">
        <input type="text" name="target" placeholder="127.0.0.1" value="127.0.0.1">
        <button type="submit">Ping</button>
    </form>
    <hr>
    {% if output %}
        <h3>Output:</h3>
        <pre>{{ output }}</pre>
    {% endif %}
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(TEMPLATE)

@app.route('/ping')
def ping():
    target = request.args.get('target', '127.0.0.1')
    try:
        # VULNERABILITY: Input is passed directly to shell=True
        # This allows command injection via characters like ; | &&
        output = subprocess.check_output(f"ping -c 1 {target}", shell=True, stderr=subprocess.STDOUT)
        return render_template_string(TEMPLATE, output=output.decode('utf-8'))
    except subprocess.CalledProcessError as e:
        return render_template_string(TEMPLATE, output=e.output.decode('utf-8'))
    except Exception as e:
        return render_template_string(TEMPLATE, output=str(e))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
