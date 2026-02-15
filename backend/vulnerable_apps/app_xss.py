from flask import Flask, request, render_template_string

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Matrix XSS Lab</title>
    <style>
        body { background-color: #1a1a1a; color: #00ff00; font-family: monospace; padding: 20px; }
        input { background: #333; border: 1px solid #00ff00; color: #00ff00; padding: 5px; }
        button { background: #00ff00; color: #000; border: none; padding: 5px 10px; cursor: pointer; }
    </style>
</head>
<body>
    <h1>🔎 Reflected XSS Lab</h1>
    <p>Try to pop an alert box! Example: <code>&lt;script&gt;alert(1)&lt;/script&gt;</code></p>
    <form action="/search" method="GET">
        <input type="text" name="q" placeholder="Search..." size="50">
        <button type="submit">Search</button>
    </form>
    <hr>
    {% if query %}
        <h2>Results for: {{ query|safe }}</h2>
        <p>No results found.</p>
    {% endif %}
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(TEMPLATE)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # VULNERABILITY: 'query' is passed to render_template_string with |safe filter
    # This disables auto-escaping, allowing XSS.
    return render_template_string(TEMPLATE, query=query)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
