import os, sqlite3, secrets, time, socket
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import requests as req
import bcrypt

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
DB_PATH = os.environ.get('DB_PATH', '/data/dns_proxy_manager.db')


# --- Database ---

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            api_key TEXT UNIQUE
        );
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS cert_requests (
            id INTEGER PRIMARY KEY,
            domain TEXT NOT NULL,
            requested_at REAL NOT NULL
        );
    ''')
    # Add api_key column if upgrading
    try:
        db.execute('ALTER TABLE users ADD COLUMN api_key TEXT UNIQUE')
    except Exception:
        pass
    db.commit()
    db.close()


def get_config(key, default=None):
    db = get_db()
    row = db.execute('SELECT value FROM config WHERE key=?', (key,)).fetchone()
    db.close()
    return row['value'] if row else default


def set_config(key, value):
    db = get_db()
    db.execute('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', (key, value))
    db.commit()
    db.close()


# --- Auth ---

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated


def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key', '')
        if not key:
            return jsonify({'error': 'Missing X-API-Key header'}), 401
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE api_key=?', (key,)).fetchone()
        db.close()
        if not user:
            return jsonify({'error': 'Invalid API key'}), 401
        return f(*args, **kwargs)
    return decorated


def has_users():
    db = get_db()
    count = db.execute('SELECT COUNT(*) as c FROM users').fetchone()['c']
    db.close()
    return count > 0


# --- Pi-hole API ---

class PiHoleAPI:
    def __init__(self):
        self.sid = None

    def _url(self):
        return get_config('pihole_url', '').rstrip('/')

    def _auth(self):
        url = self._url()
        password = get_config('pihole_password', '')
        if not url or not password:
            return False
        r = req.post(f'{url}/api/auth', json={'password': password}, timeout=5)
        if r.ok:
            data = r.json()
            self.sid = data.get('session', {}).get('sid', '')
            return bool(self.sid)
        return False

    def _headers(self):
        return {'X-FTL-SID': self.sid} if self.sid else {}

    def _request(self, method, endpoint, **kwargs):
        url = f"{self._url()}{endpoint}"
        kwargs.setdefault('timeout', 10)
        kwargs.setdefault('headers', {}).update(self._headers())
        r = req.request(method, url, **kwargs)
        if r.status_code == 401:
            if self._auth():
                kwargs['headers'].update(self._headers())
                r = req.request(method, url, **kwargs)
        return r

    def get_hosts(self):
        r = self._request('GET', '/api/config/dns/hosts')
        if r.ok:
            data = r.json()
            return data.get('config', {}).get('dns', {}).get('hosts', [])
        return []

    def add_host(self, ip, domain):
        encoded = req.utils.quote(f'{ip} {domain}')
        r = self._request('PUT', f'/api/config/dns/hosts/{encoded}')
        return r.ok

    def delete_host(self, ip, domain):
        encoded = req.utils.quote(f'{ip} {domain}')
        r = self._request('DELETE', f'/api/config/dns/hosts/{encoded}')
        return r.status_code in (200, 204)

    def test_connection(self):
        try:
            return self._auth()
        except Exception:
            return False


# --- NPM API ---

class NPMAPI:
    def __init__(self):
        self.token = None

    def _url(self):
        return get_config('npm_url', '').rstrip('/')

    def _auth(self):
        url = self._url()
        identity = get_config('npm_identity', '')
        secret = get_config('npm_secret', '')
        if not url or not identity or not secret:
            return False
        r = req.post(f'{url}/api/tokens', json={'identity': identity, 'secret': secret}, timeout=5)
        if r.ok:
            self.token = r.json().get('token', '')
            return bool(self.token)
        return False

    def _headers(self):
        return {'Authorization': f'Bearer {self.token}'} if self.token else {}

    def _request(self, method, endpoint, **kwargs):
        url = f"{self._url()}{endpoint}"
        kwargs.setdefault('timeout', 10)
        kwargs.setdefault('headers', {})
        kwargs['headers'].update(self._headers())
        kwargs['headers']['Content-Type'] = 'application/json'
        r = req.request(method, url, **kwargs)
        if r.status_code == 401:
            if self._auth():
                kwargs['headers'].update(self._headers())
                r = req.request(method, url, **kwargs)
        return r

    def get_proxy_hosts(self):
        r = self._request('GET', '/api/nginx/proxy-hosts')
        return r.json() if r.ok else []

    def create_proxy_host(self, domain, forward_host, forward_port, ssl=False, cert_id=0, force_ssl=False):
        data = {
            'domain_names': [domain],
            'forward_scheme': 'http',
            'forward_host': forward_host,
            'forward_port': int(forward_port),
            'access_list_id': 0,
            'certificate_id': cert_id,
            'ssl_forced': force_ssl,
            'http2_support': False,
            'hsts_enabled': False,
            'hsts_subdomains': False,
            'block_exploits': False,
            'caching_enabled': False,
            'allow_websocket_upgrade': True,
            'locations': [],
            'advanced_config': ''
        }
        r = self._request('POST', '/api/nginx/proxy-hosts', json=data)
        return r.json() if r.ok else None

    def delete_proxy_host(self, host_id):
        r = self._request('DELETE', f'/api/nginx/proxy-hosts/{host_id}')
        return r.status_code in (200, 204)

    def get_certificates(self):
        r = self._request('GET', '/api/nginx/certificates')
        return r.json() if r.ok else []

    def request_le_cert(self, domain):
        data = {
            'provider': 'letsencrypt',
            'domain_names': [domain],
            'meta': {
                'letsencrypt_email': get_config('npm_identity', ''),
                'letsencrypt_agree': True,
                'dns_challenge': False
            }
        }
        r = self._request('POST', '/api/nginx/certificates', json=data)
        return r.json() if r.ok else None

    def update_proxy_host(self, host_id, updates):
        r = self._request('PUT', f'/api/nginx/proxy-hosts/{host_id}', json=updates)
        return r.json() if r.ok else None

    def domain_exists(self, domain):
        hosts = self.get_proxy_hosts()
        for h in hosts:
            if domain in h.get('domain_names', []):
                return h['id']
        return None

    def test_connection(self):
        try:
            return self._auth()
        except Exception:
            return False


pihole = PiHoleAPI()
npm = NPMAPI()


# --- Rate Limit Tracking ---

def check_rate_limit(domain):
    """Returns (count_this_week, can_request)"""
    base_domain = '.'.join(domain.rsplit('.', 2)[-2:])
    week_ago = time.time() - (7 * 86400)
    db = get_db()
    count = db.execute(
        'SELECT COUNT(*) as c FROM cert_requests WHERE domain LIKE ? AND requested_at > ?',
        (f'%{base_domain}', week_ago)
    ).fetchone()['c']
    db.close()
    return count, count < 50


def record_cert_request(domain):
    db = get_db()
    db.execute('INSERT INTO cert_requests (domain, requested_at) VALUES (?, ?)', (domain, time.time()))
    db.commit()
    db.close()


# --- Routes ---

@app.route('/')
@login_required
def home():
    pihole._auth()
    npm._auth()
    dns_hosts = pihole.get_hosts()
    proxy_hosts = npm.get_proxy_hosts()

    # Parse DNS entries
    dns_map = {}
    for entry in dns_hosts:
        parts = entry.split(' ', 1)
        if len(parts) == 2:
            dns_map[parts[1]] = parts[0]

    # Parse proxy hosts
    proxy_map = {}
    for h in proxy_hosts:
        for d in h.get('domain_names', []):
            proxy_map[d] = h

    # Get certificates for provider detection
    certs = npm.get_certificates()
    cert_map = {c['id']: c for c in certs}

    # Merge
    all_domains = sorted(set(list(dns_map.keys()) + list(proxy_map.keys())))
    entries = []
    for domain in all_domains:
        entry = {
            'domain': domain,
            'dns_ip': dns_map.get(domain),
            'proxy': proxy_map.get(domain),
            'forward_host': None,
            'forward_port': None,
            'ssl': None,
            'ssl_forced': False,
            'cert_id': 0,
            'is_external': False,
        }
        if entry['proxy']:
            entry['forward_host'] = entry['proxy'].get('forward_host')
            entry['forward_port'] = entry['proxy'].get('forward_port')
            entry['cert_id'] = entry['proxy'].get('certificate_id', 0)
            entry['ssl_forced'] = entry['proxy'].get('ssl_forced', False)
            if entry['cert_id'] and entry['cert_id'] > 0:
                cert_info = cert_map.get(entry['cert_id'], {})
                provider = cert_info.get('provider', 'other')
                if provider == 'letsencrypt':
                    entry['ssl'] = 'Let\'s Encrypt'
                    entry['is_external'] = True
                else:
                    entry['ssl'] = 'Custom Cert'
            else:
                entry['ssl'] = 'None'
        entries.append(entry)

    return render_template('home.html', entries=entries)


@app.route('/add', methods=['GET', 'POST'])
@admin_required
def add_fqdn():
    if request.method == 'POST':
        domain = request.form['domain'].strip().lower()
        forward_host = request.form['forward_host'].strip()
        forward_port = request.form['forward_port'].strip()
        fqdn_type = request.form['type']
        force_ssl = request.form.get('force_ssl') == 'on'
        dns_ip = request.form.get('dns_ip', '10.69.0.99').strip()

        # Duplicate check
        npm._auth()
        existing = npm.domain_exists(domain)
        if existing:
            flash(f'Domain {domain} already exists in NPM (ID: {existing})', 'error')
            return redirect(url_for('add_fqdn'))

        # Create DNS entry
        if fqdn_type in ('internal', 'internal_ssl'):
            pihole._auth()
            if not pihole.add_host(dns_ip, domain):
                flash('Failed to create DNS entry in Pi-hole', 'error')
                return redirect(url_for('add_fqdn'))
        elif fqdn_type == 'external' and request.form.get('add_local_dns') == 'on':
            pihole._auth()
            pihole.add_host(dns_ip, domain)

        # Create proxy host
        cert_id = 0
        if fqdn_type == 'external':
            # Check rate limit
            count, can_request = check_rate_limit(domain)
            if not can_request:
                flash(f'Let\'s Encrypt rate limit reached ({count}/50 this week)', 'error')
                return redirect(url_for('add_fqdn'))

            # Request cert
            cert = npm.request_le_cert(domain)
            if cert and 'id' in cert:
                cert_id = cert['id']
                record_cert_request(domain)
            else:
                flash('Warning: cert request may have failed. Proxy created without SSL.', 'warning')

        result = npm.create_proxy_host(domain, forward_host, forward_port,
                                       ssl=(cert_id > 0), cert_id=cert_id, force_ssl=force_ssl)
        if result:
            flash(f'Created {domain} successfully', 'success')
        else:
            flash('Failed to create proxy host in NPM', 'error')

        return redirect(url_for('home'))

    return render_template('add.html')


@app.route('/delete/<domain>', methods=['POST'])
@admin_required
def delete_fqdn(domain):
    pihole._auth()
    npm._auth()

    # Find and delete from NPM
    proxy_hosts = npm.get_proxy_hosts()
    for h in proxy_hosts:
        if domain in h.get('domain_names', []):
            npm.delete_proxy_host(h['id'])
            break

    # Find and delete from Pi-hole
    dns_hosts = pihole.get_hosts()
    for entry in dns_hosts:
        parts = entry.split(' ', 1)
        if len(parts) == 2 and parts[1] == domain:
            pihole.delete_host(parts[0], domain)
            break

    flash(f'Deleted {domain}', 'success')
    return redirect(url_for('home'))


@app.route('/edit/<domain>', methods=['GET', 'POST'])
@admin_required
def edit_fqdn(domain):
    npm._auth()
    pihole._auth()

    # Get current proxy host
    proxy_hosts = npm.get_proxy_hosts()
    proxy = None
    for h in proxy_hosts:
        if domain in h.get('domain_names', []):
            proxy = h
            break

    # Get current DNS
    dns_hosts = pihole.get_hosts()
    dns_ip = None
    for entry in dns_hosts:
        parts = entry.split(' ', 1)
        if len(parts) == 2 and parts[1] == domain:
            dns_ip = parts[0]
            break

    if request.method == 'POST':
        forward_host = request.form['forward_host'].strip()
        forward_port = request.form['forward_port'].strip()
        force_ssl = request.form.get('force_ssl') == 'on'
        new_dns_ip = request.form.get('dns_ip', '').strip()

        # Update proxy host
        if proxy:
            updates = {
                'domain_names': [domain],
                'forward_scheme': 'http',
                'forward_host': forward_host,
                'forward_port': int(forward_port),
                'certificate_id': proxy.get('certificate_id', 0),
                'ssl_forced': force_ssl,
                'http2_support': proxy.get('http2_support', False),
                'hsts_enabled': proxy.get('hsts_enabled', False),
                'hsts_subdomains': proxy.get('hsts_subdomains', False),
                'block_exploits': proxy.get('block_exploits', False),
                'caching_enabled': proxy.get('caching_enabled', False),
                'allow_websocket_upgrade': proxy.get('allow_websocket_upgrade', True),
                'access_list_id': proxy.get('access_list_id', 0),
                'locations': proxy.get('locations') or [],
                'advanced_config': proxy.get('advanced_config', '')
            }
            npm.update_proxy_host(proxy['id'], updates)

        # Update DNS
        if new_dns_ip:
            # Remove old entry if exists
            if dns_ip:
                pihole.delete_host(dns_ip, domain)
            pihole.add_host(new_dns_ip, domain)
        elif dns_ip and not new_dns_ip:
            # Remove DNS if cleared
            pihole.delete_host(dns_ip, domain)

        flash(f'Updated {domain}', 'success')
        return redirect(url_for('home'))

    return render_template('edit.html', domain=domain, proxy=proxy, dns_ip=dns_ip)


@app.route('/validate-dns')
@login_required
def validate_dns():
    """AJAX endpoint to check public DNS resolution"""
    domain = request.args.get('domain', '')
    try:
        ip = socket.gethostbyname(domain)
        return jsonify({'resolved': True, 'ip': ip})
    except socket.gaierror:
        return jsonify({'resolved': False, 'ip': None})


# --- Config ---

@app.route('/config', methods=['GET', 'POST'])
@admin_required
def config_page():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'save_connections':
            set_config('pihole_url', request.form['pihole_url'].strip())
            set_config('pihole_password', request.form['pihole_password'].strip())
            set_config('npm_url', request.form['npm_url'].strip())
            set_config('npm_identity', request.form['npm_identity'].strip())
            set_config('npm_secret', request.form['npm_secret'].strip())
            flash('Connections saved', 'success')
        elif action == 'test_pihole':
            set_config('pihole_url', request.form['pihole_url'].strip())
            set_config('pihole_password', request.form['pihole_password'].strip())
            if pihole.test_connection():
                flash('Pi-hole connection successful', 'success')
            else:
                flash('Pi-hole connection failed', 'error')
        elif action == 'test_npm':
            set_config('npm_url', request.form['npm_url'].strip())
            set_config('npm_identity', request.form['npm_identity'].strip())
            set_config('npm_secret', request.form['npm_secret'].strip())
            if npm.test_connection():
                flash('NPM connection successful', 'success')
            else:
                flash('NPM connection failed', 'error')
        return redirect(url_for('config_page'))

    return render_template('config.html',
                           pihole_url=get_config('pihole_url', ''),
                           pihole_password=get_config('pihole_password', ''),
                           npm_url=get_config('npm_url', ''),
                           npm_identity=get_config('npm_identity', ''),
                           npm_secret=get_config('npm_secret', ''))


@app.route('/config/users')
@admin_required
def config_users():
    db = get_db()
    users = db.execute('SELECT id, username, role FROM users').fetchall()
    db.close()
    return render_template('users.html', users=users)


@app.route('/config/users/add', methods=['POST'])
@admin_required
def add_user():
    username = request.form['username'].strip()
    password = request.form['password']
    role = request.form.get('role', 'viewer')
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    db = get_db()
    try:
        db.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                   (username, pw_hash, role))
        db.commit()
        flash(f'User {username} created', 'success')
    except sqlite3.IntegrityError:
        flash(f'User {username} already exists', 'error')
    db.close()
    return redirect(url_for('config_users'))


@app.route('/config/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    if user_id == session.get('user_id'):
        flash('Cannot delete yourself', 'error')
        return redirect(url_for('config_users'))
    db = get_db()
    db.execute('DELETE FROM users WHERE id=?', (user_id,))
    db.commit()
    db.close()
    flash('User deleted', 'success')
    return redirect(url_for('config_users'))


@app.route('/config/users/password/<int:user_id>', methods=['POST'])
@admin_required
def change_password(user_id):
    password = request.form['password']
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    db = get_db()
    db.execute('UPDATE users SET password_hash=? WHERE id=?', (pw_hash, user_id))
    db.commit()
    db.close()
    flash('Password updated', 'success')
    return redirect(url_for('config_users'))


# --- Auth Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if not has_users():
        return redirect(url_for('setup'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        db.close()
        if user and bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('home'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if has_users():
        return redirect(url_for('login'))
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        db = get_db()
        db.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                   (username, pw_hash, 'admin'))
        db.commit()
        db.close()

        # Save connections if provided
        if request.form.get('pihole_url'):
            set_config('pihole_url', request.form['pihole_url'].strip())
            set_config('pihole_password', request.form['pihole_password'].strip())
        if request.form.get('npm_url'):
            set_config('npm_url', request.form['npm_url'].strip())
            set_config('npm_identity', request.form['npm_identity'].strip())
            set_config('npm_secret', request.form['npm_secret'].strip())

        flash('Setup complete! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('setup.html')


@app.route('/config/users/apikey/<int:user_id>', methods=['POST'])
@admin_required
def generate_api_key(user_id):
    key = secrets.token_urlsafe(32)
    db = get_db()
    db.execute('UPDATE users SET api_key=? WHERE id=?', (key, user_id))
    db.commit()
    db.close()
    flash(f'API key generated: {key}', 'success')
    return redirect(url_for('config_users'))


# --- REST API ---

@app.route('/api/health')
def api_health():
    return jsonify({'status': 'ok', 'app': 'linkr', 'version': '1.0.0'})


@app.route('/api/fqdns', methods=['GET'])
@api_key_required
def api_list_fqdns():
    pihole._auth()
    npm._auth()
    dns_hosts = pihole.get_hosts()
    proxy_hosts = npm.get_proxy_hosts()

    dns_map = {}
    for entry in dns_hosts:
        parts = entry.split(' ', 1)
        if len(parts) == 2:
            dns_map[parts[1]] = parts[0]

    proxy_map = {}
    for h in proxy_hosts:
        for d in h.get('domain_names', []):
            proxy_map[d] = h

    all_domains = sorted(set(list(dns_map.keys()) + list(proxy_map.keys())))
    results = []
    for domain in all_domains:
        entry = {'domain': domain, 'dns_ip': dns_map.get(domain), 'proxy': None}
        p = proxy_map.get(domain)
        if p:
            entry['proxy'] = {
                'id': p['id'],
                'forward_host': p.get('forward_host'),
                'forward_port': p.get('forward_port'),
                'ssl': bool(p.get('certificate_id')),
                'ssl_forced': p.get('ssl_forced', False)
            }
        results.append(entry)
    return jsonify(results)


@app.route('/api/fqdns', methods=['POST'])
@api_key_required
def api_create_fqdn():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400

    domain = data.get('domain', '').strip().lower()
    forward_host = data.get('forward_host', '').strip()
    forward_port = data.get('forward_port')
    fqdn_type = data.get('type', 'internal')
    force_ssl = data.get('force_ssl', False)
    dns_ip = data.get('dns_ip', '10.69.0.99').strip()

    if not domain or not forward_host or not forward_port:
        return jsonify({'error': 'domain, forward_host, and forward_port required'}), 400

    npm._auth()
    if npm.domain_exists(domain):
        return jsonify({'error': f'Domain {domain} already exists in NPM'}), 409

    # Internal: create DNS entry. External: skip (uses public DNS)
    if fqdn_type == 'internal':
        pihole._auth()
        if not pihole.add_host(dns_ip, domain):
            return jsonify({'error': 'Failed to create DNS entry'}), 500

    cert_id = 0
    if fqdn_type == 'external':
        count, can_request = check_rate_limit(domain)
        if not can_request:
            return jsonify({'error': f'LE rate limit reached ({count}/50 this week)'}), 429
        cert = npm.request_le_cert(domain)
        if cert and 'id' in cert:
            cert_id = cert['id']
            record_cert_request(domain)

    result = npm.create_proxy_host(domain, forward_host, forward_port,
                                   ssl=(cert_id > 0), cert_id=cert_id, force_ssl=force_ssl)
    if result:
        return jsonify({'success': True, 'domain': domain, 'proxy_id': result.get('id')}), 201
    return jsonify({'error': 'Failed to create proxy host'}), 500


@app.route('/api/fqdns/<domain>', methods=['DELETE'])
@api_key_required
def api_delete_fqdn(domain):
    pihole._auth()
    npm._auth()

    proxy_hosts = npm.get_proxy_hosts()
    for h in proxy_hosts:
        if domain in h.get('domain_names', []):
            npm.delete_proxy_host(h['id'])
            break

    dns_hosts = pihole.get_hosts()
    for entry in dns_hosts:
        parts = entry.split(' ', 1)
        if len(parts) == 2 and parts[1] == domain:
            pihole.delete_host(parts[0], domain)
            break

    return jsonify({'success': True, 'deleted': domain})


if __name__ == '__main__':
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=os.environ.get('DEBUG', False))
