import os, msal, requests, logging, sqlite3, string, secrets, csv, time
from io import StringIO
from flask import Flask, jsonify, render_template, session, redirect, url_for, request, Response
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s | AUDIT | %(message)s')
logger = logging.getLogger(__name__)

os.makedirs('static/uploads', exist_ok=True)

def init_db():
    conn = sqlite3.connect('audit.db'); c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, admin_user TEXT, ticket TEXT, action TEXT, target TEXT, status TEXT)''')
    conn.commit(); conn.close()

init_db()
app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- ENVIRONMENT VARIABLES & FEATURE FLAGS ---
TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
ALLOWED_ADMINS = [email.strip().lower() for email in os.getenv("ALLOWED_ADMINS", "").split(",") if email.strip()]
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
REDIRECT_URI = f"{BASE_URL}/getAToken"

APP_CONFIG = {
    "APP_NAME": os.getenv("APP_NAME", "Entra Help Desk"),
    "ENABLE_PASSWORD_RESET": os.getenv("ENABLE_PASSWORD_RESET", "true").lower() == "true",
    "ENABLE_MFA_MANAGEMENT": os.getenv("ENABLE_MFA_MANAGEMENT", "true").lower() == "true",
    "ENABLE_USER_DELETION": os.getenv("ENABLE_USER_DELETION", "true").lower() == "true",
    "ENABLE_GROUP_MANAGEMENT": os.getenv("ENABLE_GROUP_MANAGEMENT", "true").lower() == "true",
    "ENABLE_APP_MANAGEMENT": os.getenv("ENABLE_APP_MANAGEMENT", "true").lower() == "true"
}

msal_app = msal.ConfidentialClientApplication(CLIENT_ID, authority=AUTHORITY, client_credential=CLIENT_SECRET)

def get_graph_token():
    result = msal_app.acquire_token_silent(["https://graph.microsoft.com/.default"], account=None)
    if not result: result = msal_app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    return result.get("access_token")

API_CACHE = {}; CACHE_TTL = 60

def fetch_with_cache(cache_key, url):
    now = time.time()
    if request.args.get('refresh') != 'true' and cache_key in API_CACHE and (now - API_CACHE[cache_key]['time']) < CACHE_TTL:
        return API_CACHE[cache_key]['data']
    try:
        res = requests.get(url, headers={'Authorization': f'Bearer {get_graph_token()}', 'ConsistencyLevel': 'eventual'})
        data = res.json()
        if res.status_code == 200:
            API_CACHE[cache_key] = {'time': now, 'data': data}
            return API_CACHE[cache_key]['data']
        return data 
    except Exception as e:
        logger.error(f"Fetch Error: {str(e)}")
        return {"error": {"message": f"Backend Error: {str(e)}"}}

def invalidate_cache(key):
    if key in API_CACHE: del API_CACHE[key]
    if 'telemetry' in API_CACHE: del API_CACHE['telemetry']

def log_action(action, target, status):
    user = session.get("user", {}).get("preferred_username", "Unknown")
    ticket = request.headers.get("X-Ticket-Number", "NO_TICKET_PROVIDED")
    logger.info(f"User: {user} | Ticket: {ticket} | Action: {action} | Target: {target} | Status: {status}")
    conn = sqlite3.connect('audit.db'); c = conn.cursor()
    c.execute("INSERT INTO audit_logs (admin_user, ticket, action, target, status) VALUES (?, ?, ?, ?, ?)", (user, ticket, action, target, status))
    conn.commit(); conn.close()

def generate_password(): return ''.join(secrets.choice(string.ascii_letters + string.digits + "!@#$%^&*") for i in range(16))

# --- AUTH ROUTES ---
@app.route("/login")
def login(): return redirect(msal_app.get_authorization_request_url(["User.Read"], state=os.urandom(16).hex(), redirect_uri=REDIRECT_URI))

@app.route("/getAToken")
def authorized():
    result = msal_app.acquire_token_by_authorization_code(request.args.get("code"), scopes=["User.Read"], redirect_uri=REDIRECT_URI)
    if "id_token_claims" in result:
        user_upn = result.get("id_token_claims", {}).get("preferred_username", "").lower()
        if ALLOWED_ADMINS and user_upn not in ALLOWED_ADMINS:
            return f"<h1>Access Denied</h1><p>Your account ({user_upn}) is not authorized.</p>", 403
        session["user"] = result.get("id_token_claims"); return redirect(url_for("home"))
    return "Authentication Failed."

@app.route("/logout")
def logout(): session.clear(); return redirect(f"{AUTHORITY}/oauth2/v2.0/logout?post_logout_redirect_uri={BASE_URL}")

# --- CACHED READ ROUTES ---
@app.route('/api/telemetry', methods=['GET'])
def get_telemetry():
    if not session.get("user"): return jsonify({"error": "Unauthorized"}), 401
    res_data = fetch_with_cache('telemetry', "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=100")
    if 'error' in res_data: return jsonify(res_data), 400
    data = res_data.get('value', []); total = len(data)
    failed = sum(1 for d in data if d.get('status', {}).get('errorCode', 0) != 0)
    os_counts = {}
    for d in data:
        os_name = d.get('deviceDetail', {}).get('operatingSystem', 'Unknown')
        os_counts[os_name] = os_counts.get(os_name, 0) + 1
    return jsonify({"total": total, "success": total - failed, "failed": failed, "os_counts": os_counts})

@app.route('/api/search', methods=['GET'])
def global_search():
    if not session.get("user"): return jsonify({"error": "Unauthorized"}), 401
    q = request.args.get('q', '').replace("'", "''"); target = request.args.get('target', 'users')
    filter_query = f"startswith(displayName,'{q}') or id eq '{q}'"
    if target == 'users': filter_query += f" or startswith(userPrincipalName,'{q}')"
    elif target == 'applications': filter_query += f" or appId eq '{q}'"
    res = requests.get(f"https://graph.microsoft.com/v1.0/{target}?$filter={filter_query}&$count=true", headers={'Authorization': f'Bearer {get_graph_token()}', 'ConsistencyLevel': 'eventual'})
    return jsonify(res.json())

@app.route('/api/domains', methods=['GET'])
def list_domains():
    if not session.get("user"): return jsonify({"error": "Unauthorized"}), 401
    data = fetch_with_cache('domains', 'https://graph.microsoft.com/v1.0/domains')
    if 'error' in data: return jsonify([d['id'] for d in data.get('value', []) if d.get('isVerified')])
    return jsonify([d['id'] for d in data.get('value', []) if d.get('isVerified')])

@app.route('/api/users', methods=['GET'])
def list_users():
    if not session.get("user"): return jsonify({"error": "Unauthorized"}), 401
    return jsonify(fetch_with_cache('users', 'https://graph.microsoft.com/v1.0/users?$top=30&$select=id,displayName,userPrincipalName,accountEnabled'))

@app.route('/api/groups', methods=['GET'])
def list_groups():
    if not session.get("user"): return jsonify({"error": "Unauthorized"}), 401
    if not APP_CONFIG["ENABLE_GROUP_MANAGEMENT"]: return jsonify({"error": "Feature Disabled"}), 403
    return jsonify(fetch_with_cache('groups', 'https://graph.microsoft.com/v1.0/groups?$top=30&$select=id,displayName,description,securityEnabled'))

@app.route('/api/applications', methods=['GET'])
def list_applications():
    if not session.get("user"): return jsonify({"error": "Unauthorized"}), 401
    if not APP_CONFIG["ENABLE_APP_MANAGEMENT"]: return jsonify({"error": "Feature Disabled"}), 403
    return jsonify(fetch_with_cache('apps', 'https://graph.microsoft.com/v1.0/applications?$top=30&$select=id,displayName,appId'))

@app.route('/api/recyclebin/apps', methods=['GET'])
def list_deleted_apps():
    if not session.get("user"): return jsonify({"error": "Unauthorized"}), 401
    if not APP_CONFIG["ENABLE_APP_MANAGEMENT"]: return jsonify({"error": "Feature Disabled"}), 403
    return jsonify(fetch_with_cache('recycle', 'https://graph.microsoft.com/v1.0/directory/deletedItems/microsoft.graph.application'))

@app.route('/api/users/<user_id>/diagnostics', methods=['GET'])
def user_diagnostics(user_id):
    if not session.get("user"): return jsonify({"error": "Unauthorized"}), 401
    res = requests.get(f"https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=userId eq '{user_id}'&$top=5", headers={'Authorization': f'Bearer {get_graph_token()}'})
    return jsonify(res.json())

@app.route('/api/users/<user_id>/mfa', methods=['GET'])
def get_user_mfa(user_id):
    if not session.get("user"): return jsonify({"error": "Unauthorized"}), 401
    if not APP_CONFIG["ENABLE_MFA_MANAGEMENT"]: return jsonify({"error": {"message": "MFA Management is disabled by your administrator."}}), 403
    res = requests.get(f'https://graph.microsoft.com/beta/users/{user_id}/authentication/methods', headers={'Authorization': f'Bearer {get_graph_token()}'})
    return jsonify(res.json())

@app.route('/api/groups/<group_id>/members', methods=['GET'])
def get_group_members(group_id):
    if not session.get("user"): return jsonify({"error": "Unauthorized"}), 401
    res = requests.get(f'https://graph.microsoft.com/v1.0/groups/{group_id}/members?$select=id,displayName,userPrincipalName', headers={'Authorization': f'Bearer {get_graph_token()}'})
    return jsonify(res.json())

@app.route('/api/applications/<app_id>/permissions', methods=['GET'])
def get_app_permissions(app_id):
    if not session.get("user"): return jsonify({"error": "Unauthorized"}), 401
    res = requests.get(f'https://graph.microsoft.com/v1.0/applications/{app_id}?$select=requiredResourceAccess', headers={'Authorization': f'Bearer {get_graph_token()}'})
    return jsonify(res.json().get('requiredResourceAccess', []))

@app.route('/api/audit', methods=['GET'])
def get_audit_logs():
    if not session.get("user"): return jsonify({"error": "Unauthorized"}), 401
    conn = sqlite3.connect('audit.db'); conn.row_factory = sqlite3.Row
    logs = conn.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 50").fetchall()
    conn.close(); return jsonify([dict(row) for row in logs])

# --- SETTINGS & BACKUPS ---
@app.route('/api/logo', methods=['POST'])
def upload_logo():
    if not session.get("user"): return jsonify({"error": "Unauthorized"}), 401
    if 'logo' in request.files: request.files['logo'].save('static/uploads/company_logo.png')
    log_action("UPDATE_LOGO", "UI Settings", "SUCCESS")
    return jsonify({"success": True})

@app.route('/api/backup/users', methods=['GET'])
def backup_users():
    if not session.get("user"): return jsonify({"error": "Unauthorized"}), 401
    res = requests.get('https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled', headers={'Authorization': f'Bearer {get_graph_token()}'})
    users = res.json().get('value', [])
    si = StringIO(); writer = csv.writer(si)
    writer.writerow(['Object ID', 'Display Name', 'User Principal Name', 'Account Enabled'])
    for u in users: writer.writerow([u.get('id'), u.get('displayName'), u.get('userPrincipalName'), u.get('accountEnabled')])
    output = Response(si.getvalue(), mimetype='text/csv')
    output.headers["Content-Disposition"] = f"attachment; filename=entra_users_backup_{datetime.now().strftime('%Y%m%d')}.csv"
    log_action("EXPORT_USERS", "Full Tenant Backup", "SUCCESS")
    return output

# --- FEATURE FLAGGED WRITE ROUTES ---
@app.route('/api/users', methods=['POST'])
def create_user():
    if not session.get("user"): return jsonify({"error": "Unauthorized"}), 401
    data = request.json; temp_pass = generate_password()
    payload = {"accountEnabled": True, "displayName": data.get('displayName'), "mailNickname": data.get('mailNickname'), "userPrincipalName": data.get('upn'), "passwordProfile": {"forceChangePasswordNextSignIn": True, "password": temp_pass}}
    res = requests.post('https://graph.microsoft.com/v1.0/users', json=payload, headers={'Authorization': f'Bearer {get_graph_token()}', 'Content-Type': 'application/json'})
    log_action("CREATE_USER", data.get('upn'), "SUCCESS" if res.status_code == 201 else f"FAILED: {res.text}")
    if res.status_code == 201: invalidate_cache('users'); return jsonify({"success": True, "password": temp_pass})
    return jsonify({"error": res.text}), res.status_code

@app.route('/api/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    if not session.get("user"): return jsonify({"error": "Unauthorized"}), 401
    if not APP_CONFIG["ENABLE_USER_DELETION"]: return jsonify({"error": "User deletion is disabled"}), 403
    res = requests.delete(f'https://graph.microsoft.com/v1.0/users/{user_id}', headers={'Authorization': f'Bearer {get_graph_token()}'})
    log_action("DELETE_USER", user_id, "SUCCESS" if res.status_code == 204 else f"FAILED")
    if res.status_code == 204: invalidate_cache('users')
    return jsonify({"success": True}) if res.status_code == 204 else (jsonify({"error": res.text}), res.status_code)

@app.route('/api/users/<user_id>/reset-password', methods=['POST'])
def reset_password(user_id):
    if not session.get("user"): return jsonify({"error": "Unauthorized"}), 401
    if not APP_CONFIG["ENABLE_PASSWORD_RESET"]: return jsonify({"error": "Password resets are disabled"}), 403
    temp_pass = generate_password()
    res = requests.patch(f'https://graph.microsoft.com/v1.0/users/{user_id}', json={"passwordProfile": {"forceChangePasswordNextSignIn": True, "password": temp_pass}}, headers={'Authorization': f'Bearer {get_graph_token()}', 'Content-Type': 'application/json'})
    log_action("RESET_PASSWORD", user_id, "SUCCESS" if res.status_code == 204 else f"FAILED: {res.text}")
    if res.status_code == 204: return jsonify({"success": True, "password": temp_pass})
    return jsonify({"error": res.text}), res.status_code

@app.route('/api/users/<user_id>/revoke-sessions', methods=['POST'])
def revoke_sessions(user_id):
    if not session.get("user"): return jsonify({"error": "Unauthorized"}), 401
    res = requests.post(f'https://graph.microsoft.com/v1.0/users/{user_id}/revokeSignInSessions', headers={'Authorization': f'Bearer {get_graph_token()}'})
    log_action("REVOKE_SESSIONS", user_id, "SUCCESS" if res.status_code == 200 else f"FAILED")
    return jsonify({"success": True}) if res.status_code == 200 else (jsonify({"error": res.text}), res.status_code)

@app.route('/api/users/<user_id>/mfa/<method_id>', methods=['DELETE'])
def delete_user_mfa(user_id, method_id):
    if not session.get("user"): return jsonify({"error": "Unauthorized"}), 401
    if not APP_CONFIG["ENABLE_MFA_MANAGEMENT"]: return jsonify({"error": "MFA management is disabled"}), 403
    res = requests.delete(f'https://graph.microsoft.com/beta/users/{user_id}/authentication/methods/{method_id}', headers={'Authorization': f'Bearer {get_graph_token()}'})
    log_action("DELETE_MFA_METHOD", f"User:{user_id} Method:{method_id}", "SUCCESS" if res.status_code == 204 else f"FAILED")
    return jsonify({"success": True}) if res.status_code == 204 else (jsonify({"error": res.text}), res.status_code)

@app.route('/api/groups', methods=['POST'])
def create_group():
    if not session.get("user") or not APP_CONFIG["ENABLE_GROUP_MANAGEMENT"]: return jsonify({"error": "Unauthorized or Disabled"}), 403
    data = request.json
    payload = {"description": data.get('description'), "displayName": data.get('displayName'), "groupTypes": ["Unified"] if data.get('isM365') else [], "mailEnabled": bool(data.get('isM365')), "mailNickname": data.get('displayName', '').replace(" ", "").lower(), "securityEnabled": not bool(data.get('isM365'))}
    res = requests.post('https://graph.microsoft.com/v1.0/groups', json=payload, headers={'Authorization': f'Bearer {get_graph_token()}', 'Content-Type': 'application/json'})
    log_action("CREATE_GROUP", data.get('displayName'), "SUCCESS" if res.status_code == 201 else f"FAILED")
    if res.status_code == 201: invalidate_cache('groups')
    return jsonify({"success": True}) if res.status_code == 201 else (jsonify({"error": res.text}), res.status_code)

@app.route('/api/groups/<group_id>', methods=['DELETE'])
def delete_group(group_id):
    if not session.get("user") or not APP_CONFIG["ENABLE_GROUP_MANAGEMENT"]: return jsonify({"error": "Unauthorized or Disabled"}), 403
    res = requests.delete(f'https://graph.microsoft.com/v1.0/groups/{group_id}', headers={'Authorization': f'Bearer {get_graph_token()}'})
    log_action("DELETE_GROUP", group_id, "SUCCESS" if res.status_code == 204 else f"FAILED")
    if res.status_code == 204: invalidate_cache('groups')
    return jsonify({"success": True}) if res.status_code == 204 else (jsonify({"error": res.text}), res.status_code)

@app.route('/api/groups/<group_id>/members', methods=['POST'])
def add_group_member(group_id):
    if not session.get("user") or not APP_CONFIG["ENABLE_GROUP_MANAGEMENT"]: return jsonify({"error": "Unauthorized or Disabled"}), 403
    user_id = request.json.get("userId")
    res = requests.post(f'https://graph.microsoft.com/v1.0/groups/{group_id}/members/$ref', json={"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"}, headers={'Authorization': f'Bearer {get_graph_token()}', 'Content-Type': 'application/json'})
    log_action("ADD_GROUP_MEMBER", f"User:{user_id} -> Group:{group_id}", "SUCCESS" if res.status_code == 204 else f"FAILED")
    return jsonify({"success": True}) if res.status_code == 204 else (jsonify({"error": res.text}), res.status_code)

@app.route('/api/groups/<group_id>/members/<user_id>', methods=['DELETE'])
def remove_group_member(group_id, user_id):
    if not session.get("user") or not APP_CONFIG["ENABLE_GROUP_MANAGEMENT"]: return jsonify({"error": "Unauthorized or Disabled"}), 403
    res = requests.delete(f'https://graph.microsoft.com/v1.0/groups/{group_id}/members/{user_id}/$ref', headers={'Authorization': f'Bearer {get_graph_token()}'})
    log_action("REMOVE_GROUP_MEMBER", f"User:{user_id} -> Group:{group_id}", "SUCCESS" if res.status_code == 204 else f"FAILED")
    return jsonify({"success": True}) if res.status_code == 204 else (jsonify({"error": res.text}), res.status_code)

@app.route('/api/applications/<app_id>/rotate-secret', methods=['POST'])
def rotate_app_secret(app_id):
    if not session.get("user") or not APP_CONFIG["ENABLE_APP_MANAGEMENT"]: return jsonify({"error": "Unauthorized or Disabled"}), 403
    res = requests.post(f'https://graph.microsoft.com/v1.0/applications/{app_id}/addPassword', json={"passwordCredential": {"displayName": f"Helpdesk_Rotated_{datetime.now().strftime('%Y%m%d')}"}}, headers={'Authorization': f'Bearer {get_graph_token()}', 'Content-Type': 'application/json'})
    log_action("ROTATE_APP_SECRET", app_id, "SUCCESS" if res.status_code == 200 else f"FAILED")
    return jsonify({"success": True, "secretText": res.json()['secretText']}) if res.status_code == 200 else (jsonify({"error": res.text}), res.status_code)

@app.route('/api/recyclebin/restore', methods=['POST'])
def universal_restore():
    if not session.get("user"): return jsonify({"error": "Unauthorized"}), 401
    obj_id = request.json.get("objectId")
    res = requests.post(f'https://graph.microsoft.com/v1.0/directory/deletedItems/{obj_id}/restore', headers={'Authorization': f'Bearer {get_graph_token()}'})
    log_action("RESTORE_OBJECT", obj_id, "SUCCESS" if res.status_code == 200 else f"FAILED")
    if res.status_code == 200:
        invalidate_cache('users'); invalidate_cache('groups'); invalidate_cache('apps'); invalidate_cache('recycle')
    return jsonify({"success": True}) if res.status_code == 200 else (jsonify({"error": res.text}), res.status_code)

@app.route('/')
def home():
    if not session.get("user"): return redirect(url_for("login"))
    # Pass the config object to the frontend template
    return render_template('index.html', user=session["user"], config=APP_CONFIG)

if __name__ == '__main__': app.run(host='0.0.0.0', port=8000)
