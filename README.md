***

# 🛡️ Entra Helpdesk Portal (Community Edition)

**A Zero-Trust, containerized IT Service Management (ITSM) portal for Microsoft Entra ID.**

The Entra Helpdesk Portal is designed to solve a critical enterprise security challenge: **Keeping Tier 1 and Tier 2 support staff out of the Azure/Entra Admin Portals.** By leveraging a highly-scoped backend Service Principal and a clean, Material Design web interface, this portal allows helpdesk workers to perform daily identity tasks (password resets, MFA clearing, group management) while limiting their blast radius. Every action is strictly logged to a local database and requires a mandatory ITSM Ticket Number.

---

## ✨ Key Features

### 🔐 Zero Trust & Security First
* **Whitelist Authorization:** Authentication is handled via Microsoft SSO, but authorization is strictly controlled by an `ALLOWED_ADMINS` environment variable. Even if a user exists in your tenant, they cannot access the portal unless explicitly whitelisted.
* **Mandatory ITSM Ticketing:** No write action (Create, Delete, Reset, Rotate) can be executed without the technician entering a valid Ticket Number (e.g., INC-123456).
* **Local Audit Database:** Every action is permanently logged to an internal SQLite database tracking the Timestamp, Admin UPN, Ticket Number, Action, Target, and Success/Failure status.

### 📊 Telemetry Dashboard
* **Live Sign-In Analytics:** The default landing page aggregates the last 100 Entra ID sign-in events, displaying Total Logins, Failed Attempts, and a breakdown of Client Operating Systems.

### 🧑‍💻 User Management
* **Create Users:** Automatically detects verified tenant domains for a drop-down selection. Generates secure, 16-character temporary passwords automatically.
* **Secure Credential Handoff:** Instantly displays new credentials or rotated secrets with one-click "Copy" and "Export to CSV" buttons.
* **Reset Passwords:** Generates a new secure password and forces the user to change it on their next login.
* **Revoke Sessions:** The ultimate panic button to instantly invalidate all refresh tokens and sign-in sessions for a compromised user.
* **Sign-In Diagnostics:** Troubleshoot lockouts by viewing a user's last 5 sign-in attempts, including location, IP, and the exact Azure failure reason.
* **MFA Manager:** View a user's registered authentication methods (Authenticator App, Phone, FIDO2) and delete specific methods to force re-registration.

### 🏢 Group Management
* **Create Groups:** Provision both Security and Microsoft 365 groups directly from the UI.
* **Membership Manager:** View all current members of a group, seamlessly remove them, or add new members by pasting their Object ID.

### ⚙️ Enterprise Applications (SPNs)
* **View Applications:** See all App Registrations and Enterprise Apps in the tenant.
* **Lazy-Load Permissions:** Click the policy shield icon to dynamically fetch and view the raw `requiredResourceAccess` JSON payload to audit an app's API permissions.
* **Rotate Secrets:** Instantly generate a new Client Secret for an application.

### ♻️ Backup & Recovery
* **CSV Tenant Backup:** One-click export of all users in the tenant to a CSV file.
* **Universal Restore:** A dedicated Recycle Bin tab that allows you to paste the Object ID of *any* soft-deleted User, Group, or Application and restore it instantly.

### 🎨 UI/UX & Customization
* **System-Aware Dark Mode:** Automatically switches between Light and Dark themes based on the user's OS or browser preferences.
* **White-Labeling:** Upload your own company logo directly from the UI Settings tab.
* **Feature Flags:** Completely customize the portal via `docker-compose.yml`. Disable User Deletion, Password Resets, or entire modules (like Apps or Groups) to fit your organization's exact delegation model.

---

## 📋 Prerequisites: Microsoft Graph API Scopes

To run this container, you must create an App Registration in your Entra ID tenant and grant it the following **Application Permissions** (Admin Consent Required):

* `User.ReadWrite.All` (User management & passwords)
* `Group.ReadWrite.All` (Group & member management)
* `Application.ReadWrite.All` (App viewing & secret rotation)
* `UserAuthenticationMethod.ReadWrite.All` (MFA management)
* `AuditLog.Read.All` (Sign-in diagnostics and telemetry)
* `Domain.Read.All` (Fetching tenant domains)

*Note: You must also configure a **Web Redirect URI** in the App Registration pointing to your deployment URL (e.g., `https://helpdesk.yourdomain.com/getAToken`).*

---

## 🚀 Quick Start Deployment

This portal is packaged as a lightweight, multi-architecture Docker container (compatible with x86_64 and ARM64 devices like Raspberry Pi).

Create a `docker-compose.yml` file and populate it with your tenant details:

```yaml
version: '3.8'

services:
  helpdesk-portal:
    image: yourdockerhubname/entra-helpdesk:latest
    container_name: entra_helpdesk
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      # --- CORE IDENTITY ---
      - TENANT_ID=your_tenant_guid
      - CLIENT_ID=your_app_registration_guid
      - CLIENT_SECRET=your_app_secret_value
      - BASE_URL=https://helpdesk.yourdomain.com
      
      # --- SECURITY ---
      # Comma-separated list of UPNs allowed to log into the portal
      - ALLOWED_ADMINS=admin@yourdomain.com,tier1@yourdomain.com
      
      # --- WHITE-LABEL & FEATURE FLAGS ---
      - APP_NAME=Contoso IT Helpdesk
      - ENABLE_PASSWORD_RESET=true
      - ENABLE_MFA_MANAGEMENT=true
      - ENABLE_USER_DELETION=false      # Prevents UI/API from deleting users
      - ENABLE_GROUP_MANAGEMENT=true
      - ENABLE_APP_MANAGEMENT=true

    volumes:
      - helpdesk_data:/app/static/uploads
      - helpdesk_db:/app  # Persists the SQLite Audit Database

volumes:
  helpdesk_data:
  helpdesk_db:
```

Bring up the portal:
```bash
docker compose up -d
```

## 🏗️ Architecture

* **Backend:** Python 3.11, Flask, MSAL (Microsoft Authentication Library), SQLite.
* **Frontend:** HTML5, Materialize CSS framework, Vanilla JavaScript (ES6+).
* **Performance:** Implements an in-memory TTL caching layer for heavy Graph API read operations, ensuring lightning-fast UI navigation with smart cache invalidation on write operations.
