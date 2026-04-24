# 🏰 Throne Guard — Admin is not God

[![License](https://img.shields.io/badge/License-AGPLv3-green?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.5.1-brightgreen?style=for-the-badge)](#)
[![Platform](https://img.shields.io/badge/Platform-WordPress-21759B?style=for-the-badge&logo=wordpress)](#)
[![Architecture](https://img.shields.io/badge/Architecture-Zero--Trust-red?style=for-the-badge)](#)
[![PHP](https://img.shields.io/badge/PHP-8.1+-777BB4?style=for-the-badge&logo=php)](#)
[![Status](https://img.shields.io/badge/Status-STABLE-brightgreen?style=for-the-badge)](#)
[![VGT](https://img.shields.io/badge/VGT-VisionGaia_Technology-red?style=for-the-badge)](https://visiongaiatechnology.de)

> *"Administrator is a role, not a throne."*
> *AGPLv3+ — Open Source. Built for sites that will be compromised eventually.*

---

## ⚠️ DISCLAIMER: EXPERIMENTAL R&D PROJECT

This project is a **Proof of Concept (PoC)** and part of ongoing research and development at VisionGaia Technology. It is **not** a certified or production-ready product.

**Use at your own risk.** The software may contain security vulnerabilities, bugs, or unexpected behavior. It may break your environment if misconfigured or used improperly.

**Do not deploy in critical production environments** without thorough code review. Throne Guard modifies WordPress capability assignments — if you lock yourself out of the Master role without recording your Superkey, recovery requires direct database access.

Found a vulnerability or have an improvement? **Open an issue or contact us.**

---

## 📋 Changelog — V2.5.1

- **Pre-Flight WAF:** Scoped to admin and MCP routes only — no more collateral damage in frontend uploads
- **Upload Jail:** `.htaccess` now uses append-with-markers instead of overwrite — preserves existing custom rules (CDN, WebP, rewrites)
- **Session Gating:** Ephemeral server-side token validation with strict `hash_equals` comparison — immune to client-side cookie manipulation
- **Exception Hierarchy:** `ValidationException` / `SecurityException` / `StorageException` with asymmetric client/log messaging — users never see internal details
- **CSRF Tokens:** Single-use `bin2hex(random_bytes(32))` tokens on top of WordPress nonces for all state-changing operations

---

<img width="2816" height="1536" alt="Gemini_Generated_Image_i5yze3i5yze3i5yz" src="https://github.com/user-attachments/assets/2960ced5-f61a-4831-87cb-3d0825d2cf76" />



## 🔍 What is Throne Guard?

Throne Guard is a **WordPress hardening plugin that removes the most dangerous capabilities from the Administrator role** and places them behind a separate Master role gated by a Superkey.

It is built on a single premise: **in 9 out of 10 WordPress compromises, the attacker ends up with Administrator access.** Vulnerable plugins, phished passwords, stolen session cookies — the Administrator account is the pivot point of almost every real-world WordPress hack.

Throne Guard assumes the Administrator **will** be compromised and makes sure that even then, the attacker cannot install plugins, switch themes, create users, or deactivate Throne Guard itself.

```
Traditional WordPress Hardening:
→ 2FA on admin login                   — prevents credential theft
→ Login rate limiting                  — slows brute force
→ IP whitelisting                      — limits attack surface
→ Still: Admin compromise = full site compromise

Throne Guard Approach:
→ Admin ≠ God                          — strip toxic capabilities
→ Separate Master role                 — elevated functions isolated
→ Superkey gate                        — bcrypt-hashed, never in session
→ Plugin stealth                       — Throne Guard invisible to Admins
→ Deactivation guard                   — cannot be disabled without Master
```

---



## 🏛️ Architecture

```
Incoming Admin Request
        ↓
Pre-Flight WAF (Upload Inspection)
→ Toxic extensions (.php, .phar, .phtml, .pht...) blocked at MS 0
→ Scoped to admin routes — zero frontend collateral damage
→ Double-extension detection (shell.phar.jpg)
        ↓
Backend Lock (Zero-Trust Session Gating)
→ Master-capability check
→ Ephemeral token + server-side meta validation
→ 2-hour expiration enforced server-side
→ AJAX routes gated separately (no bypass)
        ↓
CSRF + Nonce Double Layer
→ WordPress nonce (action-scoped)
→ Single-use CSRF token from user meta
→ Both required for all state changes
        ↓
Capability Enforcement
→ Administrator: stripped of toxic capabilities
→ Master: full control, gated by Superkey
→ editable_roles filter: non-Masters cannot promote to Master
→ all_plugins filter: Throne Guard invisible to non-Masters
        ↓
Upload Jail (Auto-Healed)
→ wp-content/uploads/.htaccess maintained on every dashboard load
→ Append-with-markers — preserves existing custom rules
→ PHP execution disabled at webserver level
        ↓
Secure Vault Upload
→ MIME + magic byte + IMAGETYPE triple-check
→ GD re-encoding — all metadata and payloads stripped
→ 0600 permissions + 0700 directory + realpath jail
→ Cryptographically random filenames
```

---

## 🧩 Module Matrix

### ☢️ Admin Neutering

Strips toxic capabilities from the Administrator role. Configurable via dashboard, enforced at WordPress capability level. Requires Superkey confirmation for every change.

<img width="1733" height="855" alt="{82C71EAF-A3BC-4455-B70B-599A1EDA1916}" src="https://github.com/user-attachments/assets/0ec0e5f4-5353-4877-85b3-2f6f2b49d198" />




| Capability | Risk if Retained | Default |
|---|---|---|
| `activate_plugins` | Install backdoor plugins | Stripped |
| `delete_plugins` | Remove security plugins | Stripped |
| `install_plugins` | Upload malicious plugins | Stripped |
| `edit_plugins` | Inject code into existing plugins | Stripped |
| `update_plugins` | Downgrade to vulnerable versions | Stripped |
| `switch_themes` | Activate malicious themes | Stripped |
| `edit_themes` | Inject code into themes | Stripped |
| `install_themes` | Upload malicious themes | Stripped |
| `delete_themes` | Remove legitimate themes | Stripped |
| `update_themes` | Downgrade to vulnerable versions | Stripped |
| `edit_users` | Change other users' passwords/roles | Stripped |
| `delete_users` | Remove legitimate admins | Stripped |
| `create_users` | Create persistent backdoor accounts | Stripped |
| `promote_users` | Elevate accounts to admin | Stripped |

All capabilities are re-assignable to Administrator via the dashboard, provided the Superkey is presented.

---

### 🔐 Superkey Gate

Zero-trust session gating for the Master role.

<img width="1350" height="770" alt="{FD971F9E-66CA-48D2-B3A0-CEFB158648D1}" src="https://github.com/user-attachments/assets/e34d60f9-e08c-4257-a36b-4c64b4a76c18" />


| Feature | Detail |
|---|---|
| **Storage** | `password_hash()` with `PASSWORD_DEFAULT` (bcrypt) |
| **Verification** | `password_verify()` — timing-safe |
| **Minimum Length** | 12 characters |
| **Session Token** | Ephemeral: `expiration\|bin2hex(random_bytes(32))` |
| **Server Binding** | Identical string stored in user meta and cookie — client-side manipulation immediately detectable |
| **Validation** | `hash_equals()` strict comparison — timing-attack resistant |
| **Expiration** | 2 hours, server-side enforced via meta timestamp |
| **Cookie Flags** | `httponly`, `secure`, `samesite=Strict` |
| **Cleanup** | Session meta auto-deleted on `clear_auth_cookie` hook |
| **Anti-Bruteforce** | `sleep(2)` penalty on failed Superkey attempts |

**Recovery if Superkey is lost:**
```sql
DELETE FROM wp_options WHERE option_name = 'mcp_superkey_hash';
```
Direct database access required. No email recovery, no security questions. By design.

---

### 🚪 Pre-Flight WAF

Intercepts toxic file uploads before WordPress processes them.

| Feature | Detail |
|---|---|
| **Scope** | `is_admin()` or MCP action routes only — no frontend impact |
| **Detection** | Extension allowlist + regex double-extension check |
| **Blocked Extensions** | `.php`, `.phtml`, `.phar`, `.shtml`, `.php3`–`.php8`, `.pht`, `.cgi`, `.pl`, `.asp`, `.aspx`, `.jsp` |
| **Double-Extension** | `shell.phar.jpg` — blocked via regex pattern against any toxic extension in the filename |
| **Response** | HTTP 403 + immediate `die()` — no WordPress processing whatsoever |
| **Logging** | All interceptions written to `error_log` with filename |

---

### 🏗️ Upload Jail

Auto-maintained `.htaccess` in `wp-content/uploads/` to disable PHP execution at the webserver level.

```apache
# BEGIN VGT REDTEAM
<FilesMatch "\.(?i:php|phtml|phar|shtml|php3|php4|php5|pht|cgi|pl|asp|aspx|jsp)">
    Require all denied
    Order allow,deny
    Deny from all
</FilesMatch>
<IfModule mod_php.c>
    php_flag engine off
</IfModule>
<IfModule mod_php7.c>
    php_flag engine off
</IfModule>
<IfModule mod_php8.c>
    php_flag engine off
</IfModule>
# END VGT REDTEAM
```

**Self-healing:** Re-applied on every dashboard load if markers are missing or tampered with.
**Coexistence:** Appended using `# BEGIN` / `# END` markers — preserves existing custom rules (CDN, WebP, redirects).
**Nginx/Caddy fallback:** `index.php` injected into vault directory to prevent directory listing.

---

### 🔒 Secure Vault Upload

Jailed, re-encoded image uploads with aggressive payload stripping. Accessible only to Master users.

| Stage | Check |
|---|---|
| **1. MIME Check** | `finfo` binary inspection |
| **2. Magic Byte Check** | `getimagesize()` type verification |
| **3. Cross-Validation** | MIME type ↔ `IMAGETYPE_*` constant match — polyglot vectors blocked |
| **4. Memory Budget** | Pre-calculated image memory requirement vs. PHP `memory_limit` |
| **5. Re-Encoding** | GD `imagecreatefrom*` → `image*()` — all EXIF metadata and embedded payloads stripped |
| **6. Filesystem Jail** | `realpath` validation, 0700 directory, 0600 file permissions |
| **7. Filename** | `bin2hex(random_bytes(16))` — original filename discarded entirely |

**Allowed formats:** JPEG, PNG, WebP, GIF
**Max file size:** 5MB

---

### 🛡️ Plugin Stealth & Deactivation Guard

Throne Guard actively conceals itself from unauthorized users:

- **Invisible to Administrators:** `all_plugins` filter removes Throne Guard from the plugin list for any user without `mcp_master_access`
- **Deactivation blocked:** The `deactivate_plugin` hook fires `wp_die()` with HTTP 403 for unauthorized deactivation attempts
- **Role hidden:** The Master role is not visible in user edit forms for non-Master users via `editable_roles` filter

An attacker with full Administrator access sees a WordPress installation with no Throne Guard present. They cannot deactivate what they cannot see.

---

### 🔑 CSRF + Nonce Double Layer

Every state-changing operation requires both:

1. **WordPress nonce** — action-scoped, time-limited (`wp_verify_nonce`)
2. **CSRF token** — `bin2hex(random_bytes(32))` stored in user meta, single-use, consumed on verify via `delete_user_meta`

Both must validate. The CSRF token is deleted after a single successful verification — replay is impossible even within the nonce's validity window.

---

### 🔖 CSP Headers

Strict `Content-Security-Policy` with per-request nonces injected on the **frontend only** (admin backend is exempt to avoid breaking WordPress core inline scripts):

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}';
                          style-src 'self' 'nonce-{random}'; object-src 'none';
                          base-uri 'self';
```

Frontend script output uses `JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT` encoding and DOM construction exclusively via `document.createElement` + `textContent` — no `innerHTML`.

---

### 🚨 Exception Hierarchy

Throne Guard uses a typed exception hierarchy with asymmetric error messaging:

| Exception | Visible to User | Logged |
|---|---|---|
| `ValidationException` | Full message shown verbatim | No |
| `SecurityException` | Generic "request rejected" message | Yes — full detail to `error_log` |
| `StorageException` | Generic "server error" message | Yes — full detail to `error_log` |

Internal error details never leak to the client. Users see only what is safe to expose.

---

## ⚙️ Threat Model

> **Throne Guard is defense in depth.** It does not replace existing security measures — it adds a layer that becomes relevant specifically when your other layers have failed.

### What Throne Guard protects against

| Threat | Mitigation |
|---|---|
| Admin credential theft → backdoor plugin install | Admin lacks `install_plugins` |
| Admin session hijack → theme code injection | Admin lacks `edit_themes` |
| Admin compromise → persistent backdoor account | Admin lacks `create_users` |
| Admin compromise → privilege escalation | Admin cannot see or promote to Master role |
| File upload → PHP execution in uploads directory | Pre-Flight WAF + Upload Jail |
| Attacker discovering security tooling | Throne Guard hidden from non-Masters |
| Attacker disabling security plugin | Deactivation blocked at hook level |

### What Throne Guard does NOT protect against

| Threat | Reason |
|---|---|
| Server-level RCE | WordPress capability checks are irrelevant once the attacker has shell |
| Direct database modification | `wp_options` write access bypasses all WordPress logic |
| Master user compromise | Master is the top of the chain — protect it with 2FA |
| Supply chain attacks against Throne Guard | Always verify the plugin checksum |
| WordPress core vulnerabilities | Keep WordPress updated |

---

## 🚀 Installation

```bash
# 1. Clone into WordPress plugins directory
cd /var/www/html/wp-content/plugins/
git clone https://github.com/visiongaiatechnology/throne-guard

# 2. Activate in WordPress Admin
# Plugins → Throne Guard → Activate
# The activating Administrator is automatically promoted to Master

# 3. Define Superkey
# Master User Control → Admin Neutering
# Enter a Superkey (min 12 characters) and save

# 4. Review and apply capability stripping
# Toggle which capabilities Administrator retains
# Confirm with Superkey
```

On first activation, Throne Guard automatically:

```
→ Creates the Master role with full capabilities
→ Promotes the activating Administrator to Master
→ Initializes the capability database table (wp_mcp_user_roles)
→ Seeds default role descriptions
→ Deploys Upload Jail (.htaccess with BEGIN/END markers)
→ Hides itself from non-Master plugin lists
```

> **⚠️ Critical:** Record your Superkey somewhere safe before closing the dashboard. It is stored only as a bcrypt hash and cannot be recovered through WordPress.

---

## 🔌 Compatibility

| Component | Detail |
|---|---|
| **PHP** | 8.1+ (uses `match` expressions, throw expressions, `str_starts_with`) |
| **WordPress** | 6.0+ |
| **Webserver** | Apache with mod_rewrite (auto) · Nginx (manual rule translation required) · LiteSpeed |
| **Multisite** | Not tested — single-site installations only |
| **Page Builders** | Compatible — no DOM or header interference on frontend |
| **Other Security Plugins** | Compatible — Throne Guard operates at the capability layer, not the request layer |

---

## ⚠️ Known Limitations

- **Anti-Bruteforce uses `sleep(2)`** on failed Superkey attempts. Under concentrated attack on PHP-FPM with limited workers, this is a potential self-DoS vector. Transient-based rate limiting planned for V2.5.2.
- **Multisite not tested.** The capability model on WordPress multisite differs significantly — single-site installations only.
- **Server-level compromise bypasses Throne Guard.** WordPress capability checks are meaningless once an attacker has shell access.
- **Lost Superkey requires database access.** No email recovery, no alternative. By design — no recovery path means no recovery attack surface.

---

## 🧪 Manual Test Matrix

| Test | Steps | Expected Result |
|---|---|---|
| Capability stripping | Log in as Administrator after applying Admin Neutering | Plugins/Themes/Users menus absent or read-only |
| Master gate | Log out of Master session, access admin | Lock screen rendered, dashboard inaccessible |
| Plugin stealth | Log in as Administrator, check plugin list | Throne Guard absent from list |
| Deactivation guard | As Administrator, attempt deactivation via WP-CLI | HTTP 403 response |
| Upload WAF | Upload `shell.php`, `shell.phar.jpg`, `shell.phtml` via admin uploader | All blocked with 403 |
| Upload Jail | Place `.php` file in `wp-content/uploads/`, access via browser | 403 response |
| Superkey brute force | Attempt 5 wrong Superkeys | Each attempt delayed 2 seconds |
| Session expiry | Unlock Master session, wait 2 hours + 1 minute | Session re-locked automatically |

---

## 💰 Support the Project

[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-00457C?style=for-the-badge&logo=paypal)](https://www.paypal.com/paypalme/dergoldenelotus)

| Method | Address |
|---|---|
| **PayPal** | [paypal.me/dergoldenelotus](https://www.paypal.com/paypalme/dergoldenelotus) |
| **Bitcoin** | `bc1q3ue5gq822tddmkdrek79adlkm36fatat3lz0dm` |
| **ETH** | `0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85` |
| **USDT (ERC-20)** | `0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85` |

---

## 🔗 VGT Ecosystem

| Tool | Type | Purpose |
|---|---|---|
| 🏰 **Throne Guard** | **WordPress Hardening** | Admin capability isolation — you are here |
| ⚔️ **[VGT Sentinel CE](https://github.com/visiongaiatechnology/sentinelcom)** | **WAF / IDS Framework** | Zero-Trust request inspection, WAF, integrity monitoring |
| 🛡️ **[VGT Myrmidon](https://github.com/visiongaiatechnology/vgtmyrmidon)** | **ZTNA** | Zero Trust device registry and cryptographic integrity verification |
| ⚡ **[VGT Auto-Punisher](https://github.com/visiongaiatechnology/vgt-auto-punisher)** | **IDS** | L4+L7 Hybrid IDS — attackers terminated before they even knock |
| 📊 **[VGT Dattrack](https://github.com/visiongaiatechnology/dattrack)** | **Analytics** | Sovereign analytics engine — your data, your server, no third parties |
| 🌐 **[VGT Global Threat Sync](https://github.com/visiongaiatechnology/vgt-global-threat-sync)** | **Preventive** | Daily threat feed — block known attackers before they arrive |

---

## 🤝 Contributing

Pull requests are welcome. For major changes, open an issue first to discuss the direction.

**Security issues:** Please email rather than opening a public issue.

Licensed under **GPLv2+** — the same license as WordPress itself. Fork it, modify it, ship it.

---

## 🏢 Built by VisionGaia Technology

[![VGT](https://img.shields.io/badge/VGT-VisionGaia_Technology-red?style=for-the-badge)](https://visiongaiatechnology.de)

VisionGaia Technology builds security infrastructure for operators who assume compromise.

> *"Throne Guard was built because WordPress Administrator is a role with too much power and too little friction. The default role model was designed for 2003, when WordPress was a blog engine. In 2026, it is the pivot point of every real-world WordPress hack. Throne Guard fixes that at the capability level."*

---

*Version 2.5.1 — Throne Guard // Admin Capability Isolation // Zero-Trust Session Gating // Defense in Depth // AGPLv3+*
