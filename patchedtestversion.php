<?php
/**
 * Plugin Name: VGT Throne Guard
 * Description: Throne Guard is a WordPress hardening plugin that removes the most dangerous capabilities from the Administrator role and places them behind a separate Master role gated by a Superkey.
 * Version: 2.5.1
 * Author: VisionGaia Technology
 * Author URI: https://visiongaiatechnology.de
 * License: AGPLv3.0+
 * Requires PHP: 8.1
 */

declare(strict_types=1);

/* -------------------------------------------------------------------------
 * SECTION 1 - GLOBAL INITIALISATION & SECURITY GATE
 * ------------------------------------------------------------------------- */
if (!defined('ABSPATH')) {
    exit;
}

/* --------------------------- 1.5.A - Exception Hierarchy --------------------------- */
class AppException extends Exception {}
class ValidationException extends AppException {}  
class SecurityException extends AppException {}   
class StorageException extends AppException {}     

/* --------------------------- 1.5.C - Error Handler Consistency --------------------------- */
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED);

/* -------------------------------------------------------------------------
 * SECTION 2 - PLUGIN CORE CLASS
 * ------------------------------------------------------------------------- */
final class MasterUserControlPlugin {
    private const DB_VERSION = '1.0';
    private static ?string $csp_nonce = null;
    
    private const TOXIC_CAPABILITIES = [
        'activate_plugins', 'delete_plugins', 'install_plugins', 'edit_plugins', 'update_plugins',
        'switch_themes', 'edit_themes', 'install_themes', 'delete_themes', 'update_themes',
        'edit_users', 'delete_users', 'create_users', 'promote_users'
    ];

    public function __construct() {
        // Pre-Flight WAF Interceptor
        $this->pre_flight_waf();

        register_activation_hook(__FILE__, [$this, 'activate']);
        register_deactivation_hook(__FILE__, [$this, 'deactivate']);
        
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_post_mcp_save_roles', [$this, 'handle_save_roles']);
        add_action('admin_post_mcp_upload_file', [$this, 'handle_file_upload']);
        add_action('admin_post_mcp_admin_hardening', [$this, 'handle_admin_hardening']);
        
        // Zero-Trust Session Gating (GUI)
        add_action('admin_init', [$this, 'enforce_backend_lock'], 1);
        add_action('admin_post_mcp_unlock_backend', [$this, 'handle_backend_unlock']);
        add_action('clear_auth_cookie', [$this, 'destroy_backend_lock_cookie']);
        
        // REDTEAM FIX (v2.5.4): Zero-Trust Session Gating (Headless/API)
        add_action('rest_api_init', [$this, 'enforce_api_lock'], 1);
        add_action('xmlrpc_call', [$this, 'enforce_api_lock'], 1);

        // CSP & Frontend
        add_action('send_headers', [$this, 'inject_global_security_headers']); 
        add_action('wp_footer', [$this, 'render_frontend_script']);
        
        // Role Jailing & Stealth
        add_filter('editable_roles', [$this, 'filter_editable_roles']);
        add_filter('all_plugins', [$this, 'hide_plugin_from_admins']);
        add_action('deactivate_plugin', [$this, 'prevent_unauthorized_deactivation'], 10, 2);

        // UI & Execution Backdoor Seals
        add_action('admin_bar_menu', [$this, 'neuter_admin_bar'], 9999);
        add_action('admin_menu', [$this, 'neuter_sidebar_menu'], 9999);
        add_action('admin_init', [$this, 'block_third_party_admin_pages'], 2);
    }

    public static function get_csp_nonce(): string {
        if (self::$csp_nonce === null) {
            self::$csp_nonce = bin2hex(random_bytes(16));
        }
        return self::$csp_nonce;
    }

    /* --------------------------- 3.3 - HTTP Security Headers --------------------------- */
    public function inject_global_security_headers(): void {
        if (headers_sent()) return;

        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

        // VGT Enclave Isolation: CSP is exclusively enforced on Master Control routes.
        // Global enforcement would destroy the WordPress host ecosystem (Themes/Gutenberg).
        $is_mcp_dashboard = is_admin() && isset($_GET['page']) && $_GET['page'] === 'mcp-dashboard';
        if ($is_mcp_dashboard) {
            $nonce = self::get_csp_nonce();
            header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{$nonce}'; style-src 'self' 'nonce-{$nonce}'; object-src 'none'; base-uri 'self';");
        }
    }

    private function generate_csrf_token(): string {
        $token = bin2hex(random_bytes(32));
        update_user_meta(get_current_user_id(), '_mcp_csrf_token', $token);
        return $token;
    }

    private function verify_csrf_token(string $token): void {
        $user_id = get_current_user_id();
        $stored = get_user_meta($user_id, '_mcp_csrf_token', true);
        if (empty($stored) || !hash_equals($stored, $token)) {
            throw new SecurityException('CSRF token validation failed or token expired.');
        }
        delete_user_meta($user_id, '_mcp_csrf_token'); 
    }

    /* --------------------------- 2.0 - Activation / Deactivation --------------------------- */
    public function activate(): void {
        try {
            $this->create_tables();
            $this->seed_default_roles();
            $this->sync_core_roles(); 
            $this->bootstrap_first_master(); 
            $this->enforce_global_upload_jail();
            add_option('mcp_db_version', self::DB_VERSION);
            add_option('mcp_superkey_hash', ''); 
        } catch (Throwable $e) {
            error_log('[FATAL] Activation failed: ' . $e->getMessage());
            wp_die('Systemfehler bei der Aktivierung. Siehe Server-Logs.');
        }
    }

    public function deactivate(): void {}

    private function create_tables(): void {
        global $wpdb;
        $charset = $wpdb->get_charset_collate();
        $sql_roles = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}mcp_user_roles (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            role_key VARCHAR(64) NOT NULL,
            role_name VARCHAR(255) NOT NULL,
            role_description TEXT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY role_key (role_key)
        ) $charset;";
        $wpdb->query($sql_roles) or throw new StorageException('Failed to create user_roles table.');
    }

    private function seed_default_roles(): void {
        global $wpdb;
        $roles = [['master', 'Master', 'All-Power-User'], ['admin', 'Administrator', 'Standard-Administrator']];
        foreach ($roles as $r) {
            $wpdb->insert($wpdb->prefix . 'mcp_user_roles', ['role_key' => $r[0], 'role_name' => $r[1], 'role_description' => $r[2]], ['%s', '%s', '%s']);
        }
    }

    private function sync_core_roles(): void {
        $admin_role = get_role('administrator');
        $caps = $admin_role ? $admin_role->capabilities : ['manage_options' => true];
        $caps['mcp_master_access'] = true;
        add_role('master', 'Master', $caps);
    }

    private function bootstrap_first_master(): void {
        $masters = get_users(['role' => 'master', 'number' => 1]);
        if (empty($masters)) {
            $current_user = wp_get_current_user();
            if ($current_user && $current_user->ID && in_array('administrator', (array)$current_user->roles, true)) {
                $current_user->set_role('master');
            }
        }
    }

    public function filter_editable_roles(array $roles): array {
        if (!current_user_can('mcp_master_access') && isset($roles['master'])) {
            unset($roles['master']);
        }
        return $roles;
    }

    public function hide_plugin_from_admins(array $plugins): array {
        if (!current_user_can('mcp_master_access')) {
            unset($plugins[plugin_basename(__FILE__)]);
        }
        return $plugins;
    }

    public function prevent_unauthorized_deactivation(string $plugin, bool $network_deactivating): void {
        if ($plugin === plugin_basename(__FILE__) && !current_user_can('mcp_master_access')) {
            wp_die('Security Error: Insufficient privileges to deactivate Master Control.', 'Access Denied', ['response' => 403]);
        }
    }

    /* -------------------------------------------------------------------------
     * SECTION 2.1 - WAF & GLOBAL JAIL (RCE PREVENTION)
     * ------------------------------------------------------------------------- */
    private function pre_flight_waf(): void {
        if (empty($_FILES)) return;
        
        $is_admin = is_admin() || (strpos($_SERVER['REQUEST_URI'] ?? '', '/wp-admin/') !== false);
        $is_mcp = isset($_POST['action']) && strpos((string)$_POST['action'], 'mcp_') === 0;
        if (!$is_admin && !$is_mcp) return;

        $toxic_exts = ['php', 'phtml', 'phar', 'shtml', 'php3', 'php4', 'php5', 'pht', 'cgi', 'pl', 'asp', 'aspx', 'jsp'];
        $toxic_pattern = implode('|', $toxic_exts);
        
        $check_name = function(string $filename) use ($toxic_exts, $toxic_pattern) {
            $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
            if (in_array($ext, $toxic_exts, true) || preg_match('/\.(' . $toxic_pattern . ')\./i', $filename)) {
                error_log('[VGT WAF] AFW Intercepted: ' . $filename);
                http_response_code(403);
                die('VGT Enclave WAF: Toxic file payload intercepted and destroyed.');
            }
        };

        foreach ($_FILES as $file_input) {
            if (isset($file_input['name'])) {
                if (is_array($file_input['name'])) {
                    array_walk_recursive($file_input['name'], function($val) use ($check_name) {
                        if (is_string($val)) $check_name($val);
                    });
                } elseif (is_string($file_input['name'])) {
                    $check_name($file_input['name']);
                }
            }
        }
    }

    private function enforce_global_upload_jail(): void {
        $upload_dir = wp_upload_dir();
        if (!empty($upload_dir['error'])) return;
        
        $base_dir = $upload_dir['basedir'];
        $htaccess_path = $base_dir . '/.htaccess';
        
        $jail_rules = <<<EOT

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

EOT;

        if (file_exists($htaccess_path)) {
            $content = (string)file_get_contents($htaccess_path);
            if (strpos($content, '# BEGIN VGT REDTEAM') === false) {
                @file_put_contents($htaccess_path, $jail_rules, FILE_APPEND);
            }
        } else {
            @file_put_contents($htaccess_path, ltrim($jail_rules));
        }
    }

    /* -------------------------------------------------------------------------
     * SECTION 2.5 - ZERO-TRUST ADMIN NEUTERING (BAR, SIDEBAR & ROUTING)
     * ------------------------------------------------------------------------- */
    
    public function neuter_admin_bar(WP_Admin_Bar $wp_admin_bar): void {
        if (current_user_can('mcp_master_access')) return;

        $admin_role = get_role('administrator');
        if ($admin_role && !$admin_role->has_cap('activate_plugins')) {
            $allowed_nodes = [
                'menu-toggle', 'wp-logo', 'site-name', 'view-site', 
                'my-account', 'user-info', 'edit-profile', 'logout'
            ];
            
            $all_nodes = $wp_admin_bar->get_nodes();
            if ($all_nodes) {
                foreach ($all_nodes as $node) {
                    if (!in_array($node->id, $allowed_nodes, true)) {
                        $wp_admin_bar->remove_node($node->id);
                    }
                }
            }
        }
    }

    public function neuter_sidebar_menu(): void {
        if (current_user_can('mcp_master_access')) return;

        $admin_role = get_role('administrator');
        if ($admin_role && !$admin_role->has_cap('activate_plugins') && current_user_can('manage_options')) {
            global $menu;
            
            $allowed_core_menus = [
                'index.php', 'edit.php', 'upload.php', 'edit.php?post_type=page',
                'edit-comments.php', 'themes.php', 'plugins.php', 'users.php',
                'tools.php', 'options-general.php', 'options-writing.php', 'options-reading.php',
                'options-discussion.php', 'options-media.php', 'options-permalink.php', 'profile.php',
                'separator1', 'separator2', 'separator-last'
            ];
            
            if (is_array($menu)) {
                foreach ($menu as $key => $item) {
                    if (!in_array($item[2], $allowed_core_menus, true)) {
                        remove_menu_page($item[2]);
                    }
                }
            }
        }
    }

    public function block_third_party_admin_pages(): void {
        if (current_user_can('mcp_master_access')) return;

        $admin_role = get_role('administrator');
        if ($admin_role && !$admin_role->has_cap('activate_plugins') && current_user_can('manage_options')) {
            // REDTEAM FIX (v2.5.4): Radikale Blockade für jeglichen Parameter "page"
            // Dies fängt nun auch Plugins unter options-general.php, tools.php etc. ab.
            if (isset($_GET['page'])) {
                error_log('[VGT NEUTERING] Blocked unauthorized access to 3rd party plugin UI: ' . $_GET['page']);
                wp_die('VGT Zero-Trust Enclave: Der Zugriff auf Third-Party-Schnittstellen ist gesperrt.', 'Access Denied', ['response' => 403]);
            }
        }
    }

    // REDTEAM FIX (v2.5.4): Headless / API Lock Enforcement
    public function enforce_api_lock(): void {
        if (!current_user_can('mcp_master_access')) return;
        if (empty(get_option('mcp_superkey_hash', ''))) return;
        
        if (!$this->is_session_unlocked()) {
            wp_die('VGT Enclave Locked: API execution blocked.', 'Unauthorized', 401);
        }
    }

    public function enforce_backend_lock(): void {
        if (!current_user_can('mcp_master_access')) return;

        $superkey_hash = get_option('mcp_superkey_hash', '');
        if (empty($superkey_hash)) return; 

        if (defined('DOING_AJAX') && DOING_AJAX) {
            if ($this->is_session_unlocked()) {
                return;
            }
            wp_die('VGT Enclave Locked.', '', 401);
        }

        global $pagenow;
        if ($pagenow === 'admin-post.php' && isset($_POST['action']) && $_POST['action'] === 'mcp_unlock_backend') {
            return;
        }

        if ($this->is_session_unlocked()) return;

        $this->render_lock_screen();
        exit;
    }

    private function is_session_unlocked(): bool {
        $cookie_name = 'mcp_vault_key_' . get_current_user_id();
        if (!isset($_COOKIE[$cookie_name])) return false;

        $token = (string)$_COOKIE[$cookie_name];

        $stored_data = get_user_meta(get_current_user_id(), '_mcp_vault_session', true);
        if (empty($stored_data)) return false;

        $stored_parts = explode('|', (string)$stored_data);
        if (count($stored_parts) !== 2 || time() > (int)$stored_parts[0]) {
            delete_user_meta(get_current_user_id(), '_mcp_vault_session'); 
            return false;
        }

        return hash_equals((string)$stored_data, $token);
    }

    private function render_lock_screen(): void {
        $csrf_token = $this->generate_csrf_token();
        $nonce = self::get_csp_nonce();
        $error_msg = isset($_GET['mcp_error']) ? '<div style="color: #ff4444; margin-bottom: 20px; border: 1px solid #ff4444; padding: 10px; background: rgba(255,0,0,0.1);">VGT ALERT: Inkorrekter Superkey. Vorfall geloggt.</div>' : '';
        
        if (!headers_sent()) {
            header('X-Content-Type-Options: nosniff');
            header('X-Frame-Options: DENY');
            header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{$nonce}'; style-src 'self' 'nonce-{$nonce}'; object-src 'none'; base-uri 'self';");
        }

        http_response_code(401);
        ?>
        <!DOCTYPE html>
        <html lang="de">
        <head>
            <meta charset="UTF-8">
            <title>VGT | Restricted Enclave</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style nonce="<?php echo esc_attr($nonce); ?>">
                body { background: #0a0a0a; color: #00ff00; font-family: monospace; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
                .vault-box { border: 1px solid #333; background: #111; padding: 40px; box-shadow: 0 0 20px rgba(0, 255, 0, 0.1); max-width: 400px; width: 100%; text-align: center; }
                input[type="password"] { background: #000; border: 1px solid #00ff00; color: #00ff00; padding: 10px; width: calc(100% - 24px); margin-bottom: 20px; font-family: monospace; outline: none; }
                button { background: #00ff00; color: #000; border: none; padding: 10px 20px; font-weight: bold; cursor: pointer; text-transform: uppercase; width: 100%; }
                button:hover { background: #00cc00; }
            </style>
        </head>
        <body>
            <div class="vault-box">
                <h2>☢️ ZERO-TRUST ENCLAVE</h2>
                <p>Standard-Authentifizierung unzureichend.<br>Superkey zur Entschlüsselung der Session erforderlich.</p>
                <?php echo $error_msg; ?>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <?php wp_nonce_field('mcp_unlock_backend', 'mcp_nonce'); ?>
                    <input type="hidden" name="action" value="mcp_unlock_backend">
                    <input type="hidden" name="csrf_token" value="<?php echo esc_attr($csrf_token); ?>">
                    <input type="password" name="superkey" placeholder="Superkey eingeben..." required autofocus>
                    <button type="submit">Session Entschlüsseln</button>
                </form>
            </div>
        </body>
        </html>
        <?php
    }

    public function handle_backend_unlock(): void {
        try {
            if (!current_user_can('mcp_master_access')) {
                throw new SecurityException('Access denied. Insufficient privileges.');
            }
            if (!isset($_POST['mcp_nonce']) || !wp_verify_nonce($_POST['mcp_nonce'], 'mcp_unlock_backend')) {
                throw new SecurityException('WP Nonce verification failed.');
            }
            
            $this->verify_csrf_token($_POST['csrf_token'] ?? '');

            $superkey_hash = get_option('mcp_superkey_hash', '');
            $provided_key = $_POST['superkey'] ?? '';

            if (empty($superkey_hash) || !password_verify($provided_key, $superkey_hash)) {
                sleep(2); // Timing-Attack Mitigation
                throw new SecurityException('Invalid Superkey provided.');
            }

            $expiration = time() + (2 * 3600);
            $session_data = $expiration . '|' . bin2hex(random_bytes(32));
            update_user_meta(get_current_user_id(), '_mcp_vault_session', $session_data);

            $token = $session_data;
            $cookie_name = 'mcp_vault_key_' . get_current_user_id();
            
            setcookie($cookie_name, $token, [
                'expires' => $expiration,
                'path' => SITECOOKIEPATH,
                'domain' => COOKIE_DOMAIN,
                'secure' => is_ssl(),
                'httponly' => true,
                'samesite' => 'Strict'
            ]);

            wp_redirect(admin_url('admin.php?page=mcp-dashboard'));
            exit;

        } catch (ValidationException $e) {
            wp_die(esc_html($e->getMessage()), 'Validation Error', ['response' => 400]);
        } catch (SecurityException $e) {
            error_log('[SEC/UNLOCK] ' . $e->getMessage());
            wp_redirect(admin_url('?mcp_locked=1&mcp_error=1'));
            exit;
        } catch (StorageException $e) {
            error_log('[STORAGE] ' . $e->getMessage());
            wp_die('A server error occurred.', 'Server Error', ['response' => 500]);
        } catch (Throwable $e) {
            error_log('[FATAL] ' . $e->getMessage());
            wp_die('Critical system fault.', 'System Error', ['response' => 500]);
        }
    }

    public function destroy_backend_lock_cookie(): void {
        $cookie_name = 'mcp_vault_key_' . get_current_user_id();
        if (isset($_COOKIE[$cookie_name])) {
            setcookie($cookie_name, '', [
                'expires' => time() - 3600,
                'path' => SITECOOKIEPATH,
                'domain' => COOKIE_DOMAIN,
                'secure' => is_ssl(),
                'httponly' => true,
                'samesite' => 'Strict'
            ]);
        }
        delete_user_meta(get_current_user_id(), '_mcp_vault_session');
    }

    /* -------------------------------------------------------------------------
     * SECTION 3 - ADMIN INTERFACE
     * ------------------------------------------------------------------------- */
    public function add_admin_menu(): void {
        add_menu_page('Master User Control', 'Master User Control', 'mcp_master_access', 'mcp-dashboard', [$this, 'render_dashboard'], 'dashicons-shield', 81);
    }

    public function render_dashboard(): void {
        $this->enforce_global_upload_jail();
        
        $csrf_token = $this->generate_csrf_token();
        global $wpdb;
        $roles = $wpdb->get_results("SELECT id, role_key, role_name, role_description FROM {$wpdb->prefix}mcp_user_roles;", ARRAY_A);
        
        $superkey_hash = get_option('mcp_superkey_hash', '');
        $is_superkey_set = !empty($superkey_hash);
        
        $admin_role = get_role('administrator');
        $admin_caps = $admin_role ? $admin_role->capabilities : [];
        ?>
        <div class="wrap">
            <h1><?php esc_html_e('Master User Control Dashboard', 'mcp'); ?></h1>
            
            <?php if (isset($_GET['success'])): ?>
                <div class="notice notice-success is-dismissible"><p>Änderungen sicher gespeichert.</p></div>
            <?php endif; ?>
            <?php if (isset($_GET['error'])): ?>
                <div class="notice notice-error is-dismissible"><p>Sicherheitsverletzung: Superkey ungültig oder Aktion abgelehnt.</p></div>
            <?php endif; ?>

            <div style="background: #fff; padding: 20px; border: 1px solid #ccd0d4; margin-bottom: 20px;">
                <h2 style="margin-top: 0; color: #d63638;">☢️ Admin Neutering (Zero-Trust Override)</h2>
                <p>Entziehe der Rolle <strong>Administrator</strong> kritische Rechte. Ein Angreifer, der Admin-Zugriff erhält, ist machtlos.</p>
                
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <?php wp_nonce_field('mcp_admin_hardening', 'mcp_nonce'); ?>
                    <input type="hidden" name="action" value="mcp_admin_hardening">
                    <input type="hidden" name="csrf_token" value="<?php echo esc_attr($csrf_token); ?>">
                    
                    <table class="widefat striped">
                        <thead><tr><th>Toxisches Privileg</th><th>Admin darf das?</th></tr></thead>
                        <tbody>
                            <?php foreach (self::TOXIC_CAPABILITIES as $cap): ?>
                                <tr>
                                    <td><code><?php echo esc_html($cap); ?></code></td>
                                    <td>
                                        <label>
                                            <input type="checkbox" name="admin_caps[<?php echo esc_attr($cap); ?>]" value="1" 
                                                <?php checked(isset($admin_caps[$cap]) && $admin_caps[$cap] === true); ?>>
                                            Ja, erlauben
                                        </label>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    
                    <hr>
                    <?php if (!$is_superkey_set): ?>
                        <p style="color: #d63638;"><strong>⚠️ SETUP ERFORDERLICH:</strong> Erstelle zuerst einen Superkey, um diese Einstellungen zu speichern.</p>
                        <p>
                            <label><strong>Neuen Superkey definieren:</strong></label><br>
                            <input type="password" name="new_superkey" autocomplete="new-password" required minlength="12" style="width: 300px;">
                        </p>
                    <?php else: ?>
                        <p>
                            <label><strong>Superkey eingeben zur Bestätigung (Pflichtfeld):</strong></label><br>
                            <input type="password" name="superkey" autocomplete="new-password" required style="width: 300px; border-color: #d63638;">
                        </p>
                    <?php endif; ?>
                    
                    <?php submit_button($is_superkey_set ? 'Admin-Rechte mit Superkey überschreiben' : 'Superkey initialisieren & Speichern', 'primary', 'submit', false, ['style' => 'background: #d63638; border-color: #d63638;']); ?>
                </form>
            </div>

            <hr>
            <h2><?php esc_html_e('Rollen-Beschreibungen', 'mcp'); ?></h2>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <?php wp_nonce_field('mcp_save_roles', 'mcp_nonce'); ?>
                <input type="hidden" name="action" value="mcp_save_roles">
                <input type="hidden" name="csrf_token" value="<?php echo esc_attr($csrf_token); ?>">
                <table class="widefat fixed striped">
                    <thead><tr><th>Key</th><th>Name</th><th>Desc</th></tr></thead>
                    <tbody>
                        <?php foreach ($roles as $role): ?>
                            <tr>
                                <td><?php echo esc_html($role['role_key']); ?></td>
                                <td><input type="text" name="role_name[<?php echo (int)$role['id']; ?>]" value="<?php echo esc_attr($role['role_name']); ?>"></td>
                                <td><input type="text" name="role_desc[<?php echo (int)$role['id']; ?>]" value="<?php echo esc_attr($role['role_description']); ?>"></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                <?php submit_button(esc_html__('Rollen speichern', 'mcp')); ?>
            </form>

            <hr>
            <h2><?php esc_html_e('Sicherer Datei-Upload (Jailed Vault)', 'mcp'); ?></h2>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" enctype="multipart/form-data">
                <?php wp_nonce_field('mcp_upload_file', 'mcp_nonce'); ?>
                <input type="hidden" name="action" value="mcp_upload_file">
                <input type="hidden" name="csrf_token" value="<?php echo esc_attr($csrf_token); ?>">
                <input type="file" name="mcp_file" accept="image/jpeg,image/png,image/webp,image/gif" required>
                <?php submit_button(esc_html__('Upload to Vault', 'mcp')); ?>
            </form>
        </div>
        <?php
    }

    /* -------------------------------------------------------------------------
     * SECTION 4 - FORM HANDLERS (Hardening & Rollen)
     * ------------------------------------------------------------------------- */
    
    public function handle_admin_hardening(): void {
        try {
            if (!current_user_can('mcp_master_access')) throw new SecurityException('Insufficient permissions.');
            if (!isset($_POST['mcp_nonce']) || !wp_verify_nonce($_POST['mcp_nonce'], 'mcp_admin_hardening')) throw new SecurityException('Nonce failed.');
            $this->verify_csrf_token($_POST['csrf_token'] ?? '');

            $superkey_hash = get_option('mcp_superkey_hash', '');
            
            if (empty($superkey_hash)) {
                $new_key = $_POST['new_superkey'] ?? '';
                if (strlen($new_key) < 12) throw new ValidationException('Superkey muss mind. 12 Zeichen haben.');
                $hash = password_hash($new_key, PASSWORD_DEFAULT);
                update_option('mcp_superkey_hash', $hash);
            } else {
                $provided_key = $_POST['superkey'] ?? '';
                if (!password_verify($provided_key, $superkey_hash)) {
                    sleep(2);
                    throw new SecurityException('Superkey inkorrekt.');
                }
            }

            $admin_role = get_role('administrator');
            if (!$admin_role) throw new StorageException('Admin role missing.');
            
            $submitted_caps = $_POST['admin_caps'] ?? [];
            if (!is_array($submitted_caps)) throw new ValidationException('Invalid payload.');

            foreach (self::TOXIC_CAPABILITIES as $cap) {
                if (isset($submitted_caps[$cap]) && $submitted_caps[$cap] === '1') {
                    $admin_role->add_cap($cap);
                } else {
                    $admin_role->remove_cap($cap);
                }
            }
            
            wp_redirect(admin_url('admin.php?page=mcp-dashboard&success=1'));
            exit;

        } catch (ValidationException|SecurityException|StorageException $e) {
            error_log('[SEC/HARDENING] ' . $e->getMessage());
            wp_redirect(admin_url('admin.php?page=mcp-dashboard&error=1'));
            exit;
        }
    }

    public function handle_save_roles(): void {
        try {
            if (!current_user_can('mcp_master_access')) throw new SecurityException('Insufficient permissions for role modification.');
            if (!isset($_POST['mcp_nonce']) || !wp_verify_nonce($_POST['mcp_nonce'], 'mcp_save_roles')) throw new SecurityException('WP Nonce validation failed.');
            $this->verify_csrf_token($_POST['csrf_token'] ?? '');

            $role_names = $_POST['role_name'] ?? null;
            $role_descs = $_POST['role_desc'] ?? null;
            
            if (!is_array($role_names) || !is_array($role_descs)) throw new ValidationException('Invalid payload structure.');

            global $wpdb;
            $wpdb->query('START TRANSACTION');
            foreach ($role_names as $id => $name) {
                $name = trim((string)$name);
                if ($name === '') throw new ValidationException('Rollenname darf nicht leer sein.');
                
                $role_key = $wpdb->get_var($wpdb->prepare("SELECT role_key FROM {$wpdb->prefix}mcp_user_roles WHERE id = %d", (int)$id));
                if ($role_key === 'master') {
                    global $wp_roles;
                    if (!isset($wp_roles)) $wp_roles = new WP_Roles();
                    if (isset($wp_roles->roles['master'])) {
                        $wp_roles->roles['master']['name'] = $name;
                        update_option($wp_roles->role_key, $wp_roles->roles);
                    }
                }

                $result = $wpdb->update(
                    $wpdb->prefix . 'mcp_user_roles',
                    ['role_name' => $name, 'role_description' => trim((string)($role_descs[$id] ?? ''))],
                    ['id' => (int)$id],
                    ['%s', '%s'],
                    ['%d']
                );
                if ($result === false) throw new StorageException('DB update failed.');
            }
            $wpdb->query('COMMIT');
            
            wp_redirect(admin_url('admin.php?page=mcp-dashboard&success=1'));
            exit;

        } catch (ValidationException $e) {
            wp_die(esc_html($e->getMessage()), 'Validation Error', ['response' => 400]);
        } catch (SecurityException $e) {
            error_log('[SEC] ' . $e->getMessage());
            wp_die('Request rejected for security reasons.', 'Security Error', ['response' => 403]);
        } catch (StorageException $e) {
            error_log('[STORAGE] ' . $e->getMessage());
            wp_die('A server error occurred.', 'Server Error', ['response' => 500]);
        } catch (Throwable $e) {
            error_log('[FATAL] ' . $e->getMessage());
            wp_die('Critical system fault.', 'System Error', ['response' => 500]);
        }
    }

    /* -------------------------------------------------------------------------
     * SECTION 5 - SICHERER DATEI-UPLOAD (Vault, Jailed, Re-encoded)
     * ------------------------------------------------------------------------- */
    public function handle_file_upload(): void {
        try {
            if (!current_user_can('mcp_master_access')) throw new SecurityException('Insufficient permissions.');
            if (!isset($_POST['mcp_nonce']) || !wp_verify_nonce($_POST['mcp_nonce'], 'mcp_upload_file')) throw new SecurityException('WP Nonce verification failed.');
            $this->verify_csrf_token($_POST['csrf_token'] ?? '');

            if (!isset($_FILES['mcp_file'])) throw new ValidationException('Keine Datei übermittelt.');
            $file = $_FILES['mcp_file'];
            
            if (!is_string($file['tmp_name'])) throw new SecurityException('Invalid file structure injected.');
            if (!is_uploaded_file($file['tmp_name'])) throw new SecurityException('Uploaded file validation failed.');

            $max_bytes = 5 * 1024 * 1024;
            $realSize = filesize($file['tmp_name']);
            if ($realSize === false || $realSize === 0 || $realSize > $max_bytes) throw new ValidationException('Size boundary violation.');

            $finfo = new finfo(FILEINFO_MIME_TYPE);
            $mime  = $finfo->file($file['tmp_name']);
            $allowedMimes = [
                'image/jpeg' => IMAGETYPE_JPEG,
                'image/png'  => IMAGETYPE_PNG,
                'image/webp' => IMAGETYPE_WEBP,
                'image/gif'  => IMAGETYPE_GIF,
            ];
            if (!array_key_exists($mime, $allowedMimes)) throw new ValidationException('Unsupported MIME type.');

            $imageInfo = getimagesize($file['tmp_name']);
            if ($imageInfo === false) throw new ValidationException('Unable to read image information.');
            $expectedType = $allowedMimes[$mime];
            if ($imageInfo[2] !== $expectedType) throw new SecurityException('MIME/type mismatch. Polyglot vector blocked.');

            $required_memory = (int)(($imageInfo[0] * $imageInfo[1] * 4 * 1.5) + (10 * 1024 * 1024));
            $available_memory = wp_convert_hr_to_bytes(ini_get('memory_limit'));
            if ($available_memory > 0 && $required_memory > $available_memory) throw new ValidationException('Image dimensions require too much memory.');

            $src = match ($expectedType) {
                IMAGETYPE_JPEG => imagecreatefromjpeg($file['tmp_name']),
                IMAGETYPE_PNG  => imagecreatefrompng($file['tmp_name']),
                IMAGETYPE_WEBP => imagecreatefromwebp($file['tmp_name']),
                IMAGETYPE_GIF  => imagecreatefromgif($file['tmp_name']),
                default        => false
            };
            if ($src === false) throw new ValidationException('Failed to read image stream.');

            $upload_dir = wp_upload_dir()['basedir'] . '/mcp_vault';
            if (!is_dir($upload_dir)) {
                $old_umask = umask(0077);
                if (!mkdir($upload_dir, 0700, true)) {
                    umask($old_umask);
                    throw new StorageException('Failed to create vault directory.');
                }
                umask($old_umask);
                file_put_contents($upload_dir . '/.htaccess', "Require all denied\nOptions -Indexes");
                file_put_contents($upload_dir . '/index.php', "<?php\n// Silence is golden.");
            }

            $resolvedDir = realpath($upload_dir);
            if ($resolvedDir === false || !is_dir($resolvedDir)) throw new SecurityException('Upload directory resolution failed.');
            
            $safe_ext = match ($expectedType) {
                IMAGETYPE_JPEG => 'jpg',
                IMAGETYPE_PNG  => 'png',
                IMAGETYPE_WEBP => 'webp',
                IMAGETYPE_GIF  => 'gif',
            };
            $new_filename = bin2hex(random_bytes(16)) . '.' . $safe_ext;
            $destination  = $resolvedDir . DIRECTORY_SEPARATOR . $new_filename;

            if (!str_starts_with($destination, $resolvedDir . DIRECTORY_SEPARATOR)) throw new SecurityException('Path escaped jail.');

            $old_umask = umask(0077);
            $saved = match ($expectedType) {
                IMAGETYPE_JPEG => imagejpeg($src, $destination, 90),
                IMAGETYPE_PNG  => imagepng($src, $destination),
                IMAGETYPE_WEBP => imagewebp($src, $destination),
                IMAGETYPE_GIF  => imagegif($src, $destination),
            };
            umask($old_umask);
            imagedestroy($src);

            if (!$saved) throw new StorageException('Failed to store re-encoded image.');
            
            chmod($destination, 0600);
            wp_redirect(admin_url('admin.php?page=mcp-dashboard&upload=success'));
            exit;

        } catch (ValidationException $e) {
            wp_die(esc_html($e->getMessage()), 'Validation Error', ['response' => 400]);
        } catch (SecurityException $e) {
            error_log('[SEC] ' . $e->getMessage());
            wp_die('Request rejected for security reasons.', 'Security Error', ['response' => 403]);
        } catch (StorageException $e) {
            error_log('[STORAGE] ' . $e->getMessage());
            wp_die('A server error occurred.', 'Server Error', ['response' => 500]);
        } catch (Throwable $e) {
            error_log('[FATAL] ' . $e->getMessage());
            wp_die('Critical system fault.', 'System Error', ['response' => 500]);
        }
    }

    /* -------------------------------------------------------------------------
     * SECTION 7 - FRONTEND USER-DATA RENDERING
     * ------------------------------------------------------------------------- */
    public function render_frontend_script(): void {
        if (!is_user_logged_in()) return;
        $nonce = self::get_csp_nonce();
        $userData = wp_get_current_user()->display_name;
        ?>
        <script nonce="<?php echo esc_attr($nonce); ?>">
        (function(){
            const container = document.createElement('div');
            container.style.position = 'fixed';
            container.style.bottom = '10px';
            container.style.right = '10px';
            container.style.padding = '8px 12px';
            container.style.background = '#111';
            container.style.color = '#fff';
            container.style.fontFamily = 'monospace';
            container.style.borderRadius = '4px';
            container.style.zIndex = '999999';

            const userSlot = document.createElement('span');
            userSlot.id = 'mcp-user-slot';
            const userData = <?php echo json_encode($userData, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT | JSON_THROW_ON_ERROR); ?>;
            userSlot.textContent = 'Active: ' + userData;
            
            container.appendChild(userSlot);
            document.body.appendChild(container);
        })();
        </script>
        <?php
    }
}

new MasterUserControlPlugin();
