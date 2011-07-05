<?php
/*
Plugin Name: Simple LDAP Authentication
Version: 1.0.4
Plugin URI: http://redgecko.jp/wp/ldap_auth/
Description: Allows WordPress to authenticate users through LDAP
Author: RedGecko
Author URI: http://redgecko.jp/
*/

/*	Copyright 2009 Yoshimitsu Mori (email : redgecko@redgecko.jp)

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

if ( !class_exists('LdapAuthenticationPlugin') ) {

	class LdapAuthenticationPlugin {
		var $authenticated = false;
		var $ldap_auth_domain = 'ldap-auth';
		
		function LdapAuthenticationPlugin() {
			if ( isset($_GET['activate']) && $_GET['activate'] == 'true' )
				add_action('init', array(&$this, 'initialize_options'));
			add_action('network_admin_menu', array(&$this, 'add_options_page'));
			add_filter('authenticate', array(&$this, 'authenticate'), 10, 3);
			add_filter('check_password', array(&$this, 'override_password_check'), 10, 4);
			add_action('lost_password', array(&$this, 'disable_function'));
			add_action('retrieve_password', array(&$this, 'disable_function'));
			add_action('password_reset', array(&$this, 'disable_function'));
			add_action('check_passwords', array(&$this, 'generate_password'), 10, 3);
			add_filter('show_password_fields', array(&$this, 'disable_password_fields'));
			add_filter('plugin_action_links', array(&$this, 'add_link'), 10, 2);
			$this->ldap_auth_domain = dirname(plugin_basename(__FILE__));
			load_plugin_textdomain($this->ldap_auth_domain,
				PLUGINDIR.'/'.dirname(plugin_basename(__FILE__)).'/languages',
				dirname(plugin_basename(__FILE__)).'/languages');
		}

		/*************************************************************
		 * Plugin hooks
		 *************************************************************/

		/*
		 * Add options for this plugin to the database.
		 */
		function initialize_options() {
			if ( current_user_can('manage_options') ) {
				add_site_option('LDAP_authentication_auto_create_user', false, 'Should a new user be created automatically if not already in the WordPress database?');
				add_site_option('LDAP_authentication_use_ssl', false, 'Use SSL Connection');
				add_site_option('LDAP_authentication_server', '', 'LDAP Server');
				add_site_option('LDAP_authentication_base_dn', '', 'Base DN');
				add_site_option('LDAP_authentication_role_equivalent_groups', '', 'Role Equivalent Groups');
				add_site_option('LDAP_authentication_default_email_domain', '', 'Default Email Domain');
				add_site_option('LDAP_authentication_bind_dn', '', 'Bind DN');
				add_site_option('LDAP_authentication_bind_password', '', 'Bind Password');
				add_site_option('LDAP_authentication_uid_filter', '(uid=%user_id%)', 'LDAP uid search filter');
				add_site_option('LDAP_authentication_group_filter', '(cn=%group%)', 'LDAP group search filter');
				add_site_option('LDAP_authentication_group_attribute', 'memberuid', 'LDAP group attribute');
			}
		}

		/*
		 * Add an options pane for this plugin.
		 */
		function add_options_page() {
			if ( function_exists('add_submenu_page') ) {
				$page = add_submenu_page('settings.php', 'Simple LDAP Authentication', 'Simple LDAP Authentication', 'manage_options', 'simple_ldap_authentication', array(&$this, '_display_options_page'));
				add_action("admin_print_styles-$page", array(&$this, 'add_admin_custom_css'));
				add_action("admin_print_scripts-$page", array(&$this, 'add_admin_script'));
			}
		}

		function authenticate( $user, $username, $password ) {
			if (is_a($user, 'WP_User')) {
				return $user;
			}
			
			$this->authenticated = false;
			$use_ssl = (bool) get_site_option('LDAP_authentication_use_ssl');
			$ldap_server = get_site_option('LDAP_authentication_server');
			$use_ssl = get_site_option('LDAP_authentication_use_ssl');
			$base_dn = get_site_option('LDAP_authentication_base_dn');
			$bind_dn = get_site_option('LDAP_authentication_bind_dn');
			$bind_password = get_site_option('LDAP_authentication_bind_password');
			$uid_filter = get_site_option('LDAP_authentication_uid_filter');
			$replace_count = 0;
			$uid_filter = str_replace('%user_id%', $username, $uid_filter, &$replace_count);
			if ( $replace_count == 0 ) {
				if ( defined('WP_DEBUG') && ( true === WP_DEBUG ) )
					trigger_error('LDAP uid search filter is mistaked.');
				return new WP_Error('filter_error', __('<strong>ERROR</strong>: LDAP user ID search filter is inacuurate. The filter must contains \'%user_id%\'.', $this->ldap_auth_domain));
			}

			if ( $use_ssl )
				$ldap_server = 'ldaps://' . $ldap_server . '/';
			if ( !defined('WP_DEBUG') || ( defined('WP_DEBUG') && false === WP_DEBUG ) ) {
				$ldap = @ldap_connect($ldap_server);
			} else {
				trigger_error('Connecting to \'' . $ldap_server . '\'.');
				$ldap = ldap_connect($ldap_server);
			}
			if ( !$ldap )
				return new WP_Error('cannot_connect', sprintf(__('<strong>ERROR</strong>: Cannot connect to \'%s\'.', $this->ldap_auth_domain), $ldap_server));
			ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
			if ( $bind_dn ) {
				if ( !defined('WP_DEBUG') || ( defined('WP_DEBUG') && false === WP_DEBUG ) ) {
					$ldap_bind = @ldap_bind($ldap, $bind_dn, $bind_password);
				} else {
					trigger_error('LDAP bind as \'' . $bind_dn . '\'.');
					$ldap_bind = ldap_bind($ldap, $bind_dn, $bind_password);
				}
				if ( !$ldap_bind ) {
					if ( $use_ssl )
						return new WP_Error('cannot_bind', __('<strong>ERROR</strong>: LDAP bind failed. Either the LDAPS connection failed or the login credentials are incorrect.', $this->ldap_auth_domain));
					else
						return new WP_Error('cannot_bind', __('<strong>ERROR</strong>: LDAP bind failed. Check the login credentials.', $this->ldap_auth_domain));
				}
			} else {
				if ( !defined('WP_DEBUG') || ( defined('WP_DEBUG') && false === WP_DEBUG ) ) {
					$ldap_bind = @ldap_bind($ldap);
				} else {
					trigger_error('LDAP bind as anonymous.');
					$ldap_bind = ldap_bind($ldap, $bind_dn, $bind_password);
				}
				if ( !$ldap_bind ) {
					if ( $use_ssl )
						return new WP_Error('cannot_bind', __('<strong>ERROR</strong>: Anonymous LDAP bind failed. Either the LDAPS connection failed or the login credentials are incorrect.', $this->ldap_auth_domain));
					else
						return new WP_Error('cannot_bind', __('<strong>ERROR</strong>: Anonymous LDAP bind failed. Check the login credentials.', $this->ldap_auth_domain));
				}
			}
			if ( !defined('WP_DEBUG') || ( defined('WP_DEBUG') && false === WP_DEBUG ) ) {
				$result = @ldap_search($ldap, $base_dn, $uid_filter, array('dn'));
			} else {
				trigger_error('Searching with \'' . $uid_filter . '\' filter.');
				$result = ldap_search($ldap, $base_dn, $uid_filter, array('dn'));
			}
			if ( !$result ) return false;
			if ( !defined('WP_DEBUG') || ( defined('WP_DEBUG') && false === WP_DEBUG ) )
				$ldap_user = @ldap_get_entries($ldap, $result);
			else
				$ldap_user = ldap_get_entries($ldap, $result);
			if ( is_array($ldap_user) && $ldap_user['count'] == 1 ) {
				$ldap_user = $ldap_user[0]['dn'];
			} else {
				if ( defined('WP_DEBUG') && ( true === WP_DEBUG ) )
					trigger_error('Can\'t find user \'' . $username . '\' in LDAP.');
				@ldap_unbind($ldap);
				return false;
			}
			
			if ( !defined('WP_DEBUG') || ( defined('WP_DEBUG') && false === WP_DEBUG ) ) {
				$ldap_bind = @ldap_bind($ldap, $ldap_user, $password);
			} else {
				trigger_error('LDAP re-bind as \'' . $ldap_user . '\'.');
				$ldap_bind = ldap_bind($ldap, $ldap_user, $password);
			}
			if ( $ldap_bind ) {
				$this->authenticated = true;
			} else {
				if ( defined('WP_DEBUG') && ( true === WP_DEBUG ) )
					trigger_error('Re-bind failed');
				@ldap_unbind($ldap);
				return false;
			}
			
			// Create new users automatically, if configured
			$user = get_userdatabylogin($username);
			if ( !$user or $user->user_login != $username ) {
				$user_role = $this->_get_user_role_equiv($ldap, $username);
				if ( (bool) get_site_option('LDAP_authentication_auto_create_user' )
						|| $user_role != '' ) {
					$sn_lang = 'sn;lang-' . WPLANG;
					$gn_lang = 'givenname;lang-' . WPLANG;
					$result = @ldap_search($ldap, $base_dn, $uid_filter,
							array('sn', 'givenname', 'mail', $sn_lang, $gn_lang)
							);
					$userinfo = @ldap_get_entries($ldap, $result);
					$userinfo = $userinfo[0];
					$email = $userinfo['mail'][0];
					if ( $userinfo[$gn_lang][0] )
						$first_name = $userinfo[$gn_lang][0];
					else
						$first_name = $userinfo['givenname'][0];
					if ( $userinfo[$sn_lang][0] )
						$last_name = $userinfo[$sn_lang][0];
					else
						$last_name = $userinfo['sn'][0];
					$this->_create_user($username, $email, $first_name, $last_name, $user_role);
				} else {
					// Bail out to avoid showing the login form
					@ldap_unbind($ldap);
					return new WP_Error('invalid_username', __('<strong>ERROR</strong>: This user exists in LDAP, but has not been granted access to this installation of WordPress.', $this->ldap_auth_domain));
				}
			}
			
			@ldap_unbind($ldap);
			
			if ($this->authenticated && ($userdata = get_user_by('login', $username))) {
				return new WP_User($userdata->ID);
			}
			
			return false;
		}

		/*
		 * Skip the password check, since we've externally authenticated.
		 */
		function override_password_check( $check, $password, $hash, $user_id ) {
			if ( $this->authenticated == true )
				return true;
			else
				return $check;
		}

		/*
		 * Generate a password for the user. This plugin does not
		 * require the user to enter this value, but we want to set it
		 * to something nonobvious.
		 */
		function generate_password( $username, $password1, $password2 ) {
			$password1 = $password2 = $this->_get_password();
		}

		/*
		 * Used to disable certain display elements, e.g. password
		 * fields on profile screen.
		 */
		function disable_password_fields( $show_password_fields ) {
			return false;
		}

		/*
		 * Used to disable certain login functions, e.g. retrieving a
		 * user's password.
		 */
		function disable_function() {
			die('Disabled');
		}

		/*
		 * Add action link in the plugin page.
		 */
		function add_link($links, $file) {
			static $this_plugin;
			if ( !$this_plugin ) $this_plugin = plugin_basename(__FILE__);

			if ( $file === $this_plugin ) {
				$settings_link = '<a href="options-general.php?page=' . $this->ldap_auth_domain . '">' . _('Settings') . '</a>';
				array_unshift($links, $settings_link);
			}

			return($links);
		}

		/*
		 * Add custom style sheet to the admin page
		 */
		function add_admin_custom_css() {
			$style = WPMU_PLUGIN_URL . '/' . dirname(plugin_basename(__FILE__)) . '/extra-table.css';
			wp_register_style('ldap-auth-extra', $style, array('colors'));
			wp_enqueue_style('ldap-auth-extra');
		}

		/*
		 * Add custom script to the admin page
		 */
		function add_admin_script() {
			$script = WPMU_PLUGIN_URL . '/' . dirname(plugin_basename(__FILE__)) . '/extra-table.js';
			wp_register_script('ldap-auth-extra', $script, array('jquery-ui-dialog'));
			wp_enqueue_script('ldap-auth-extra');
		}

		/*************************************************************
		 * Functions
		 *************************************************************/

		/*
		 * Check the group includes the target user.
		 */
		function _user_in_group( $ldap, $username, $group ) {
			$base_dn = get_site_option('LDAP_authentication_base_dn');
			$group_filter = get_site_option('LDAP_authentication_group_filter');
			$group_attr = strtolower(get_site_option('LDAP_authentication_group_attribute'));
			$replace_count = 0;
			$group_filter = str_replace('%group%', $group, $group_filter, &$replace_count);
			if ( $replace_count == 0 ) {
				if ( defined('WP_DEBUG') && ( true === WP_DEBUG ) )
					trigger_error('LDAP group search filter is mistaked.');
				return false;
			}
			if ( !defined('WP_DEBUG') || ( defined('WP_DEBUG') && false === WP_DEBUG ) ) {
				$result = @ldap_search($ldap, $base_dn, $group_filter, array($group_attr));
			} else {
				trigger_error('Searching group in LDAP with \'' . $group_filter . '\' filter.');
				$result = ldap_search($ldap, $base_dn, $group_filter, array($group_attr));
			}
			if ( $result === FALSE ) return false;
			$members = @ldap_get_entries($ldap, $result);
			$members = $members[0][$group_attr];
			return in_array($username, $members);
		}

		/*
		 * Get the user's group info from LDAP and return the WordPress role.
		 */
		function _get_user_role_equiv( $ldap, $username ) {
			$role_equiv_groups = get_site_option('LDAP_authentication_role_equivalent_groups');
			$role_equiv_groups = explode(';', $role_equiv_groups);
			$user_role = '';
			foreach ( $role_equiv_groups as $role_group ) {
				if ( defined('WP_DEBUG') && ( true === WP_DEBUG ) )
					trigger_error('Trying \''  . $role_group . '\' rule.');
				$role_group = explode('=', $role_group);
				if ( count($role_group) != 2 )
					continue;
				$ldap_group = $role_group[0];
				$corresponding_role = $role_group[1];
				if ( $this->_user_in_group($ldap, $username, $ldap_group) ) {
					$user_role = $corresponding_role;
					break;
				}
			}
			if ( defined('WP_DEBUG') && ( true === WP_DEBUG ) )
				trigger_error('User \'' . $username . '\' is assigned as \'' . $user_role . '\' role.');
			return $user_role;
		}

		/*
		 * Generate a random password.
		 */
		function _get_password( $length = 10 ) {
			return substr(md5(uniqid(microtime())), 0, $length);
		}

		/*
		 * Create a new WordPress account for the specified username.
		 */
		function _create_user( $username, $email, $first_name, $last_name, $role = '' ) {
			$password = $this->_get_password();
			$email_domain = get_site_option('LDAP_authentication_default_email_domain');
			
			if ( $email == '' ) 
				$email = $username . '@' . $email_domain;
			
			require_once(ABSPATH . WPINC . DIRECTORY_SEPARATOR . 'registration.php');
			wp_create_user($username, $password, $email);
			$user_id = username_exists($username);
			if ( !$user_id ) {
				die('Error creating user!');
			} else {
				update_usermeta($user_id, 'first_name', $first_name);
				update_usermeta($user_id, 'last_name', $last_name);
				if ( $role != '' ) {
					if (is_multisite() && trim(strtolower($role)) == 'super admin') {
						require_once ABSPATH . 'wp-admin/includes/ms.php';
						wp_update_user(array('ID' => $user_id, 'user_level' => 10, 'role' => 'administrator'));
						grant_super_admin($user_id);
					}
					else {
						wp_update_user(array('ID' => $user_id, 'role' => $role));
					}
				}
			}
		}

		/*
		 * Reset already setted options in this plugin
		 */
		function _reset_options() {
			$all_options = array_filter(array_keys((array)get_alloptions()), create_function('$target', 'return ereg("^LDAP_authentication_", $target);'));
			foreach ( $all_options as $option ) {
				delete_site_option($option);
			}
			$this->initialize_options();
?>
<div id="message" class="updated fade"><p><strong><?php _e('Options reseted.', $this->ldap_auth_domain); ?></strong></p></div>
<?php
		}

		/*
		 * Display the options for this plugin.
		 */
		function _display_options_page() {
			if ( isset($_POST['reset_options']) )
				$this->_reset_options();
			
			if (isset($_POST['page_options'])) {
				$fields = explode(',', $_POST['page_options']);
				foreach ($fields as $field) {
					if (isset($_POST[$field])) {
						add_site_option($field, $_POST[$field]);
					}
				}
			}
			
			$ldap_server = get_site_option('LDAP_authentication_server');
			$use_ssl = get_site_option('LDAP_authentication_use_ssl');
			$base_dn = get_site_option('LDAP_authentication_base_dn');
			$role_equiv_groups = get_site_option('LDAP_authentication_role_equivalent_groups');
			$auto_create_user = (bool) get_site_option('LDAP_authentication_auto_create_user');
			$email_domain = get_site_option('LDAP_authentication_default_email_domain');
			$bind_dn = get_site_option('LDAP_authentication_bind_dn');
			$bind_password = get_site_option('LDAP_authentication_bind_password');
			$uid_filter = get_site_option('LDAP_authentication_uid_filter');
			$group_filter = get_site_option('LDAP_authentication_group_filter');
			$group_attr = get_site_option('LDAP_authentication_group_attribute');
?>


<div class="wrap">
	<h2><?php _e('Simple LDAP Authentication Options', $this->ldap_auth_domain); ?></h2>
	<form method="post">
		<input type="hidden" name="action" value="update" />
		<input type="hidden" name="page_options" value="LDAP_authentication_auto_create_user,LDAP_authentication_base_dn,LDAP_authentication_server,LDAP_authentication_use_ssl,LDAP_authentication_role_equivalent_groups,LDAP_authentication_default_email_domain,LDAP_authentication_bind_dn,LDAP_authentication_bind_password,LDAP_authentication_uid_filter,LDAP_authentication_group_filter,LDAP_authentication_group_attribute" />
		<?php if (function_exists('wp_nonce_field')): wp_nonce_field('update-options'); endif; ?>

		<table class="form-table">
			<tr valign="top">
				<th scope="row"><label for="LDAP_authentication_server"><?php _e('LDAP Server', $this->ldap_auth_domain); ?></label></th>
				<td>
					<input type="text" name="LDAP_authentication_server" id="LDAP_authentication_server" value="<?php echo $ldap_server; ?>" /><br />
					<?php _e('LDAP Server (e.g. <code>ldap.example.net</code>)', $this->ldap_auth_domain); ?>
				</td>
			</tr>
			<tr valign="top">
						  <th scope="row"><label for="LDAP_authentication_use_ssl"><?php _e('Use SSL connection with LDAP?', $this->ldap_auth_domain); ?></label></th>
				<td>
					<input type="checkbox" name="LDAP_authentication_use_ssl" id="LDAP_authentication_use_ssl"<?php if ($use_ssl) echo ' checked="checked"' ?> value="1" /><br />
					<?php _e('If you use SSL connection or not, when LDAP connection.', $this->ldap_auth_domain); ?>
				</td>
			</tr>
			<tr valign="top">
				<th scope="row"><label for="LDAP_authentication_base_dn"><?php _e('Base DN', $this->ldap_auth_domain); ?></label></th>
				<td>
					<input type="text" name="LDAP_authentication_base_dn" id="LDAP_authentication_base_dn" value="<?php echo $base_dn; ?>" /><br />
					<?php _e('Base DN (e.g., <code>dc=example,dc=net</code>)', $this->ldap_auth_domain); ?>
				</td>
			</tr>
			<tr valign="top">
				<th scope="row"><label for="LDAP_authentication_bind_dn"><?php _e('Bind DN', $this->ldap_auth_domain); ?></label></th>
				<td>
					<input type="text" name="LDAP_authentication_bind_dn" id="LDAP_authentication_bind_dn" value="<?php echo $bind_dn; ?>" /><br />
					<?php _e('Bind DN (e.g., <code>cn=proxyuser,dc=example,dc=net</code>)', $this->ldap_auth_domain); ?>
				</td>
			</tr>
			<tr valign="top">
				<th scope="row"><label for="LDAP_authentication_bind_password"><?php _e('Bind Password', $this->ldap_auth_domain); ?></label></th>
				<td>
					<input type="password" name="LDAP_authentication_bind_password" id="LDAP_authentication_bind_password" value="<?php echo $bind_password; ?>" /><br />
					<?php _e('Password for database login account.', $this->ldap_auth_domain); ?>
				</td>
			</tr>
			<tr valign="top">
				<th scope="row"><label for="LDAP_authentication_uid_filter"><?php _e('User ID Search Filter', $this->ldap_auth_domain); ?></label></th>
				<td>
					<input type="text" name="LDAP_authentication_uid_filter" id="LDAP_authentication_uid_filter" value="<?php echo $uid_filter; ?>" /><br />
					<?php _e('LDAP filter for searching user ID (e.g., <code>(uid=%user_id%)</code>)<br />
This setting must contain <code>%user_id%</code> string.', $this->ldap_auth_domain); ?>
				</td>
			</tr>
			<tr valign="top">
				<th scope="row"><label for="LDAP_authentication_group_filter"><?php _e('Group Search Filter', $this->ldap_auth_domain); ?></label></th>
				<td>
					<input type="text" name="LDAP_authentication_group_filter" id="LDAP_authentication_group_filter" value="<?php echo $group_filter; ?>" /><br />
					<?php _e('LDAP filter for searching group (e.g., <code>(cn=%group%)</code>)<br />
This setting must contain <code>%group%</code> string.', $this->ldap_auth_domain); ?>
				</td>
			</tr>
			<tr valign="top">
				<th scope="row"><label for="LDAP_authentication_group_attribute"><?php _e('Group Member Attribute', $this->ldap_auth_domain); ?></label></th>
				<td>
					<input type="text" name="LDAP_authentication_group_attribute" id="LDAP_authentication_group_attribute" value="<?php echo $group_attr; ?>" /><br />
					<?php _e('LDAP attribute for group member (e.g., <code>memberuid</code>)', $this->ldap_auth_domain); ?>
				</td>
			</tr>
			<tr valign="top">
				<th scope="row"><label for="LDAP_authentication_auto_create_user"><?php _e('Automatically create accounts for any and all users can authenticate to the LDAP?', $this->ldap_auth_domain); ?></label></th>
				<td>
					<input type="checkbox" name="LDAP_authentication_auto_create_user" id="LDAP_authentication_auto_create_user"<?php if ( $auto_create_user ) echo ' checked="checked"' ?> value="1" /><br />
					<?php _e('Should a new user be created automatically if not already in the WordPress database?<br />
Created users will obtain the role defined under &quot;New User Default Role&quot; on the <a href="options-general.php">General Options</a> page.
<br />
This setting is separate from the Role Equivalent Groups option, below.
<br />
<strong>Users with role equivalent groups will be created even if this setting is turned off</strong> (because if you didn\'t want this to happen, you would leave that option blank.)'); ?>
				</td>
			</tr>
			<tr valign="top">
				<th scope="row"><label for="LDAP_authentication_default_email_domain"><?php _e('Default email domain', $this->ldap_auth_domain); ?></label></th>
				<td>
					<input type="text" name="LDAP_authentication_default_email_domain" id="LDAP_authentication_default_email_domain" value="<?php echo $email_domain; ?>" /><br />
					<?php _e('If the LDAP attribute \'mail\' is blank, a user\'s email will be set to username@whatever-this-says', $this->ldap_auth_domain); ?>
				</td>
			</tr>
			<tr valign="top">
				<th scope="row"><label for="LDAP_authentication_role_equivalent_groups"><?php _e('Role Equivalent Groups', $this->ldap_auth_domain); ?></label></th>
				<td>
					<input type="text" name="LDAP_authentication_role_equivalent_groups" id="LDAP_authentication_role_equivalent_groups" value="<?php echo $role_equiv_groups; ?>" /><br />
					<?php _e('List of LDAP groups which correspond to WordPress user roles.<br />
When a user is first created, his role will correspond to what is specified here.<br />
Format: <code>LDAP-Group=WordPress-Role;LDAP-Group=WordPress-Role;...</code><br />
E.g., <code>Soc-Faculty=faculty</code> or <code>Faculty=faculty;Students=subscriber</code><br />
A user will be created based on the first math, from left to right, so you should obviously put the more powerful groups first.<br />
NOTE: WordPress stores roles as lower case ( Faculty is stored as faculty )<br />
ALSO NOTE: LDAP groups are case-sensitive', $this->ldap_auth_domain); ?>
				</td>
			</tr>
		</table>
		<input type="hidden" name="default_role" id="default_role" value="<?php echo get_site_option('default_role'); ?>" />
		<p class="submit">
			<input type="submit" name="Submit" value="<?php _e('Save Changes'); ?>" />
		</p>
	</form>
	<hr />
	<form action="" method="post">
		<p class="submit">
			<input type="submit" name="reset_options" value="<?php _e('Reset Options', $this->ldap_auth_domain); ?>" />
		</p>
	</form>
</div>
<div id="equivalent_dialog" title="<?php _e('Role Equivalent Groups Editor', $this->ldap_auth_domain); ?>" style="display: none" class="ui-widget">
	<table class="equivalent-table form-table">
		<thead>
			<tr align="center" class="ui-widget-header">
				<th scope="col"><?php _e('LDAP Group', $this->ldap_auth_domain); ?></th>
				<th scope="col"><?php _e('WordPress Role', $this->ldap_auth_domain); ?></th>
				<th scope="col"></th>
			</tr>
		</thead>
		<tbody>
			<tr valign="top" style="display: none">
				<td>
					<input type="text" />
				</td>
				<td>
					<select><?php wp_dropdown_roles(); // wp_dropdown_roles does stupid things with whitespace ?>

<?php if (is_multisite()): ?>
						<option value="super admin">Super Admin (Network Admin)</option>
<?php endif; ?>
					</select>
				</td>
				<td>
					<span class="submit">
						<input type="button" value="+" />
						<input type="button" value="-" />
						<input type="button" value="&uarr;" />
						<input type="button" value="&darr;" />
					</span>
				</td>
			</tr>
		</tbody>
	</table>
</div>
<?php
		}
	}
}

// Load the plugin hooks, etc.
$Ldap_authentication_plugin = new LdapAuthenticationPlugin();
