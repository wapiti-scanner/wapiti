<?php
/**
 * Plugins Library
 *
 * Helper functions for installing and activating plugins.
 *
 * Used by the REST API
 *
 * @package jetpack-plugins-installer
 */

namespace Automattic\Jetpack;

use Plugin_Upgrader;
use WP_Error;

/**
 * Plugins management tools.
 */
class Plugins_Installer {

	/**
	 * Ensures that plugins functions are loaded, as they are only loaded in admin context by default.
	 */
	private static function ensure_plugin_functions_are_loaded() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
	}
	/**
	 * Install and activate a plugin.
	 *
	 * @since-jetpack 5.8.0
	 *
	 * @param string $slug Plugin slug.
	 *
	 * @return bool|WP_Error True if installation succeeded, error object otherwise.
	 */
	public static function install_and_activate_plugin( $slug ) {
		$plugin_id = self::get_plugin_id_by_slug( $slug );

		if ( ! $plugin_id ) {
			$installed = self::install_plugin( $slug );
			if ( is_wp_error( $installed ) ) {
				return $installed;
			}
			$plugin_id = self::get_plugin_id_by_slug( $slug );
		} elseif ( self::is_plugin_active( $plugin_id ) ) {
			return true; // Already installed and active.
		}

		if ( ! current_user_can( 'activate_plugins' ) ) {
			return new WP_Error( 'not_allowed', __( 'You are not allowed to activate plugins on this site.', 'jetpack-plugins-installer' ) );
		}
		$activated = activate_plugin( $plugin_id );
		if ( is_wp_error( $activated ) ) {
			return $activated;
		}

		return true;
	}

	/**
	 * Install a plugin.
	 *
	 * @since-jetpack 5.8.0
	 *
	 * @param string $slug Plugin slug.
	 *
	 * @return bool|WP_Error True if installation succeeded, error object otherwise.
	 */
	public static function install_plugin( $slug ) {
		if ( is_multisite() && ! current_user_can( 'manage_network' ) ) {
			return new WP_Error( 'not_allowed', __( 'You are not allowed to install plugins on this site.', 'jetpack-plugins-installer' ) );
		}

		$skin     = new Automatic_Install_Skin();
		$upgrader = new Plugin_Upgrader( $skin );
		$zip_url  = self::generate_wordpress_org_plugin_download_link( $slug );
		$mc_stats = new A8c_Mc_Stats();

		$result = $upgrader->install( $zip_url );

		if ( is_wp_error( $result ) ) {
			$mc_stats->add( 'install-plugin', "fail-$slug" );
			return $result;
		}

		$plugin     = self::get_plugin_id_by_slug( $slug );
		$error_code = 'install_error';
		if ( ! $plugin ) {
			$error = __( 'There was an error installing your plugin', 'jetpack-plugins-installer' );
		}

		if ( ! $result ) {
			$error_code = $upgrader->skin->get_main_error_code();
			$message    = $upgrader->skin->get_main_error_message();
			$error      = $message ? $message : __( 'An unknown error occurred during installation', 'jetpack-plugins-installer' );
		}

		if ( ! empty( $error ) ) {
			if ( 'download_failed' === $error_code ) {
				// For backwards compatibility: versions prior to 3.9 would return no_package instead of download_failed.
				$error_code = 'no_package';
			}

			$mc_stats->add( 'install-plugin', "fail-$slug" );
			return new WP_Error( $error_code, $error, 400 );
		}

		$mc_stats->add( 'install-plugin', "success-$slug" );
		return (array) $upgrader->skin->get_upgrade_messages();
	}

	/**
	 * Get WordPress.org zip download link from a plugin slug
	 *
	 * @param string $plugin_slug Plugin slug.
	 */
	protected static function generate_wordpress_org_plugin_download_link( $plugin_slug ) {
		return "https://downloads.wordpress.org/plugin/$plugin_slug.latest-stable.zip";
	}

	/**
	 * Get the plugin ID (composed of the plugin slug and the name of the main plugin file) from a plugin slug.
	 *
	 * @param string $slug Plugin slug.
	 */
	public static function get_plugin_id_by_slug( $slug ) {
		// Check if get_plugins() function exists. This is required on the front end of the
		// site, since it is in a file that is normally only loaded in the admin.
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		/** This filter is documented in wp-admin/includes/class-wp-plugins-list-table.php */
		$plugins = apply_filters( 'all_plugins', get_plugins() );
		if ( ! is_array( $plugins ) ) {
			return false;
		}

		foreach ( $plugins as $plugin_file => $plugin_data ) {
			if ( self::get_slug_from_file_path( $plugin_file ) === $slug ) {
				return $plugin_file;
			}
		}

		return false;
	}

	/**
	 * Get the plugin slug from the plugin ID (composed of the plugin slug and the name of the main plugin file)
	 *
	 * @param string $plugin_file Plugin file (ID -- e.g. hello-dolly/hello.php).
	 */
	protected static function get_slug_from_file_path( $plugin_file ) {
		// Similar to get_plugin_slug() method.
		$slug = dirname( $plugin_file );
		if ( '.' === $slug ) {
			$slug = preg_replace( '/(.+)\.php$/', '$1', $plugin_file );
		}

		return $slug;
	}

	/**
	 * Get the activation status for a plugin.
	 *
	 * @since-jetpack 8.9.0
	 *
	 * @param string $plugin_file The plugin file to check.
	 * @return string Either 'network-active', 'active' or 'inactive'.
	 */
	public static function get_plugin_status( $plugin_file ) {
		if ( self::is_plugin_active_for_network( $plugin_file ) ) {
			return 'network-active';
		}

		if ( self::is_plugin_active( $plugin_file ) ) {
			return 'active';
		}

		return 'inactive';
	}

	/**
	 * Safely checks if the plugin is active
	 *
	 * @since $next-version$
	 *
	 * @param string $plugin_file The plugin file to check.
	 * @return bool
	 */
	public static function is_plugin_active( $plugin_file ) {
		self::ensure_plugin_functions_are_loaded();
		return is_plugin_active( $plugin_file );
	}

	/**
	 * Safely checks if the plugin is active for network
	 *
	 * @since $next-version$
	 *
	 * @param string $plugin_file The plugin file to check.
	 * @return bool
	 */
	public static function is_plugin_active_for_network( $plugin_file ) {
		self::ensure_plugin_functions_are_loaded();
		return is_plugin_active_for_network( $plugin_file );
	}

	/**
	 * Returns a list of all plugins in the site.
	 *
	 * @since-jetpack 8.9.0
	 * @uses get_plugins()
	 *
	 * @return array
	 */
	public static function get_plugins() {
		self::ensure_plugin_functions_are_loaded();
		/** This filter is documented in wp-admin/includes/class-wp-plugins-list-table.php */
		$plugins = apply_filters( 'all_plugins', get_plugins() );

		if ( is_array( $plugins ) && ! empty( $plugins ) ) {
			foreach ( $plugins as $plugin_slug => $plugin_data ) {
				$plugins[ $plugin_slug ]['active'] = in_array(
					self::get_plugin_status( $plugin_slug ),
					array( 'active', 'network-active' ),
					true
				);
			}
			return $plugins;
		}

		return array();
	}

	/**
	 * Determine if the current request is activating a plugin from the plugins page.
	 *
	 * @param string $plugin Plugin file path to check.
	 * @return bool
	 */
	public static function is_current_request_activating_plugin_from_plugins_screen( $plugin ) {
		// Filter out common async request contexts
		if (
			wp_doing_ajax() ||
			( defined( 'REST_REQUEST' ) && REST_REQUEST ) ||
			( defined( 'REST_API_REQUEST' ) && REST_API_REQUEST ) ||
			( defined( 'WP_CLI' ) && WP_CLI )
		) {
			return false;
		}

		if ( isset( $_SERVER['SCRIPT_NAME'] ) ) {
			$request_file = esc_url_raw( wp_unslash( $_SERVER['SCRIPT_NAME'] ) );
		} elseif ( isset( $_SERVER['REQUEST_URI'] ) ) {
			list( $request_file ) = explode( '?', esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) );
		} else {
			return false;
		}

		// Not the plugins page
		if ( strpos( $request_file, 'wp-admin/plugins.php' ) === false ) {
			return false;
		}

		// Same method to get the action as used by plugins.php
		$wp_list_table = _get_list_table( 'WP_Plugins_List_Table' );
		$action        = $wp_list_table->current_action();

		// Not a singular activation
		// This also means that if the plugin is activated as part of a group ( bulk activation ), this function will return false here.
		if ( 'activate' !== $action ) {
			return false;
		}

		// Check the nonce associated with the plugin activation
		// We are not changing any data here, so this is not super necessary, it's just a best practice before using the form data from $_REQUEST.
		check_admin_referer( 'activate-plugin_' . $plugin );

		// Not the right plugin
		$requested_plugin = isset( $_REQUEST['plugin'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['plugin'] ) ) : null;
		if ( $requested_plugin !== $plugin ) {
			return false;
		}

		return true;
	}
}
