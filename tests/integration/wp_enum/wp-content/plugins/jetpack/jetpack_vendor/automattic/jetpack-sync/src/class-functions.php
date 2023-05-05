<?php
/**
 * Utility functions to generate data synced to wpcom
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync;

use Automattic\Jetpack\Connection\Urls;
use Automattic\Jetpack\Constants;
use Automattic\Jetpack\Modules as Jetpack_Modules;

/**
 * Utility functions to generate data synced to wpcom
 */
class Functions {
	const HTTPS_CHECK_OPTION_PREFIX = 'jetpack_sync_https_history_';
	const HTTPS_CHECK_HISTORY       = 5;

	/**
	 * Return array of Jetpack modules.
	 *
	 * @return array
	 */
	public static function get_modules() {
		if ( defined( 'JETPACK__PLUGIN_DIR' ) ) {
			require_once JETPACK__PLUGIN_DIR . 'class.jetpack-admin.php';

			return \Jetpack_Admin::init()->get_modules();
		}

		return array();
	}

	/**
	 * Return array of taxonomies registered on the site.
	 *
	 * @return array
	 */
	public static function get_taxonomies() {
		global $wp_taxonomies;
		$wp_taxonomies_without_callbacks = array();
		foreach ( $wp_taxonomies as $taxonomy_name => $taxonomy ) {
			$sanitized_taxonomy = self::sanitize_taxonomy( $taxonomy );
			if ( ! empty( $sanitized_taxonomy ) ) {
				$wp_taxonomies_without_callbacks[ $taxonomy_name ] = $sanitized_taxonomy;
			}
		}
		return $wp_taxonomies_without_callbacks;
	}

	/**
	 * Return array of registered shortcodes.
	 *
	 * @return array
	 */
	public static function get_shortcodes() {
		global $shortcode_tags;
		return array_keys( $shortcode_tags );
	}

	/**
	 * Removes any callback data since we will not be able to process it on our side anyways.
	 *
	 * @param \WP_Taxonomy $taxonomy \WP_Taxonomy item.
	 *
	 * @return mixed|null
	 */
	public static function sanitize_taxonomy( $taxonomy ) {

		// Lets clone the taxonomy object instead of modifing the global one.
		$cloned_taxonomy = json_decode( wp_json_encode( $taxonomy ) );

		// recursive taxonomies are no fun.
		if ( $cloned_taxonomy === null ) {
			return null;
		}
		// Remove any meta_box_cb if they are not the default wp ones.
		if ( isset( $cloned_taxonomy->meta_box_cb ) &&
			! in_array( $cloned_taxonomy->meta_box_cb, array( 'post_tags_meta_box', 'post_categories_meta_box' ), true ) ) {
			$cloned_taxonomy->meta_box_cb = null;
		}
		// Remove update call back.
		if ( isset( $cloned_taxonomy->update_count_callback ) &&
			$cloned_taxonomy->update_count_callback !== null ) {
			$cloned_taxonomy->update_count_callback = null;
		}
		// Remove rest_controller_class if it something other then the default.
		if ( isset( $cloned_taxonomy->rest_controller_class ) &&
			'WP_REST_Terms_Controller' !== $cloned_taxonomy->rest_controller_class ) {
			$cloned_taxonomy->rest_controller_class = null;
		}
		return $cloned_taxonomy;
	}

	/**
	 * Return array of registered post types.
	 *
	 * @return array
	 */
	public static function get_post_types() {
		global $wp_post_types;

		$post_types_without_callbacks = array();
		foreach ( $wp_post_types as $post_type_name => $post_type ) {
			$sanitized_post_type = self::sanitize_post_type( $post_type );
			if ( ! empty( $sanitized_post_type ) ) {
				$post_types_without_callbacks[ $post_type_name ] = $sanitized_post_type;
			}
		}
		return $post_types_without_callbacks;
	}

	/**
	 * Sanitizes by cloning post type object.
	 *
	 * @param object $post_type \WP_Post_Type.
	 *
	 * @return object
	 */
	public static function sanitize_post_type( $post_type ) {
		// Lets clone the post type object instead of modifing the global one.
		$sanitized_post_type = array();
		foreach ( Defaults::$default_post_type_attributes as $attribute_key => $default_value ) {
			if ( isset( $post_type->{ $attribute_key } ) ) {
				$sanitized_post_type[ $attribute_key ] = $post_type->{ $attribute_key };
			}
		}
		return (object) $sanitized_post_type;
	}

	/**
	 * Return information about a synced post type.
	 *
	 * @param array  $sanitized_post_type Array of args used in constructing \WP_Post_Type.
	 * @param string $post_type Post type name.
	 *
	 * @return object \WP_Post_Type
	 */
	public static function expand_synced_post_type( $sanitized_post_type, $post_type ) {
		$post_type        = sanitize_key( $post_type );
		$post_type_object = new \WP_Post_Type( $post_type, $sanitized_post_type );
		$post_type_object->add_supports();
		$post_type_object->add_rewrite_rules();
		$post_type_object->add_hooks();
		$post_type_object->register_taxonomies();
		return (object) $post_type_object;
	}

	/**
	 * Returns site's post_type_features.
	 *
	 * @return array
	 */
	public static function get_post_type_features() {
		global $_wp_post_type_features;

		return $_wp_post_type_features;
	}

	/**
	 * Return hosting provider.
	 *
	 * Uses a set of known constants, classes, or functions to help determine the hosting platform.
	 *
	 * @return string Hosting provider.
	 */
	public static function get_hosting_provider() {
		$hosting_provider_detection_methods = array(
			'get_hosting_provider_by_known_constant',
			'get_hosting_provider_by_known_class',
			'get_hosting_provider_by_known_function',
		);

		$functions = new Functions();
		foreach ( $hosting_provider_detection_methods as $method ) {
			$hosting_provider = call_user_func( array( $functions, $method ) );
			if ( false !== $hosting_provider ) {
				return $hosting_provider;
			}
		}

		return 'unknown';
	}

	/**
	 * Return a hosting provider using a set of known constants.
	 *
	 * @return mixed A host identifier string or false.
	 */
	public function get_hosting_provider_by_known_constant() {
		$hosting_provider_constants = array(
			'GD_SYSTEM_PLUGIN_DIR' => 'gd-managed-wp',
			'MM_BASE_DIR'          => 'bh',
			'PAGELYBIN'            => 'pagely',
			'KINSTAMU_VERSION'     => 'kinsta',
			'FLYWHEEL_CONFIG_DIR'  => 'flywheel',
			'IS_PRESSABLE'         => 'pressable',
			'VIP_GO_ENV'           => 'vip-go',
		);

		foreach ( $hosting_provider_constants as $constant => $constant_value ) {
			if ( Constants::is_defined( $constant ) ) {
				if ( 'VIP_GO_ENV' === $constant && false === Constants::get_constant( 'VIP_GO_ENV' ) ) {
					continue;
				}
				return $constant_value;
			}
		}

		return false;
	}

	/**
	 * Return a hosting provider using a set of known classes.
	 *
	 * @return mixed A host identifier string or false.
	 */
	public function get_hosting_provider_by_known_class() {
		$hosting_provider = false;

		switch ( true ) {
			case ( class_exists( '\\WPaaS\\Plugin' ) ):
				$hosting_provider = 'gd-managed-wp';
				break;
		}

		return $hosting_provider;
	}

	/**
	 * Return a hosting provider using a set of known functions.
	 *
	 * @return mixed A host identifier string or false.
	 */
	public function get_hosting_provider_by_known_function() {
		$hosting_provider = false;

		switch ( true ) {
			case ( function_exists( 'is_wpe' ) || function_exists( 'is_wpe_snapshot' ) ):
				$hosting_provider = 'wpe';
				break;
		}

		return $hosting_provider;
	}

	/**
	 * Return array of allowed REST API post types.
	 *
	 * @return array Array of allowed post types.
	 */
	public static function rest_api_allowed_post_types() {
		/** This filter is already documented in class.json-api-endpoints.php */
		return apply_filters( 'rest_api_allowed_post_types', array( 'post', 'page', 'revision' ) );
	}

	/**
	 * Return array of allowed REST API public metadata.
	 *
	 * @return array Array of allowed metadata.
	 */
	public static function rest_api_allowed_public_metadata() {
		/**
		 * Filters the meta keys accessible by the REST API.
		 *
		 * @see https://developer.wordpress.com/2013/04/26/custom-post-type-and-metadata-support-in-the-rest-api/
		 *
		 * @module json-api
		 *
		 * @since 1.6.3
		 * @since-jetpack 2.2.3
		 *
		 * @param array $whitelisted_meta Array of metadata that is accessible by the REST API.
		 */
		return apply_filters( 'rest_api_allowed_public_metadata', array() );
	}

	/**
	 * Finds out if a site is using a version control system.
	 *
	 * @return bool
	 **/
	public static function is_version_controlled() {

		if ( ! class_exists( 'WP_Automatic_Updater' ) ) {
			require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		}
		$updater = new \WP_Automatic_Updater();

		return (bool) (string) $updater->is_vcs_checkout( ABSPATH );
	}

	/**
	 * Returns true if the site has file write access false otherwise.
	 *
	 * @return bool
	 **/
	public static function file_system_write_access() {
		if ( ! function_exists( 'get_filesystem_method' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		require_once ABSPATH . 'wp-admin/includes/template.php';

		$filesystem_method = get_filesystem_method();
		if ( 'direct' === $filesystem_method ) {
			return true;
		}

		ob_start();

		if ( ! function_exists( 'request_filesystem_credentials' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		$filesystem_credentials_are_stored = request_filesystem_credentials( self_admin_url() );
		ob_end_clean();
		if ( $filesystem_credentials_are_stored ) {
			return true;
		}

		return false;
	}

	/**
	 * Helper function that is used when getting home or siteurl values. Decides
	 * whether to get the raw or filtered value.
	 *
	 * @deprecated 1.23.1
	 *
	 * @param string $url_type URL to get, home or siteurl.
	 * @return string
	 */
	public static function get_raw_or_filtered_url( $url_type ) {
		_deprecated_function( __METHOD__, '1.23.1', '\\Automattic\\Jetpack\\Connection\\Urls::get_raw_or_filtered_url' );
		return Urls::get_raw_or_filtered_url( $url_type );
	}

	/**
	 * Return the escaped home_url.
	 *
	 * @deprecated 1.23.1
	 *
	 * @return string
	 */
	public static function home_url() {
		_deprecated_function( __METHOD__, '1.23.1', '\\Automattic\\Jetpack\\Connection\\Urls::home_url' );
		return Urls::home_url();
	}

	/**
	 * Return the escaped siteurl.
	 *
	 * @deprecated 1.23.1
	 *
	 * @return string
	 */
	public static function site_url() {
		_deprecated_function( __METHOD__, '1.23.1', '\\Automattic\\Jetpack\\Connection\\Urls::site_url' );
		return Urls::site_url();
	}

	/**
	 * Return main site URL with a normalized protocol.
	 *
	 * @deprecated 1.23.1
	 *
	 * @return string
	 */
	public static function main_network_site_url() {
		_deprecated_function( __METHOD__, '1.23.1', '\\Automattic\\Jetpack\\Connection\\Urls::main_network_site_url' );
		return Urls::main_network_site_url();
	}

	/**
	 * Return main site WordPress.com site ID.
	 *
	 * @return string
	 */
	public static function main_network_site_wpcom_id() {
		/**
		 * Return the current site WPCOM ID for single site installs
		 */
		if ( ! is_multisite() ) {
			return \Jetpack_Options::get_option( 'id' );
		}

		/**
		 * Return the main network site WPCOM ID for multi-site installs
		 */
		$current_network = get_network();
		switch_to_blog( $current_network->blog_id );
		$wpcom_blog_id = \Jetpack_Options::get_option( 'id' );
		restore_current_blog();
		return $wpcom_blog_id;
	}

	/**
	 * Return URL with a normalized protocol.
	 *
	 * @deprecated 1.23.1
	 *
	 * @param callable $callable Function to retrieve URL option.
	 * @param string   $new_value URL Protocol to set URLs to.
	 * @return string Normalized URL.
	 */
	public static function get_protocol_normalized_url( $callable, $new_value ) {
		_deprecated_function( __METHOD__, '1.23.1', '\\Automattic\\Jetpack\\Connection\\Urls::get_protocol_normalized_url' );
		return Urls::get_protocol_normalized_url( $callable, $new_value );
	}

	/**
	 * Return URL from option or PHP constant.
	 *
	 * @deprecated 1.23.1
	 *
	 * @param string $option_name (e.g. 'home').
	 *
	 * @return mixed|null URL.
	 */
	public static function get_raw_url( $option_name ) {
		_deprecated_function( __METHOD__, '1.23.1', '\\Automattic\\Jetpack\\Connection\\Urls::get_raw_url' );
		return Urls::get_raw_url( $option_name );
	}

	/**
	 * Normalize domains by removing www unless declared in the site's option.
	 *
	 * @deprecated 1.23.1
	 *
	 * @param string   $option Option value from the site.
	 * @param callable $url_function Function retrieving the URL to normalize.
	 * @return mixed|string URL.
	 */
	public static function normalize_www_in_url( $option, $url_function ) {
		_deprecated_function( __METHOD__, '1.23.1', '\\Automattic\\Jetpack\\Connection\\Urls::normalize_www_in_url' );
		return Urls::normalize_www_in_url( $option, $url_function );
	}

	/**
	 * Return filtered value of get_plugins.
	 *
	 * @return mixed|void
	 */
	public static function get_plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		/** This filter is documented in wp-admin/includes/class-wp-plugins-list-table.php */
		return apply_filters( 'all_plugins', get_plugins() );
	}

	/**
	 * Get custom action link tags that the plugin is using
	 * Ref: https://codex.wordpress.org/Plugin_API/Filter_Reference/plugin_action_links_(plugin_file_name)
	 *
	 * @param string $plugin_file_singular Particular plugin.
	 * @return array of plugin action links (key: link name value: url)
	 */
	public static function get_plugins_action_links( $plugin_file_singular = null ) {
		// Some sites may have DOM disabled in PHP fail early.
		if ( ! class_exists( 'DOMDocument' ) ) {
			return array();
		}
		$plugins_action_links = get_option( 'jetpack_plugin_api_action_links', array() );
		if ( ! empty( $plugins_action_links ) ) {
			if ( $plugin_file_singular === null ) {
				return $plugins_action_links;
			}
			return ( isset( $plugins_action_links[ $plugin_file_singular ] ) ? $plugins_action_links[ $plugin_file_singular ] : null );
		}
		return array();
	}

	/**
	 * Return the WP version as defined in the $wp_version global.
	 *
	 * @return string
	 */
	public static function wp_version() {
		global $wp_version;
		return $wp_version;
	}

	/**
	 * Return site icon url used on the site.
	 *
	 * @param int $size Size of requested icon in pixels.
	 * @return mixed|string|void
	 */
	public static function site_icon_url( $size = 512 ) {
		$site_icon = get_site_icon_url( $size );
		return $site_icon ? $site_icon : get_option( 'jetpack_site_icon_url' );
	}

	/**
	 * Return roles registered on the site.
	 *
	 * @return array
	 */
	public static function roles() {
		$wp_roles = wp_roles();
		return $wp_roles->roles;
	}

	/**
	 * Determine time zone from WordPress' options "timezone_string"
	 * and "gmt_offset".
	 *
	 * 1. Check if `timezone_string` is set and return it.
	 * 2. Check if `gmt_offset` is set, formats UTC-offset from it and return it.
	 * 3. Default to "UTC+0" if nothing is set.
	 *
	 * Note: This function is specifically not using wp_timezone() to keep consistency with
	 * the existing formatting of the timezone string.
	 *
	 * @return string
	 */
	public static function get_timezone() {
		$timezone_string = get_option( 'timezone_string' );

		if ( ! empty( $timezone_string ) ) {
			return str_replace( '_', ' ', $timezone_string );
		}

		$gmt_offset = get_option( 'gmt_offset', 0 );

		$formatted_gmt_offset = sprintf( '%+g', (float) $gmt_offset );

		$formatted_gmt_offset = str_replace(
			array( '.25', '.5', '.75' ),
			array( ':15', ':30', ':45' ),
			(string) $formatted_gmt_offset
		);

		/* translators: %s is UTC offset, e.g. "+1" */
		return sprintf( __( 'UTC%s', 'jetpack-sync' ), $formatted_gmt_offset );
	}

	/**
	 * Return list of paused themes.
	 *
	 * @return array|bool Array of paused themes or false if unsupported.
	 */
	public static function get_paused_themes() {
		$paused_themes = wp_paused_themes();
		return $paused_themes->get_all();
	}

	/**
	 * Return list of paused plugins.
	 *
	 * @return array|bool Array of paused plugins or false if unsupported.
	 */
	public static function get_paused_plugins() {
		$paused_plugins = wp_paused_plugins();
		return $paused_plugins->get_all();
	}

	/**
	 * Return the theme's supported features.
	 * Used for syncing the supported feature that we care about.
	 *
	 * @return array List of features that the theme supports.
	 */
	public static function get_theme_support() {
		global $_wp_theme_features;

		$theme_support = array();
		foreach ( Defaults::$default_theme_support_whitelist as $theme_feature ) {
			$has_support = current_theme_supports( $theme_feature );
			if ( $has_support ) {
				$theme_support[ $theme_feature ] = $_wp_theme_features[ $theme_feature ];
			}
		}

		return $theme_support;
	}

	/**
	 * Returns if the current theme is a Full Site Editing theme.
	 *
	 * @return bool Theme is a Full Site Editing theme.
	 */
	public static function get_is_fse_theme() {
		return function_exists( 'gutenberg_is_fse_theme' ) && gutenberg_is_fse_theme();
	}

	/**
	 * Wraps data in a way so that we can distinguish between objects and array and also prevent object recursion.
	 *
	 * @since 1.21.0
	 *
	 * @param array|obj $any        Source data to be cleaned up.
	 * @param array     $seen_nodes Built array of nodes.
	 *
	 * @return array
	 */
	public static function json_wrap( &$any, $seen_nodes = array() ) {
		if ( is_object( $any ) ) {
			$input        = get_object_vars( $any );
			$input['__o'] = 1;
		} else {
			$input = &$any;
		}

		if ( is_array( $input ) ) {
			$seen_nodes[] = &$any;

			$return = array();

			foreach ( $input as $k => &$v ) {
				if ( ( is_array( $v ) || is_object( $v ) ) ) {
					if ( in_array( $v, $seen_nodes, true ) ) {
						continue;
					}
					$return[ $k ] = self::json_wrap( $v, $seen_nodes );
				} else {
					$return[ $k ] = $v;
				}
			}

			return $return;
		}

		return $any;
	}

	/**
	 * Return the list of installed themes
	 *
	 * @since 1.31.0
	 *
	 * @return array
	 */
	public static function get_themes() {
		$current_stylesheet = get_stylesheet();
		$installed_themes   = wp_get_themes();
		$synced_headers     = array( 'Name', 'ThemeURI', 'Author', 'Version', 'Template', 'Status', 'TextDomain', 'RequiresWP', 'RequiresPHP' );
		$themes             = array();
		foreach ( $installed_themes as $stylesheet => $theme ) {
			$themes[ $stylesheet ] = array();
			foreach ( $synced_headers as $header ) {
				$themes[ $stylesheet ][ $header ] = $theme->get( $header );
			}
			$themes[ $stylesheet ]['active'] = $stylesheet === $current_stylesheet;
			if ( method_exists( $theme, 'is_block_theme' ) ) {
				$themes[ $stylesheet ]['is_block_theme'] = $theme->is_block_theme();
			}
		}
		/**
		 * Filters the output of Sync's get_theme callable
		 *
		 * @since 1.31.0
		 *
		 * @param array $themes The list of installed themes formatted in an array with a collection of information extracted from the Theme's headers
		 */
		return apply_filters( 'jetpack_sync_get_themes_callable', $themes );
	}

	/**
	 * Return the list of active Jetpack modules.
	 *
	 * @since $$next_version$$
	 *
	 * @return array
	 */
	public static function get_active_modules() {
		return ( new Jetpack_Modules() )->get_active();
	}
}
