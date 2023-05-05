<?php  // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * This class extends the Abstract_Jetpack_Site class, which includes providing
 * the implementation for functions that were declared in that class.
 *
 * @see class.json-api-site-jetpack-base.php for more context on some of
 * the functions extended here.
 *
 * @package automattic/jetpack
 */
use Automattic\Jetpack\Status\Host;
use Automattic\Jetpack\Sync\Functions;

require_once __DIR__ . '/class.json-api-site-jetpack-base.php';
require_once __DIR__ . '/class.json-api-post-jetpack.php';

/**
 * Base class for Jetpack_Site. This code runs on Jetpack (.org) sites.
 */
class Jetpack_Site extends Abstract_Jetpack_Site {

	/**
	 * Retrieves a Jetpack option's value, given the option name.
	 *
	 * @param string $name the name of the Jetpack option, without the 'jetpack' prefix (eg. 'log' for 'jetpack_log').
	 *
	 * @return mixed
	 */
	protected function get_mock_option( $name ) {
		return get_option( 'jetpack_' . $name );
	}

	/**
	 * If a Jetpack constant name has been defined, this will return the value of the constant.
	 *
	 * @param string $name the name of the Jetpack constant to check.
	 *
	 * @return mixed
	 */
	protected function get_constant( $name ) {
		if ( defined( $name ) ) {
			return constant( $name );
		}
		return null;
	}

	/**
	 * Returns the site URL for the current network.
	 *
	 * @return string
	 */
	protected function main_network_site() {
		return network_site_url();
	}

	/**
	 * Returns the WordPress version for the current site.
	 *
	 * @return string
	 */
	protected function wp_version() {
		global $wp_version;
		return $wp_version;
	}

	/**
	 * Returns the maximum upload size allowed in php.ini.
	 *
	 * @return int
	 */
	protected function max_upload_size() {
		return wp_max_upload_size();
	}

	/**
	 * This function returns the value of the 'WP_MEMORY_LIMIT' constant converted to an integer byte value.
	 *
	 * @return int
	 */
	protected function wp_memory_limit() {
		return wp_convert_hr_to_bytes( WP_MEMORY_LIMIT );
	}

	/**
	 * This function returns the value of the 'WP_MAX_MEMORY_LIMIT' constant converted to an integer byte value.
	 *
	 * @return int
	 */
	protected function wp_max_memory_limit() {
		return wp_convert_hr_to_bytes( WP_MAX_MEMORY_LIMIT );
	}

	/**
	 * Returns true if the site is within a system with a multiple networks, false otherwise.
	 *
	 * @see /projects/packages/status/src/class-status.php
	 *
	 * @return bool
	 */
	protected function is_main_network() {
		return Jetpack::is_multi_network();
	}

	/**
	 * Returns true if Multisite is enabled, false otherwise.
	 *
	 * @return bool
	 */
	public function is_multisite() {
		return (bool) is_multisite();
	}

	/**
	 * Returns true if the current site is a single user site, false otherwise.
	 *
	 * @return bool
	 */
	public function is_single_user_site() {
		return (bool) Jetpack::is_single_user_site();
	}

	/**
	 * Returns true if is_vcs_checkout discovers a version control checkout, false otherwise.
	 *
	 * @see projects/packages/sync/src/class-functions.php.
	 *
	 * @return bool
	 */
	protected function is_version_controlled() {
		return Functions::is_version_controlled();
	}

	/**
	 * Returns true if the site has file write access, false otherwise.
	 *
	 * @see projects/packages/sync/src/class-functions.php.
	 *
	 * @return bool
	 */
	protected function file_system_write_access() {
		return Functions::file_system_write_access();
	}

	/**
	 * Returns true if the current theme supports the $feature_name, false otherwise.
	 *
	 * @param string $feature_name the name of the Jetpack feature.
	 *
	 * @return bool
	 */
	protected function current_theme_supports( $feature_name ) {
		return current_theme_supports( $feature_name );
	}

	/**
	 * Gets theme support arguments to be checked against the specific Jetpack feature.
	 *
	 * @param string $feature_name the name of the Jetpack feature to check against.
	 *
	 * @return array
	 */
	protected function get_theme_support( $feature_name ) {
		return get_theme_support( $feature_name );
	}

	/**
	 * Fetch a list of active plugins that are using Jetpack Connection.
	 *
	 * @return array An array of active plugins (by slug) that are using Jetpack Connection.
	 */
	protected function get_connection_active_plugins() {
		$plugins = $this->get_mock_option( 'connection_active_plugins' );

		return is_array( $plugins ) ? array_keys( $plugins ) : array();
	}

	/**
	 * Gets updates and then stores them in the jetpack_updates option, returning an array with the option schema.
	 *
	 * @return array
	 */
	public function get_updates() {
		return (array) Jetpack::get_updates();
	}

	/**
	 * Returns the Jetpack blog ID for a site.
	 *
	 * @return int
	 */
	public function get_id() {
		return $this->platform->token->blog_id;
	}

	/**
	 * Returns true if a site has the 'videopress' option enabled, false otherwise.
	 *
	 * @return bool
	 */
	public function has_videopress() {
		// TODO - this only works on wporg site - need to detect videopress option for remote Jetpack site on WPCOM.
		$videopress = Jetpack_Options::get_option( 'videopress', array() );
		if ( isset( $videopress['blog_id'] ) && $videopress['blog_id'] > 0 ) {
			return true;
		}

		return false;
	}

	/**
	 * Returns VideoPress storage used, in MB.
	 *
	 * @see class.json-api-site-jetpack-shadow.php on WordPress.com for implementation. Only applicable on WordPress.com.
	 *
	 * @return float
	 */
	public function get_videopress_storage_used() {
		return 0;
	}

	/**
	 * Sets the upgraded_filetypes_enabled Jetpack option to true as a default.
	 *
	 * Only relevant for WordPress.com sites:
	 * See wpcom_site_has_upgraded_upload_filetypes at /wpcom/wp-content/mu-plugins/misc.php.
	 *
	 * @return bool
	 */
	public function upgraded_filetypes_enabled() {
		return true;
	}

	/**
	 * Sets the is_mapped_domain Jetpack option to true as a default.
	 *
	 * Primarily used in WordPress.com to confirm the current blog's domain does or doesn't match the primary redirect.
	 *
	 * @see /wpcom/wp-content/mu-plugins/insecure-content-helpers.php within WordPress.com.
	 *
	 * @return bool
	 */
	public function is_mapped_domain() {
		return true;
	}

	/**
	 * Fallback to the home URL since all Jetpack sites don't have an unmapped *.wordpress.com domain.
	 *
	 * @return string
	 */
	public function get_unmapped_url() {
		// Fallback to the home URL since all Jetpack sites don't have an unmapped *.wordpress.com domain.
		return $this->get_url();
	}

	/**
	 * Whether the domain is a site redirect or not. Defaults to false on a Jetpack site.
	 *
	 * Primarily used in WordPress.com where it is determined if a HTTP status check is a redirect or not and whether an exception should be thrown.
	 *
	 * @see /wpcom/wp-includes/Requests/Response.php within WordPress.com.
	 *
	 * @return bool
	 */
	public function is_redirect() {
		return false;
	}

	/**
	 * Whether or not the current user is following this blog. Defaults to false.
	 *
	 * @return bool
	 */
	public function is_following() {
		return false;
	}

	/**
	 * Points to the user ID of the site owner
	 *
	 * @return null for Jetpack sites
	 */
	public function get_site_owner() {
		return null;
	}

	/**
	 * Whether or not the Jetpack 'wordads' module is active on the site.
	 *
	 * @return bool
	 */
	public function has_wordads() {
		return Jetpack::is_module_active( 'wordads' );
	}

	/**
	 * Defaults to false on Jetpack sites, however is used on WordPress.com sites. This nonce is used for previews on Jetpack sites.
	 *
	 * @see /wpcom/public.api/rest/sal/class.json-api-site-jetpack-shadow.php.
	 *
	 * @return bool
	 */
	public function get_frame_nonce() {
		return false;
	}

	/**
	 * Defaults to false on Jetpack sites, however is used on WordPress.com sites,
	 * where it creates a nonce to be used with iframed block editor requests to a Jetpack site.
	 *
	 * @see /wpcom/public.api/rest/sal/class.json-api-site-jetpack-shadow.php.
	 *
	 * @return bool
	 */
	public function get_jetpack_frame_nonce() {
		return false;
	}

	/**
	 * Defaults to false on Jetpack sites, however is used on WordPress.com sites, where it returns true if the headstart-fresh blog sticker is present.
	 *
	 * @see /wpcom/public.api/rest/sal/trait.json-api-site-wpcom.php.
	 *
	 * @return bool
	 */
	public function is_headstart_fresh() {
		return false;
	}

	/**
	 * Returns the allowed mime types and file extensions for a site.
	 *
	 * @return array
	 */
	public function allowed_file_types() {
		$allowed_file_types = array();

		// https://codex.wordpress.org/Uploading_Files.
		$mime_types = get_allowed_mime_types();
		foreach ( $mime_types as $type => $mime_type ) {
			$extras = explode( '|', $type );
			foreach ( $extras as $extra ) {
				$allowed_file_types[] = $extra;
			}
		}

		return $allowed_file_types;
	}

	/**
	 * Return site's privacy status.
	 *
	 * @return bool  Is site private?
	 */
	public function is_private() {
		return (int) $this->get_atomic_cloud_site_option( 'blog_public' ) === -1;
	}

	/**
	 * Return site's coming soon status.
	 *
	 * @return bool  Is site "Coming soon"?
	 */
	public function is_coming_soon() {
		return $this->is_private() && (int) $this->get_atomic_cloud_site_option( 'wpcom_coming_soon' ) === 1;
	}

	/**
	 * Return site's launch status.
	 *
	 * @return string|bool  Launch status ('launched', 'unlaunched', or false).
	 */
	public function get_launch_status() {
		return $this->get_atomic_cloud_site_option( 'launch-status' );
	}

	/**
	 * Given an option name, returns false if the site isn't WoA or doesn't have the ability to retrieve  cloud site options.
	 * Otherwise, if the option name exists amongst Jetpack options, the option value is returned.
	 *
	 * @param string $option The option name to check.
	 *
	 * @return string|bool
	 */
	public function get_atomic_cloud_site_option( $option ) {
		if ( ! ( new Host() )->is_woa_site() ) {
			return false;
		}

		$jetpack = Jetpack::init();
		if ( ! method_exists( $jetpack, 'get_cloud_site_options' ) ) {
			return false;
		}

		$result = $jetpack->get_cloud_site_options( array( $option ) );
		if ( ! array_key_exists( $option, $result ) ) {
			return false;
		}

		return $result[ $option ];
	}

	/**
	 * Defaults to false instead of returning the current site plan.
	 *
	 * @see /modules/masterbar/admin-menu/class-dashboard-switcher-tracking.php.
	 *
	 * @return bool
	 */
	public function get_plan() {
		return false;
	}

	/**
	 * Defaults to 0 for the number of WordPress.com subscribers - this is filled in on the WordPress.com side.
	 *
	 * @see /wpcom/public.api/rest/sal/trait.json-api-site-wpcom.php.
	 *
	 * @return int
	 */
	public function get_subscribers_count() {
		return 0;
	}

	/**
	 * Defaults to false - this is filled on the WordPress.com side in multiple locations.
	 *
	 * @return bool
	 */
	public function get_capabilities() {
		return false;
	}

	/**
	 * Returns the language code for the current site.
	 *
	 * @return string
	 */
	public function get_locale() {
		return get_bloginfo( 'language' );
	}

	/**
	 * The flag indicates that the site has Jetpack installed.
	 *
	 * @return bool
	 */
	public function is_jetpack() {
		return true;
	}

	/**
	 * The flag indicates that the site is connected to WP.com via Jetpack Connection.
	 *
	 * @return bool
	 */
	public function is_jetpack_connection() {
		return true;
	}

	/**
	 * Returns the current site's Jetpack version.
	 *
	 * @return string
	 */
	public function get_jetpack_version() {
		return JETPACK__VERSION;
	}

	/**
	 * Empty function declaration - this function is filled out on the WordPress.com side, returning true if the site has an AK / VP bundle.
	 *
	 * @see /wpcom/public.api/rest/sal/class.json-api-site-jetpack-shadow.php.
	 */
	public function get_ak_vp_bundle_enabled() {}

	/**
	 * Returns the front page meta description for current site.
	 *
	 * @see /modules/seo-tools/class-jetpack-seo-utils.php.
	 *
	 * @return string
	 */
	public function get_jetpack_seo_front_page_description() {
		return Jetpack_SEO_Utils::get_front_page_meta_description();
	}

	/**
	 * Returns custom title formats from site option.
	 *
	 * @see /modules/seo-tools/class-jetpack-seo-titles.php.
	 *
	 * @return array
	 */
	public function get_jetpack_seo_title_formats() {
		return Jetpack_SEO_Titles::get_custom_title_formats();
	}

	/**
	 * Returns website verification codes. Allowed keys include: google, pinterest, bing, yandex, facebook.
	 *
	 * @see /modules/verification-tools/blog-verification-tools.php.
	 *
	 * @return array
	 */
	public function get_verification_services_codes() {
		return get_option( 'verification_services_codes', null );
	}

	/**
	 * Returns null for Jetpack sites. For WordPress.com sites this returns the value of the 'podcasting_archive' option.
	 *
	 * @see /wpcom/public.api/rest/sal/class.json-api-site-wpcom.php.
	 *
	 * @return null
	 */
	public function get_podcasting_archive() {
		return null;
	}

	/**
	 * Defaulting to true, this function is expanded out on the WordPress.com side, returning an error if the site is not connected or not communicating to us.
	 *
	 * @see /wpcom/public.api/rest/sal/class.json-api-site-jetpack-shadow.php.
	 *
	 * @return bool
	 */
	public function is_connected_site() {
		return true;
	}

	/**
	 * Defaulting to false and not relevant for Jetpack sites, this is expanded on the WordPress.com side for a specific wp.com/start 'WP for teams' flow.
	 *
	 * @see /wpcom/public.api/rest/sal/class.json-api-site-wpcom.php.
	 *
	 * @return bool
	 */
	public function is_wpforteams_site() {
		return false;
	}

	/**
	 * Returns true if a user has got the capability that is being checked, false otherwise.
	 *
	 * @param string $role The capability to check.
	 *
	 * @return bool
	 */
	public function current_user_can( $role ) {
		return current_user_can( $role );
	}

	/**
	 * Check if full site editing should be considered as currently active. Full site editing
	 * requires the FSE plugin to be installed and activated, as well the current
	 * theme to be FSE compatible. The plugin can also be explicitly disabled via the
	 * a8c_disable_full_site_editing filter.
	 *
	 * @since 7.7.0
	 *
	 * @return bool true if full site editing is currently active.
	 */
	public function is_fse_active() {
		if ( ! Jetpack::is_plugin_active( 'full-site-editing/full-site-editing-plugin.php' ) ) {
			return false;
		}
		return function_exists( '\A8C\FSE\is_full_site_editing_active' ) && \A8C\FSE\is_full_site_editing_active();
	}

	/**
	 * Check if site should be considered as eligible for full site editing. Full site editing
	 * requires the FSE plugin to be installed and activated. For this method to return true
	 * the current theme does not need to be FSE compatible. The plugin can also be explicitly
	 * disabled via the a8c_disable_full_site_editing filter.
	 *
	 * @since 8.1.0
	 *
	 * @return bool true if site is eligible for full site editing
	 */
	public function is_fse_eligible() {
		if ( ! Jetpack::is_plugin_active( 'full-site-editing/full-site-editing-plugin.php' ) ) {
			return false;
		}
		return function_exists( '\A8C\FSE\is_site_eligible_for_full_site_editing' ) && \A8C\FSE\is_site_eligible_for_full_site_editing();
	}

	/**
	 * Check if site should be considered as eligible for use of the core Site Editor.
	 * The Site Editor requires a block based theme to be active.
	 *
	 * @return bool true if site is eligible for the Site Editor
	 */
	public function is_core_site_editor_enabled() {
		return function_exists( 'gutenberg_is_fse_theme' ) && gutenberg_is_fse_theme();
	}

	/**
	 * Return the last engine used for an import on the site. Not used in Jetpack.
	 *
	 * @see /wpcom/public.api/rest/sal/class.json-api-site-wpcom.php.
	 *
	 * @return null
	 */
	public function get_import_engine() {
		return null;
	}

	/**
	 * Post functions
	 */

	/**
	 * Wrap a WP_Post object with SAL methods, returning a Jetpack_Post object.
	 *
	 * @param WP_Post $post A WP_Post object.
	 * @param string  $context The post request context (for example 'edit' or 'display').
	 *
	 * @return Jetpack_Post
	 */
	public function wrap_post( $post, $context ) {
		return new Jetpack_Post( $this, $post, $context );
	}

	/**
	 * Get the option storing the Anchor podcast ID that identifies a site as a podcasting site.
	 *
	 * @return string
	 */
	public function get_anchor_podcast() {
		return $this->get_atomic_cloud_site_option( 'anchor_podcast' );
	}

	/**
	 * Get user interactions with a site. Not used in Jetpack.
	 *
	 * @see /wpcom/public.api/rest/sal/trait.json-api-site-wpcom.php.
	 *
	 * @return null
	 */
	public function get_user_interactions() {
		return null;
	}

	/**
	 * Get site option for the production blog id (if is a WP.com Staging Site). Not used in Jetpack.
	 *
	 * @see /wpcom/public.api/rest/sal/trait.json-api-site-wpcom.php.
	 *
	 * @return null
	 */
	public function get_wpcom_production_blog_id() {
		return null;
	}

	/**
	 * Get site option for the staging blog ids (if it has them). Not used in Jetpack.
	 *
	 * @see /wpcom/public.api/rest/sal/trait.json-api-site-wpcom.php.
	 *
	 * @return null
	 */
	public function get_wpcom_staging_blog_ids() {
		return null;
	}
}
