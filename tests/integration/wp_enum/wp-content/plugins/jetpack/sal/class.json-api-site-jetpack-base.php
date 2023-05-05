<?php  // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * This class extends the SAL_Site class, providing the implementation for
 * functions that were declared in that SAL_Site class as well as defining
 * base functions to be implemented in class Jetpack_Site.
 *
 * @see class.json-api-site-jetpack.php for more context on
 * the functions extended here.
 *
 * @package automattic/jetpack
 */
require_once __DIR__ . '/class.json-api-site-base.php';

/**
 * Base class for Abstract_Jetpack_Site.
 */
abstract class Abstract_Jetpack_Site extends SAL_Site {

	/**
	 * Defining a base get_constant() function to be extended in the Jetpack_Site class.
	 *
	 * If a Jetpack constant name has been defined, this will return the value of the constant.
	 *
	 * @param string $name the name of the Jetpack constant to check.
	 */
	abstract protected function get_constant( $name );

	/**
	 * Defining a base current_theme_supports() function to be extended in the Jetpack_Site class.
	 *
	 * Returns true if the current theme supports the $feature_name, false otherwise.
	 *
	 * @param string $feature_name the name of the Jetpack feature.
	 */
	abstract protected function current_theme_supports( $feature_name );

	/**
	 * Defining a base get_theme_support() function to be extended in the Jetpack_Site class.
	 *
	 * Gets theme support arguments to be checked against the specific Jetpack feature.
	 *
	 * @param string $feature_name the name of the Jetpack feature to check against.
	 */
	abstract protected function get_theme_support( $feature_name );

	/**
	 * Defining a base get_mock_option() function to be extended in the Jetpack_Site class.
	 *
	 * Retrieves a Jetpack option's value, given the option name.
	 *
	 * @param string $name the name of the Jetpack option, without the 'jetpack' prefix (eg. 'log' for 'jetpack_log').
	 */
	abstract protected function get_mock_option( $name );

	/**
	 * Defining a base get_jetpack_version() function to be extended in the Jetpack_Site class.
	 *
	 * Returns the current Jetpack version number.
	 */
	abstract public function get_jetpack_version();

	/**
	 * Defining a base get_updates() function to be extended in the Jetpack_Site class.
	 *
	 * Gets updates and then stores them in the jetpack_updates option, returning an array with the option schema.
	 */
	abstract public function get_updates();

	/**
	 * Defining a base main_network_site() function to be extended in the Jetpack_Site class.
	 *
	 * Returns the site URL for the current network.
	 */
	abstract protected function main_network_site();

	/**
	 * Defining a base wp_version() function to be extended in the Jetpack_Site class.
	 *
	 * Returns the WordPress version for the current site.
	 */
	abstract protected function wp_version();

	/**
	 * Defining a base max_upload_size() function to be extended in the Jetpack_Site class.
	 *
	 * Returns the maximum upload size allowed in php.ini.
	 */
	abstract protected function max_upload_size();

	/**
	 * Defining a base is_main_network() function to be extended in the Jetpack_Site class.
	 *
	 * Returns true if the site is within a system with a multiple networks, false otherwise.
	 *
	 * @see /projects/packages/status/src/class-status.php.
	 */
	abstract protected function is_main_network();

	/**
	 * Defining a base is_version_controlled() function to be extended in the Jetpack_Site class.
	 *
	 * Returns true if is_vcs_checkout discovers a version control checkout, false otherwise.
	 *
	 * @see projects/packages/sync/src/class-functions.php.
	 */
	abstract protected function is_version_controlled();

	/**
	 * Defining a base file_system_write_access() function to be extended in the Jetpack_Site class.
	 *
	 * Returns true if the site has file write access false otherwise.
	 *
	 * @see projects/packages/sync/src/class-functions.php.
	 */
	abstract protected function file_system_write_access();

	/**
	 * Fetch a list of active plugins that are using Jetpack Connection.
	 */
	abstract protected function get_connection_active_plugins();

	/**
	 * This function is implemented on WPCom sites, where a filter is removed which forces the URL to http.
	 *
	 * @see /wpcom/public.api/rest/sal/class.json-api-site-jetpack-shadow.php.
	 */
	public function before_render() {
	}

	/**
	 * This function returns the value of the 'WP_MEMORY_LIMIT' constant.
	 *
	 * @return int|string
	 */
	protected function wp_memory_limit() {
		return $this->get_constant( 'WP_MEMORY_LIMIT' );
	}

	/**
	 * This function returns the value of the 'WP_MAX_MEMORY_LIMIT' constant.
	 *
	 * @return int|string
	 */
	protected function wp_max_memory_limit() {
		return $this->get_constant( 'WP_MAX_MEMORY_LIMIT' );
	}

	/**
	 * If a user has manage options permissions and the site is the main site of the network, make updates visible.
	 *
	 * Called after response_keys have been rendered, which itself is used to return all the necessary information for a site’s response.
	 *
	 * @param array $response an array of the response keys.
	 */
	public function after_render( &$response ) {
		if ( current_user_can( 'manage_options' ) && $this->is_main_site( $response ) ) {
			$jetpack_update = $this->get_updates();
			if ( ! empty( $jetpack_update ) ) {
				// In previous version of Jetpack 3.4, 3.5, 3.6 we synced the wp_version into to jetpack_updates.
				unset( $jetpack_update['wp_version'] );
				// In previous version of Jetpack 3.4, 3.5, 3.6 we synced the site_is_version_controlled into to jetpack_updates.
				unset( $jetpack_update['site_is_version_controlled'] );

				$response['updates'] = $jetpack_update;
			}
		}
	}

	/**
	 * Extends the Jetpack options array with details including site constraints, WordPress and Jetpack versions, and plugins using the Jetpack connection.
	 *
	 * @param array $options an array of the Jetpack options.
	 */
	public function after_render_options( &$options ) {
		$options['jetpack_version'] = $this->get_jetpack_version();

		$main_network_site = $this->main_network_site();
		if ( $main_network_site ) {
			$options['main_network_site'] = (string) rtrim( $main_network_site, '/' );
		}

		$active_modules = Jetpack_Options::get_option( 'active_modules' );
		if ( is_array( $active_modules ) ) {
			$options['active_modules'] = (array) array_values( $active_modules );
		}

		$options['software_version']    = (string) $this->wp_version();
		$options['max_upload_size']     = $this->max_upload_size();
		$options['wp_memory_limit']     = $this->wp_memory_limit();
		$options['wp_max_memory_limit'] = $this->wp_max_memory_limit();

		// Sites have to prove that they are not main_network site.
		// If the sync happends right then we should be able to see that we are not dealing with a network site.
		$options['is_multi_network'] = (bool) $this->is_main_network();
		$options['is_multi_site']    = (bool) $this->is_multisite();

		$file_mod_disabled_reasons = array_keys(
			array_filter(
				array(
					'automatic_updater_disabled'      => (bool) $this->get_constant( 'AUTOMATIC_UPDATER_DISABLED' ),
					// WP AUTO UPDATE CORE defaults to minor, '1' if true and '0' if set to false.
					'wp_auto_update_core_disabled'    => ! ( (bool) $this->get_constant( 'WP_AUTO_UPDATE_CORE' ) ),
					'is_version_controlled'           => (bool) $this->is_version_controlled(),
					// By default we assume that site does have system write access if the value is not set yet.
					'has_no_file_system_write_access' => ! (bool) $this->file_system_write_access(),
					'disallow_file_mods'              => (bool) $this->get_constant( 'DISALLOW_FILE_MODS' ),
				)
			)
		);

		$options['file_mod_disabled'] = empty( $file_mod_disabled_reasons ) ? false : $file_mod_disabled_reasons;

		$options['jetpack_connection_active_plugins'] = $this->get_connection_active_plugins();
	}

	/**
	 * This function returns the values of any active Jetpack modules.
	 *
	 * @return array
	 */
	public function get_jetpack_modules() {
		return array_values( Jetpack_Options::get_option( 'active_modules', array() ) );
	}

	/**
	 * This function returns true if a specified Jetpack module is active, false otherwise.
	 *
	 * @param string $module The Jetpack module name to check.
	 *
	 * @return bool
	 */
	public function is_module_active( $module ) {
		return in_array( $module, Jetpack_Options::get_option( 'active_modules', array() ), true );
	}

	/**
	 * This function returns false for a check as to whether a site is a VIP site or not.
	 *
	 * @return bool Always returns false.
	 */
	public function is_vip() {
		return false; // this may change for VIP Go sites, which sync using Jetpack.
	}

	/**
	 * If the site's current theme supports post thumbnails, return true (otherwise return false).
	 *
	 * @return bool
	 */
	public function featured_images_enabled() {
		return $this->current_theme_supports( 'post-thumbnails' );
	}

	/**
	 * Returns an array of supported post formats.
	 *
	 * @return array
	 */
	public function get_post_formats() {
		// deprecated - see separate endpoint. get a list of supported post formats.
		$all_formats = get_post_format_strings();
		$supported   = $this->get_theme_support( 'post-formats' );

		$supported_formats = array();

		if ( isset( $supported[0] ) ) {
			foreach ( $supported[0] as $format ) {
				$supported_formats[ $format ] = $all_formats[ $format ];
			}
		}

		return $supported_formats;
	}

	/**
	 * Returns an array with site icon details.
	 *
	 * @return array
	 */
	public function get_icon() {
		$icon_id = get_option( 'site_icon' );
		if ( empty( $icon_id ) ) {
			$icon_id = Jetpack_Options::get_option( 'site_icon_id' );
		}

		if ( empty( $icon_id ) ) {
			return null;
		}

		$icon = array_filter(
			array(
				'img' => wp_get_attachment_image_url( $icon_id, 'full' ),
				'ico' => wp_get_attachment_image_url( $icon_id, array( 16, 16 ) ),
			)
		);

		if ( empty( $icon ) ) {
			return null;
		}

		if ( current_user_can( 'edit_posts', $icon_id ) ) {
			$icon['media_id'] = (int) $icon_id;
		}

		return $icon;
	}

	/**
	 * Private methods
	 **/

	/**
	 * This function returns true if the current site is the main network site, false otherwise.
	 *
	 * @param array $response The array of Jetpack response keys.
	 *
	 * @return bool
	 */
	private function is_main_site( $response ) {
		if ( isset( $response['options']->main_network_site, $response['options']->unmapped_url ) ) {
			$main_network_site_url = set_url_scheme( $response['options']->main_network_site, 'http' );
			$unmapped_url          = set_url_scheme( $response['options']->unmapped_url, 'http' );
			if ( $unmapped_url === $main_network_site_url ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * For Jetpack sites this will always return false.
	 *
	 * This is extended for WordPress.com sites in wpcom/public.api/rest/sal/trait.json-api-site-wpcom.php.
	 *
	 * @param int $post_id The post id.
	 *
	 * @return bool
	 */
	protected function is_a8c_publication( $post_id ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable -- Extended and used in WordPress.com.
		return false;
	}
}
