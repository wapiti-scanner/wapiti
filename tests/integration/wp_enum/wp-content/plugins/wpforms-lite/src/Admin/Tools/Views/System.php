<?php

namespace WPForms\Admin\Tools\Views;

/**
 * Class System.
 *
 * @since 1.6.6
 */
class System extends View {

	/**
	 * View slug.
	 *
	 * @since 1.6.6
	 *
	 * @var string
	 */
	protected $slug = 'system';

	/**
	 * Init view.
	 *
	 * @since 1.6.6
	 */
	public function init() {}

	/**
	 * Get view label.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 */
	public function get_label() {

		return esc_html__( 'System Info', 'wpforms-lite' );
	}

	/**
	 * Checking user capability to view.
	 *
	 * @since 1.6.6
	 *
	 * @return bool
	 */
	public function check_capability() {

		return wpforms_current_user_can();
	}

	/**
	 * System view content.
	 *
	 * @since 1.6.6
	 */
	public function display() {
		?>

		<div class="wpforms-setting-row tools">
			<h4 id="form-export"><?php esc_html_e( 'System Information', 'wpforms-lite' ); ?></h4>
			<textarea class="info-area" readonly><?php echo esc_textarea( $this->get_system_info() ); ?></textarea>
		</div>

		<div class="wpforms-setting-row tools">
			<h4 id="ssl-verify"><?php esc_html_e( 'Test SSL Connections', 'wpforms-lite' ); ?></h4>
			<p><?php esc_html_e( 'Click the button below to verify your web server can perform SSL connections successfully.', 'wpforms-lite' ); ?></p>
			<button type="button" id="wpforms-ssl-verify" class="wpforms-btn wpforms-btn-md wpforms-btn-orange">
				<?php esc_html_e( 'Test Connection', 'wpforms-lite' ); ?>
			</button>
		</div>

		<?php
	}

	/**
	 * Get system information.
	 *
	 * Based on a function from Easy Digital Downloads by Pippin Williamson.
	 *
	 * @link https://github.com/easydigitaldownloads/easy-digital-downloads/blob/master/includes/admin/tools.php#L470
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 */
	public function get_system_info() {

		$data = '### Begin System Info ###' . "\n\n";

		$data .= $this->wpforms_info();
		$data .= $this->site_info();
		$data .= $this->wp_info();
		$data .= $this->uploads_info();
		$data .= $this->plugins_info();
		$data .= $this->server_info();

		$data .= "\n" . '### End System Info ###';

		return $data;
	}

	/**
	 * Get WPForms info.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 */
	private function wpforms_info() {

		$activated = get_option( 'wpforms_activated', [] );
		$data      = '-- WPForms Info' . "\n\n";

		if ( ! empty( $activated['pro'] ) ) {
			$date  = $activated['pro'] + ( get_option( 'gmt_offset' ) * 3600 );
			$data .= 'Pro:                      ' . date_i18n( 'M j, Y @ g:ia', $date ) . "\n";
		}

		if ( ! empty( $activated['lite'] ) ) {
			$date  = $activated['lite'] + ( get_option( 'gmt_offset' ) * 3600 );
			$data .= 'Lite:                     ' . date_i18n( 'M j, Y @ g:ia', $date ) . "\n";
		}

		$data .= 'Lite Connect:             ' . $this->get_lite_connect_info() . "\n";

		return $data;
	}

	/**
	 * Get Site info.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 */
	private function site_info() {

		$data  = "\n" . '-- Site Info' . "\n\n";
		$data .= 'Site URL:                 ' . site_url() . "\n";
		$data .= 'Home URL:                 ' . home_url() . "\n";
		$data .= 'Multisite:                ' . ( is_multisite() ? 'Yes' : 'No' ) . "\n";

		return $data;
	}

	/**
	 * Get WordPress Configuration info.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 */
	private function wp_info() {

		global $wpdb;

		$theme_data = wp_get_theme();
		$theme      = $theme_data->name . ' ' . $theme_data->version;

		$data  = "\n" . '-- WordPress Configuration' . "\n\n";
		$data .= 'Version:                  ' . get_bloginfo( 'version' ) . "\n";
		$data .= 'Language:                 ' . get_locale() . "\n";
		$data .= 'User Language:            ' . get_user_locale() . "\n";
		$data .= 'Permalink Structure:      ' . ( get_option( 'permalink_structure' ) ? get_option( 'permalink_structure' ) : 'Default' ) . "\n";
		$data .= 'Active Theme:             ' . $theme . "\n";
		$data .= 'Show On Front:            ' . get_option( 'show_on_front' ) . "\n";

		// Only show page specs if front page is set to 'page'.
		if ( get_option( 'show_on_front' ) === 'page' ) {
			$front_page_id = get_option( 'page_on_front' );
			$blog_page_id  = get_option( 'page_for_posts' );

			$data .= 'Page On Front:            ' . ( $front_page_id ? get_the_title( $front_page_id ) . ' (#' . $front_page_id . ')' : 'Unset' ) . "\n";
			$data .= 'Page For Posts:           ' . ( $blog_page_id ? get_the_title( $blog_page_id ) . ' (#' . $blog_page_id . ')' : 'Unset' ) . "\n";
		}
		$data .= 'ABSPATH:                  ' . ABSPATH . "\n";
		$data .= 'Table Prefix:             ' . 'Length: ' . strlen( $wpdb->prefix ) . '   Status: ' . ( strlen( $wpdb->prefix ) > 16 ? 'ERROR: Too long' : 'Acceptable' ) . "\n"; //phpcs:ignore
		$data .= 'WP_DEBUG:                 ' . ( defined( 'WP_DEBUG' ) ? WP_DEBUG ? 'Enabled' : 'Disabled' : 'Not set' ) . "\n";
		$data .= 'WPFORMS_DEBUG:            ' . ( defined( 'WPFORMS_DEBUG' ) ? WPFORMS_DEBUG ? 'Enabled' : 'Disabled' : 'Not set' ) . "\n";
		$data .= 'Memory Limit:             ' . WP_MEMORY_LIMIT . "\n";
		$data .= 'Registered Post Stati:    ' . implode( ', ', get_post_stati() ) . "\n";
		$data .= 'Revisions:                ' . ( WP_POST_REVISIONS ? WP_POST_REVISIONS > 1 ? 'Limited to ' . WP_POST_REVISIONS : 'Enabled' : 'Disabled' ) . "\n";

		return $data;
	}

	/**
	 * Get Uploads/Constants info.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 */
	private function uploads_info() {

		// @todo WPForms configuration/specific details.
		$data  = "\n" . '-- WordPress Uploads/Constants' . "\n\n";
		$data .= 'WP_CONTENT_DIR:           ' . ( defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR ? WP_CONTENT_DIR : 'Disabled' : 'Not set' ) . "\n";
		$data .= 'WP_CONTENT_URL:           ' . ( defined( 'WP_CONTENT_URL' ) ? WP_CONTENT_URL ? WP_CONTENT_URL : 'Disabled' : 'Not set' ) . "\n";
		$data .= 'UPLOADS:                  ' . ( defined( 'UPLOADS' ) ? UPLOADS ? UPLOADS : 'Disabled' : 'Not set' ) . "\n";

		$uploads_dir = wp_upload_dir();

		$data .= 'wp_uploads_dir() path:    ' . $uploads_dir['path'] . "\n";
		$data .= 'wp_uploads_dir() url:     ' . $uploads_dir['url'] . "\n";
		$data .= 'wp_uploads_dir() basedir: ' . $uploads_dir['basedir'] . "\n";
		$data .= 'wp_uploads_dir() baseurl: ' . $uploads_dir['baseurl'] . "\n";

		return $data;
	}

	/**
	 * Get Plugins info.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 */
	private function plugins_info() {

		// Get plugins that have an update.
		$data  = $this->mu_plugins();
		$data .= $this->installed_plugins();
		$data .= $this->multisite_plugins();

		return $data;
	}

	/**
	 * Get MU Plugins info.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 */
	private function mu_plugins() {

		$data = '';

		// Must-use plugins.
		// NOTE: MU plugins can't show updates!
		$muplugins = get_mu_plugins();

		if ( ! empty( $muplugins ) && count( $muplugins ) > 0 ) {
			$data = "\n" . '-- Must-Use Plugins' . "\n\n";

			foreach ( $muplugins as $plugin => $plugin_data ) {
				$data .= $plugin_data['Name'] . ': ' . $plugin_data['Version'] . "\n";
			}
		}

		return $data;
	}

	/**
	 * Get Installed Plugins info.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 */
	private function installed_plugins() {

		$updates = get_plugin_updates();

		// WordPress active plugins.
		$data = "\n" . '-- WordPress Active Plugins' . "\n\n";

		$plugins        = get_plugins();
		$active_plugins = get_option( 'active_plugins', [] );

		foreach ( $plugins as $plugin_path => $plugin ) {
			if ( ! in_array( $plugin_path, $active_plugins, true ) ) {
				continue;
			}
			$update = ( array_key_exists( $plugin_path, $updates ) ) ? ' (needs update - ' . $updates[ $plugin_path ]->update->new_version . ')' : '';
			$data  .= $plugin['Name'] . ': ' . $plugin['Version'] . $update . "\n";
		}

		// WordPress inactive plugins.
		$data .= "\n" . '-- WordPress Inactive Plugins' . "\n\n";

		foreach ( $plugins as $plugin_path => $plugin ) {
			if ( in_array( $plugin_path, $active_plugins, true ) ) {
				continue;
			}
			$update = ( array_key_exists( $plugin_path, $updates ) ) ? ' (needs update - ' . $updates[ $plugin_path ]->update->new_version . ')' : '';
			$data  .= $plugin['Name'] . ': ' . $plugin['Version'] . $update . "\n";
		}

		return $data;
	}

	/**
	 * Get Multisite Plugins info.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 */
	private function multisite_plugins() {

		$data = '';

		if ( ! is_multisite() ) {
			return $data;
		}

		$updates = get_plugin_updates();

		// WordPress Multisite active plugins.
		$data = "\n" . '-- Network Active Plugins' . "\n\n";

		$plugins        = wp_get_active_network_plugins();
		$active_plugins = get_site_option( 'active_sitewide_plugins', [] );

		foreach ( $plugins as $plugin_path ) {
			$plugin_base = plugin_basename( $plugin_path );

			if ( ! array_key_exists( $plugin_base, $active_plugins ) ) {
				continue;
			}
			$update = ( array_key_exists( $plugin_path, $updates ) ) ? ' (needs update - ' . $updates[ $plugin_path ]->update->new_version . ')' : '';
			$plugin = get_plugin_data( $plugin_path );
			$data  .= $plugin['Name'] . ': ' . $plugin['Version'] . $update . "\n";
		}

		return $data;
	}

	/**
	 * Get Server info.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 */
	private function server_info() {

		global $wpdb;

		// Server configuration (really just versions).
		$data  = "\n" . '-- Webserver Configuration' . "\n\n";
		$data .= 'PHP Version:              ' . PHP_VERSION . "\n";
		$data .= 'MySQL Version:            ' . $wpdb->db_version() . "\n";
		$data .= 'Webserver Info:           ' . ( isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : '' ) . "\n";

		// PHP configs... now we're getting to the important stuff.
		$data .= "\n" . '-- PHP Configuration' . "\n\n";
		$data .= 'Memory Limit:             ' . ini_get( 'memory_limit' ) . "\n";
		$data .= 'Upload Max Size:          ' . ini_get( 'upload_max_filesize' ) . "\n";
		$data .= 'Post Max Size:            ' . ini_get( 'post_max_size' ) . "\n";
		$data .= 'Upload Max Filesize:      ' . ini_get( 'upload_max_filesize' ) . "\n";
		$data .= 'Time Limit:               ' . ini_get( 'max_execution_time' ) . "\n";
		$data .= 'Max Input Vars:           ' . ini_get( 'max_input_vars' ) . "\n";
		$data .= 'Display Errors:           ' . ( ini_get( 'display_errors' ) ? 'On (' . ini_get( 'display_errors' ) . ')' : 'N/A' ) . "\n";

		// PHP extensions and such.
		$data .= "\n" . '-- PHP Extensions' . "\n\n";
		$data .= 'cURL:                     ' . ( function_exists( 'curl_init' ) ? 'Supported' : 'Not Supported' ) . "\n";
		$data .= 'fsockopen:                ' . ( function_exists( 'fsockopen' ) ? 'Supported' : 'Not Supported' ) . "\n";
		$data .= 'SOAP Client:              ' . ( class_exists( 'SoapClient', false ) ? 'Installed' : 'Not Installed' ) . "\n";
		$data .= 'Suhosin:                  ' . ( extension_loaded( 'suhosin' ) ? 'Installed' : 'Not Installed' ) . "\n";

		// Session stuff.
		$data .= "\n" . '-- Session Configuration' . "\n\n";
		$data .= 'Session:                  ' . ( isset( $_SESSION ) ? 'Enabled' : 'Disabled' ) . "\n";

		// The rest of this is only relevant if session is enabled.
		if ( isset( $_SESSION ) ) {
			$data .= 'Session Name:             ' . esc_html( ini_get( 'session.name' ) ) . "\n";
			$data .= 'Cookie Path:              ' . esc_html( ini_get( 'session.cookie_path' ) ) . "\n";
			$data .= 'Save Path:                ' . esc_html( ini_get( 'session.save_path' ) ) . "\n";
			$data .= 'Use Cookies:              ' . ( ini_get( 'session.use_cookies' ) ? 'On' : 'Off' ) . "\n";
			$data .= 'Use Only Cookies:         ' . ( ini_get( 'session.use_only_cookies' ) ? 'On' : 'Off' ) . "\n";
		}

		return $data;
	}

	/**
	 * Get Lite Connect status info string.
	 *
	 * @since 1.7.5
	 *
	 * @return string
	 */
	private function get_lite_connect_info() {

		$lc_enabled       = wpforms_setting( 'lite-connect-enabled' );
		$lc_enabled_since = wpforms_setting( 'lite-connect-enabled-since' );
		$date             = date_i18n( 'M j, Y @ g:ia', $lc_enabled_since + get_option( 'gmt_offset' ) * 3600 );

		if ( $lc_enabled ) {
			$string = $lc_enabled_since ? 'Backup is enabled since ' . $date : 'Backup is enabled';
		} else {
			$string = $lc_enabled_since ? 'Backup is not enabled. Previously was enabled since ' . $date : 'Backup is not enabled';
		}

		return $string;
	}
}
