<?php
/**
 * Plugin Name:       WPForms Lite
 * Plugin URI:        https://wpforms.com
 * Description:       Beginner friendly WordPress contact form plugin. Use our Drag & Drop form builder to create your WordPress forms.
 * Requires at least: 5.2
 * Requires PHP:      5.6
 * Author:            WPForms
 * Author URI:        https://wpforms.com
 * Version:           1.8.1.2
 * Text Domain:       wpforms-lite
 * Domain Path:       assets/languages
 *
 * WPForms is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * any later version.
 *
 * WPForms is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with WPForms. If not, see <https://www.gnu.org/licenses/>.
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'WPFORMS_VERSION' ) ) {
	/**
	 * Plugin version.
	 *
	 * @since 1.0.0
	 */
	define( 'WPFORMS_VERSION', '1.8.1.2' );
}

// Plugin Folder Path.
if ( ! defined( 'WPFORMS_PLUGIN_DIR' ) ) {
	define( 'WPFORMS_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
}

// Plugin Folder URL.
if ( ! defined( 'WPFORMS_PLUGIN_URL' ) ) {
	define( 'WPFORMS_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
}

// Plugin Root File.
if ( ! defined( 'WPFORMS_PLUGIN_FILE' ) ) {
	define( 'WPFORMS_PLUGIN_FILE', __FILE__ );
}

// Don't allow multiple versions to be active.
if ( function_exists( 'wpforms' ) ) {

	if ( ! function_exists( 'wpforms_pro_just_activated' ) ) {
		/**
		 * When we activate a Pro version, we need to do additional operations:
		 * 1) deactivate a Lite version;
		 * 2) register option which help to run all activation process for Pro version (custom tables creation, etc.).
		 *
		 * @since 1.6.2
		 */
		function wpforms_pro_just_activated() {

			wpforms_deactivate();
			add_option( 'wpforms_install', 1 );
		}
	}
	add_action( 'activate_wpforms/wpforms.php', 'wpforms_pro_just_activated' );

	if ( ! function_exists( 'wpforms_lite_just_activated' ) ) {
		/**
		 * Store temporarily that the Lite version of the plugin was activated.
		 * This is needed because WP does a redirect after activation and
		 * we need to preserve this state to know whether user activated Lite or not.
		 *
		 * @since 1.5.8
		 */
		function wpforms_lite_just_activated() {

			set_transient( 'wpforms_lite_just_activated', true );
		}
	}
	add_action( 'activate_wpforms-lite/wpforms.php', 'wpforms_lite_just_activated' );

	if ( ! function_exists( 'wpforms_lite_just_deactivated' ) ) {
		/**
		 * Store temporarily that Lite plugin was deactivated.
		 * Convert temporary "activated" value to a global variable,
		 * so it is available through the request. Remove from the storage.
		 *
		 * @since 1.5.8
		 */
		function wpforms_lite_just_deactivated() {

			global $wpforms_lite_just_activated, $wpforms_lite_just_deactivated;

			$wpforms_lite_just_activated   = (bool) get_transient( 'wpforms_lite_just_activated' );
			$wpforms_lite_just_deactivated = true;

			delete_transient( 'wpforms_lite_just_activated' );
		}
	}
	add_action( 'deactivate_wpforms-lite/wpforms.php', 'wpforms_lite_just_deactivated' );

	if ( ! function_exists( 'wpforms_deactivate' ) ) {
		/**
		 * Deactivate Lite if WPForms already activated.
		 *
		 * @since 1.0.0
		 */
		function wpforms_deactivate() {

			$plugin = 'wpforms-lite/wpforms.php';

			deactivate_plugins( $plugin );

			do_action( 'wpforms_plugin_deactivated', $plugin );
		}
	}
	add_action( 'admin_init', 'wpforms_deactivate' );

	if ( ! function_exists( 'wpforms_lite_notice' ) ) {
		/**
		 * Display the notice after deactivation when Pro is still active
		 * and user wanted to activate the Lite version of the plugin.
		 *
		 * @since 1.0.0
		 */
		function wpforms_lite_notice() {

			global $wpforms_lite_just_activated, $wpforms_lite_just_deactivated;

			if (
				empty( $wpforms_lite_just_activated ) ||
				empty( $wpforms_lite_just_deactivated )
			) {
				return;
			}

			// Currently tried to activate Lite with Pro still active, so display the message.
			printf(
				'<div class="notice notice-warning">
					<p>%1$s</p>
					<p>%2$s</p>
				</div>',
				esc_html__( 'Heads up!', 'wpforms-lite' ),
				esc_html__( 'Your site already has WPForms Pro activated. If you want to switch to WPForms Lite, please first go to Plugins → Installed Plugins and deactivate WPForms. Then, you can activate WPForms Lite.', 'wpforms-lite' )
			);

			if ( isset( $_GET['activate'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				unset( $_GET['activate'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			}

			unset( $wpforms_lite_just_activated, $wpforms_lite_just_deactivated );
		}
	}
	add_action( 'admin_notices', 'wpforms_lite_notice' );

	// Do not process the plugin code further.
	return;
}

// We require PHP version 5.6+ for the whole plugin to work.
if ( version_compare( phpversion(), '5.6', '<' ) ) {

	if ( ! function_exists( 'wpforms_php52_notice' ) ) {

		/**
		 * Display the notice about incompatible PHP version after deactivation.
		 *
		 * @since 1.5.0
		 */
		function wpforms_php52_notice() {

			?>
			<div class="notice notice-error">
				<p>
					<?php
					printf(
						wp_kses(
							/* translators: %s - WPBeginner URL for recommended WordPress hosting. */
							__( 'Your site is running an <strong>insecure version</strong> of PHP that is no longer supported. Please contact your web hosting provider to update your PHP version or switch to a <a href="%s" target="_blank" rel="noopener noreferrer">recommended WordPress hosting company</a>.', 'wpforms-lite' ),
							[
								'a'      => [
									'href'   => [],
									'target' => [],
									'rel'    => [],
								],
								'strong' => [],
							]
						),
						'https://www.wpbeginner.com/wordpress-hosting/'
					);
					?>
					<br><br>
					<?php
					printf(
						wp_kses(
							/* translators: %s - WPForms.com URL for documentation with more details. */
							__( '<strong>Note:</strong> The WPForms plugin is disabled on your site until you fix the issue. <a href="%s" target="_blank" rel="noopener noreferrer">Read more for additional information.</a>', 'wpforms-lite' ),
							[
								'a'      => [
									'href'   => [],
									'target' => [],
									'rel'    => [],
								],
								'strong' => [],
							]
						),
						'https://wpforms.com/docs/supported-php-version/'
					);
					?>
				</p>
			</div>

			<?php
			// In case this is on plugin activation.
			// phpcs:disable WordPress.Security.NonceVerification.Recommended
			if ( isset( $_GET['activate'] ) ) {
				unset( $_GET['activate'] );
			}
			// phpcs:enable WordPress.Security.NonceVerification.Recommended
		}
	}

	add_action( 'admin_notices', 'wpforms_php52_notice' );

	// Do not process the plugin code further.
	return;
}

// We require WP version 5.2+ for the whole plugin to work.
if ( version_compare( $GLOBALS['wp_version'], '5.2', '<' ) ) {

	if ( ! function_exists( 'wpforms_wp_notice' ) ) {

		/**
		 * Display the notice about incompatible WP version after deactivation.
		 *
		 * @since 1.7.3
		 */
		function wpforms_wp_notice() {

			?>
			<div class="notice notice-error">
				<p>
					<?php
					printf(
						/* translators: %s - WordPress version. */
						esc_html__( 'The WPForms plugin is disabled because it requires WordPress %s or later.', 'wpforms-lite' ),
						'5.2'
					);
					?>
				</p>
			</div>

			<?php
			// In case this is on plugin activation.
			// phpcs:disable WordPress.Security.NonceVerification.Recommended
			if ( isset( $_GET['activate'] ) ) {
				unset( $_GET['activate'] );
			}
			// phpcs:enable WordPress.Security.NonceVerification.Recommended
		}
	}

	add_action( 'admin_notices', 'wpforms_wp_notice' );

	// Do not process the plugin code further.
	return;
}

// Define the class and the function.
require_once dirname( __FILE__ ) . '/src/WPForms.php';

wpforms();
