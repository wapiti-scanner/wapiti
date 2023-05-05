<?php
/**
 * Compatibility functions for the Jetpack Boost plugin.
 * https://wordpress.org/plugins/jetpack-boost/
 *
 * @since 10.4
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Jetpack_Boost;

use Automattic\Jetpack\Plugins_Installer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

const PLUGIN_SLUG = 'jetpack-boost';
const PLUGIN_FILE = 'jetpack-boost/jetpack-boost.php';

if ( isset( $_GET['jetpack-boost-install-error'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	add_action( 'admin_notices', __NAMESPACE__ . '\error_notice' );
}

if ( isset( $_GET['jetpack-boost-action'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	add_action( 'admin_init', __NAMESPACE__ . '\try_install' );
}

/**
 * Verify the intent to install Jetpack Boost, and kick off installation.
 *
 * This works in tandem with a JITM set up in the JITM package.
 */
function try_install() {
	if ( ! isset( $_GET['jetpack-boost-action'] ) ) {
		return;
	}

	check_admin_referer( 'jetpack-boost-install' );

	$result = false;
	// If the plugin install fails, redirect to plugin install page pre-populated with jetpack-boost search term.
	$redirect_on_error = admin_url( 'plugin-install.php?s=jetpack-boost&tab=search&type=term' );

	// Attempt to install and activate the plugin.
	if ( current_user_can( 'activate_plugins' ) ) {
		switch ( $_GET['jetpack-boost-action'] ) {
			case 'install':
				$result = install_and_activate();
				break;
			case 'activate':
				$result = activate();
				break;
		}
	}

	if ( $result ) {
		/** This action is already documented in _inc/lib/class.core-rest-api-endpoints.php */
		do_action( 'jetpack_activated_plugin', PLUGIN_FILE, 'jitm' );
		$redirect = admin_url( 'admin.php?page=jetpack-boost' );
	} else {
		$redirect = add_query_arg( 'jetpack-boost-install-error', true, $redirect_on_error );
	}

	wp_safe_redirect( $redirect );

	exit;
}

/**
 * Install and activate the Jetpack Boost plugin.
 *
 * @return bool result of installation
 */
function install_and_activate() {
	$result = Plugins_Installer::install_and_activate_plugin( PLUGIN_SLUG );

	if ( is_wp_error( $result ) ) {
		return false;
	} else {
		return true;
	}
}

/**
 * Activate the Jetpack Boost plugin.
 *
 * @return bool result of activation
 */
function activate() {
	$result = activate_plugin( PLUGIN_FILE );

	// Activate_plugin() returns null on success.
	return $result === null;
}

/**
 * Notify the user that the installation of Jetpack Boost failed.
 */
function error_notice() {
	if ( empty( $_GET['jetpack-boost-install-error'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return;
	}

	?>
	<div class="notice notice-error is-dismissible">
		<p><?php esc_html_e( 'There was an error installing Jetpack Boost. Please try again.', 'jetpack' ); ?></p>
	</div>
	<?php
}
