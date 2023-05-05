<?php
/**
 * Compatibility functions for the Creative Mail plugin.
 * https://wordpress.org/plugins/creative-mail-by-constant-contact/
 *
 * @since 8.9.0
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Creative_Mail;

use Automattic\Jetpack\Plugins_Installer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

const PLUGIN_SLUG = 'creative-mail-by-constant-contact';
const PLUGIN_FILE = 'creative-mail-by-constant-contact/creative-mail-plugin.php';

add_action( 'jetpack_activated_plugin', __NAMESPACE__ . '\configure_plugin', 10, 2 );

// Check for the JITM action.
if ( isset( $_GET['creative-mail-action'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	add_action( 'admin_init', __NAMESPACE__ . '\try_install' );
}

if ( ! empty( $_GET['creative-mail-install-error'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	add_action( 'admin_notices', __NAMESPACE__ . '\error_notice' );
}

/**
 * Verify the intent to install Creative Mail, and kick off installation.
 *
 * This works in tandem with a JITM set up in the JITM package.
 */
function try_install() {
	check_admin_referer( 'creative-mail-install' );

	$result   = false;
	$redirect = admin_url( 'edit.php?post_type=feedback' );

	// Attempt to install and activate the plugin.
	if ( current_user_can( 'activate_plugins' ) ) {
		switch ( $_GET['creative-mail-action'] ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- Function only hooked if set.
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
		$redirect = admin_url( 'admin.php?page=creativemail' );
	} else {
		$redirect = add_query_arg( 'creative-mail-install-error', true, $redirect );
	}

	wp_safe_redirect( $redirect );

	exit;
}

/**
 * Install and activate the Creative Mail plugin.
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
 * Activate the Creative Mail plugin.
 *
 * @return bool result of activation
 */
function activate() {
	$result = activate_plugin( PLUGIN_FILE );

	// Activate_plugin() returns null on success.
	return $result === null;
}

/**
 * Notify the user that the installation of Creative Mail failed.
 */
function error_notice() {
	?>
	<div class="notice notice-error is-dismissible">
		<p><?php esc_html_e( 'There was an error installing Creative Mail.', 'jetpack' ); ?></p>
	</div>
	<?php
}

/**
 * Set some options when first activating the plugin via Jetpack.
 *
 * @since 8.9.0
 *
 * @param string $plugin_file Plugin file.
 * @param string $source      Where did the plugin installation originate.
 */
function configure_plugin( $plugin_file, $source ) {
	if ( PLUGIN_FILE !== $plugin_file ) {
		return;
	}

	$plugin_info = array(
		'plugin'  => 'jetpack',
		'version' => JETPACK__VERSION,
		'time'    => time(),
		'source'  => esc_attr( $source ),
	);

	update_option( 'ce4wp_referred_by', $plugin_info );
}
