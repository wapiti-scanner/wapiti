<?php
/**
 * Handles acceptance of WordPress.com Terms of Service for sites connected to WP.com.
 *
 * This is auto-loaded as of Jetpack v8.3 for WP.com connected-sites only.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\TOS;

use Automattic\Jetpack\Connection\Client;

/**
 * Makes a request to the WP.com legal endpoint to mark the Terms of Service as accepted.
 */
function accept_tos() {
	check_ajax_referer( 'wp_ajax_action', '_nonce' );

	$response = Client::wpcom_json_api_request_as_user(
		'/legal',
		'2',
		array(
			'method' => 'POST',
		),
		array(
			'action' => 'accept_tos',
		)
	);

	if ( is_wp_error( $response ) ) {
		wp_send_json_error( array( 'message' => __( 'Could not accept the Terms of Service. Please try again later.', 'jetpack' ) ) );
		wp_die();
	}

	wp_send_json_success( $response );

	wp_die();
}

add_action( 'wp_ajax_jetpack_accept_tos', __NAMESPACE__ . '\accept_tos' );
