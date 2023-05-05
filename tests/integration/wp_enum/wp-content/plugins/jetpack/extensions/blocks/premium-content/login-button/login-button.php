<?php
/**
 * Premium Content Login Button Child Block.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\Premium_Content;

use Automattic\Jetpack\Blocks;
use Automattic\Jetpack\Extensions\Premium_Content\Subscription_Service\Token_Subscription_Service;
use Automattic\Jetpack\Status\Host;
use Jetpack_Gutenberg;

require_once dirname( __DIR__ ) . '/_inc/subscription-service/include.php';

const LOGIN_BUTTON_NAME = 'premium-content/login-button';

/**
 * Registers the block for use in Gutenberg
 * This is done via an action so that we can disable
 * registration if we need to.
 */
function register_login_button_block() {
	// Only load this block on WordPress.com.
	if ( ( defined( 'IS_WPCOM' ) && IS_WPCOM ) || ( new Host() )->is_woa_site() ) {
		Blocks::jetpack_register_block(
			LOGIN_BUTTON_NAME,
			array(
				'render_callback' => __NAMESPACE__ . '\render_login_button_block',
			)
		);
	}
}
add_action( 'init', __NAMESPACE__ . '\register_login_button_block' );

/**
 * Render callback.
 *
 * @param array  $attributes Array containing the block attributes.
 * @param string $content    String containing the block content.
 *
 * @return string
 */
function render_login_button_block( $attributes, $content ) {
	if ( ! pre_render_checks() ) {
		return '';
	}

	$has_auth_cookie = isset( $_COOKIE[ Token_Subscription_Service::JWT_AUTH_TOKEN_COOKIE_NAME ] );
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended
	$has_token_parameter = isset( $_GET['token'] );

	if ( is_user_logged_in() || $has_auth_cookie || $has_token_parameter ) {
		// The viewer is logged it, so they shouldn't see the login button.
		return '';
	}

	Jetpack_Gutenberg::load_styles_as_required( LOGIN_BUTTON_NAME );

	$url = subscription_service()->access_url();

	return preg_replace( '/(<a\b[^><]*)>/i', '$1 href="' . esc_url( $url ) . '">', $content );
}
