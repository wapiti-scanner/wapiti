<?php
/**
 * A paywall that exchanges JWT tokens from WordPress.com to allow
 * a current visitor to view content that has been deemed "Premium content".
 *
 * @package Automattic\Jetpack\Extensions\Premium_Content
 */

namespace Automattic\Jetpack\Extensions\Premium_Content\Subscription_Service;

use Automattic\Jetpack\Connection\Tokens;

/**
 * Class Jetpack_Token_Subscription_Service
 *
 * @package Automattic\Jetpack\Extensions\Premium_Content\Subscription_Service
 */
class Jetpack_Token_Subscription_Service extends Token_Subscription_Service {

	/**
	 * Is the Jetpack_Options class available?
	 *
	 * @return bool Whether Jetpack_Options class exists.
	 */
	public static function available() {
		return class_exists( '\Jetpack_Options' );
	}

	/**
	 * Get the site ID.
	 *
	 * @return int The site ID.
	 */
	public function get_site_id() {
		return \Jetpack_Options::get_option( 'id' );
	}

	/**
	 * Get the key.
	 *
	 * @return string The key.
	 */
	public function get_key() {
		$token = ( new Tokens() )->get_access_token();
		if ( ! isset( $token->secret ) ) {
			return false;
		}
		return $token->secret;
	}
}
