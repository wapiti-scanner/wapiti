<?php
/**
 * Jetpack Client
 *
 * Deprecated methods for Jetpack to act as client with wpcom, provided for back-compatibility.
 *
 * @category Connection
 * @package  automattic/jetpack-compat
 */

use Automattic\Jetpack\Connection\Client;

/**
 * Class Jetpack_Client
 *
 * @deprecated Use Automattic\Jetpack\Connection\Client
 */
class Jetpack_Client {

	/**
	 * Jetpack API version.
	 *
	 * @deprecated use Automattic\Jetpack\Connection\Client::WPCOM_JSON_API_VERSION
	 */
	const WPCOM_JSON_API_VERSION = '1.1';

	/**
	 * Perform remote request.
	 *
	 * @deprecated use Automattic\Jetpack\Connection\Client::remote_request
	 *
	 * @param array $args Arguments.
	 * @param null  $body Request body.
	 *
	 * @return array|WP_Error
	 */
	public static function remote_request( $args, $body = null ) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Connection\Client' );
		return Client::remote_request( $args, $body );
	}

	/**
	 * Request to wpcom using the blog id.
	 *
	 * @deprecated use Automattic\Jetpack\Connection\Client::wpcom_json_api_request_as_blog
	 *
	 * @param string $path Endpoint path.
	 * @param string $version Endpoint version.
	 * @param array  $args Arguments.
	 * @param null   $body Request body.
	 * @param string $base_api_path Endpoint base prefix.
	 *
	 * @return array|WP_Error
	 */
	public static function wpcom_json_api_request_as_blog(
		$path,
		$version = self::WPCOM_JSON_API_VERSION,
		$args = array(),
		$body = null,
		$base_api_path = 'rest'
	) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Connection\Client' );
		return Client::wpcom_json_api_request_as_blog( $path, $version, $args, $body, $base_api_path );
	}

	/**
	 * Wrapper for wp_remote_request().  Turns off SSL verification for certain SSL errors.
	 * This is suboptimal, but many, many, many hosts have misconfigured SSL.
	 *
	 * @deprecated use Automattic\Jetpack\Connection\Client::_wp_remote_request
	 *
	 * When Jetpack is registered, the jetpack_fallback_no_verify_ssl_certs option is set to the current time if:
	 * 1. a certificate error is found AND
	 * 2. not verifying the certificate works around the problem.
	 *
	 * The option is checked on each request.
	 *
	 * @internal
	 *
	 * @param String  $url the request URL.
	 * @param array   $args request arguments.
	 * @param Boolean $set_fallback whether to allow flagging this request to use a fallback certficate override.
	 * @return array|WP_Error WP HTTP response on success
	 */
	public static function _wp_remote_request( $url, $args, $set_fallback = false ) { // phpcs:ignore PSR2.Methods.MethodDeclaration.Underscore
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Connection\Client' );
		return Client::_wp_remote_request( $url, $args, $set_fallback );
	}
}
