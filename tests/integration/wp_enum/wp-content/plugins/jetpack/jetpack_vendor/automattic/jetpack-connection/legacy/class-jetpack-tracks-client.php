<?php
/**
 * Legacy Jetpack Tracks Client
 *
 * @package automattic/jetpack-tracking
 */

use Automattic\Jetpack\Connection\Manager;

/**
 * Jetpack_Tracks_Client
 *
 * Send Tracks events on behalf of a user
 *
 * Example Usage:
```php
	require( dirname(__FILE__).'path/to/tracks/class-jetpack-tracks-client.php' );

	$result = Jetpack_Tracks_Client::record_event( array(
		'_en'        => $event_name,       // required
		'_ui'        => $user_id,          // required unless _ul is provided
		'_ul'        => $user_login,       // required unless _ui is provided

		// Optional, but recommended
		'_ts'        => $ts_in_ms,         // Default: now
		'_via_ip'    => $client_ip,        // we use it for geo, etc.

		// Possibly useful to set some context for the event
		'_via_ua'    => $client_user_agent,
		'_via_url'   => $client_url,
		'_via_ref'   => $client_referrer,

		// For user-targeted tests
		'abtest_name'        => $abtest_name,
		'abtest_variation'   => $abtest_variation,

		// Your application-specific properties
		'custom_property'    => $some_value,
	) );

	if ( is_wp_error( $result ) ) {
		// Handle the error in your app
	}
```
 */
class Jetpack_Tracks_Client {
	const PIXEL           = 'https://pixel.wp.com/t.gif';
	const BROWSER_TYPE    = 'php-agent';
	const USER_AGENT_SLUG = 'tracks-client';
	const VERSION         = '0.3';

	/**
	 * Stores the Terms of Service Object Reference.
	 *
	 * @var null
	 */
	private static $terms_of_service = null;

	/**
	 * Record an event.
	 *
	 * @param  mixed $event Event object to send to Tracks. An array will be cast to object. Required.
	 *                      Properties are included directly in the pixel query string after light validation.
	 * @return mixed         True on success, WP_Error on failure
	 */
	public static function record_event( $event ) {
		if ( ! self::$terms_of_service ) {
			self::$terms_of_service = new \Automattic\Jetpack\Terms_Of_Service();
		}

		// Don't track users who have opted out or not agreed to our TOS, or are not running an active Jetpack.
		if ( ! self::$terms_of_service->has_agreed() || ! empty( $_COOKIE['tk_opt-out'] ) ) {
			return false;
		}

		if ( ! $event instanceof Jetpack_Tracks_Event ) {
			$event = new Jetpack_Tracks_Event( $event );
		}
		if ( is_wp_error( $event ) ) {
			return $event;
		}

		$pixel = $event->build_pixel_url( $event );

		if ( ! $pixel ) {
			return new WP_Error( 'invalid_pixel', 'cannot generate tracks pixel for given input', 400 );
		}

		return self::record_pixel( $pixel );
	}

	/**
	 * Synchronously request the pixel.
	 *
	 * @param string $pixel The wp.com tracking pixel.
	 * @return array|bool|WP_Error True if successful. wp_remote_get response or WP_Error if not.
	 */
	public static function record_pixel( $pixel ) {
		// Add the Request Timestamp and URL terminator just before the HTTP request.
		$pixel .= '&_rt=' . self::build_timestamp() . '&_=_';

		$response = wp_remote_get(
			$pixel,
			array(
				'blocking'    => true, // The default, but being explicit here :).
				'timeout'     => 1,
				'redirection' => 2,
				'httpversion' => '1.1',
				'user-agent'  => self::get_user_agent(),
			)
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = isset( $response['response']['code'] ) ? $response['response']['code'] : 0;

		if ( 200 !== $code ) {
			return new WP_Error( 'request_failed', 'Tracks pixel request failed', $code );
		}

		return true;
	}

	/**
	 * Get the user agent.
	 *
	 * @return string The user agent.
	 */
	public static function get_user_agent() {
		return self::USER_AGENT_SLUG . '-v' . self::VERSION;
	}

	/**
	 * Build an event and return its tracking URL
	 *
	 * @deprecated          Call the `build_pixel_url` method on a Jetpack_Tracks_Event object instead.
	 * @param  array $event Event keys and values.
	 * @return string       URL of a tracking pixel.
	 */
	public static function build_pixel_url( $event ) {
		$_event = new Jetpack_Tracks_Event( $event );
		return $_event->build_pixel_url();
	}

	/**
	 * Validate input for a tracks event.
	 *
	 * @deprecated          Instantiate a Jetpack_Tracks_Event object instead
	 * @param  array $event Event keys and values.
	 * @return mixed        Validated keys and values or WP_Error on failure
	 */
	private static function validate_and_sanitize( $event ) {
		$_event = new Jetpack_Tracks_Event( $event );
		if ( is_wp_error( $_event ) ) {
			return $_event;
		}
		return get_object_vars( $_event );
	}

	/**
	 * Builds a timestamp.
	 *
	 * Milliseconds since 1970-01-01.
	 *
	 * @return string
	 */
	public static function build_timestamp() {
		$ts = round( microtime( true ) * 1000 );
		return number_format( $ts, 0, '', '' );
	}

	/**
	 * Grabs the user's anon id from cookies, or generates and sets a new one
	 *
	 * @return string An anon id for the user
	 */
	public static function get_anon_id() {
		static $anon_id = null;

		if ( ! isset( $anon_id ) ) {

			// Did the browser send us a cookie?
			if ( isset( $_COOKIE['tk_ai'] ) && preg_match( '#^[a-z]+:[A-Za-z0-9+/=]{24}$#', $_COOKIE['tk_ai'] ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- This is validating.
				$anon_id = $_COOKIE['tk_ai']; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- This is validating.
			} else {

				$binary = '';

				// Generate a new anonId and try to save it in the browser's cookies.
				// Note that base64-encoding an 18 character string generates a 24-character anon id.
				for ( $i = 0; $i < 18; ++$i ) {
					$binary .= chr( wp_rand( 0, 255 ) );
				}

				$anon_id = 'jetpack:' . base64_encode( $binary ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode

				if ( ! headers_sent()
					&& ! ( defined( 'REST_REQUEST' ) && REST_REQUEST )
					&& ! ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )
				) {
					setcookie( 'tk_ai', $anon_id, 0, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), false ); // phpcs:ignore Jetpack.Functions.SetCookie -- This is a random value and should be fine.
				}
			}
		}

		return $anon_id;
	}

	/**
	 * Gets the WordPress.com user's Tracks identity, if connected.
	 *
	 * @return array|bool
	 */
	public static function get_connected_user_tracks_identity() {
		$user_data = ( new Manager() )->get_connected_user_data();
		if ( ! $user_data ) {
			return false;
		}

		return array(
			'blogid'      => Jetpack_Options::get_option( 'id', 0 ),
			'userid'      => $user_data['ID'],
			'username'    => $user_data['login'],
			'user_locale' => $user_data['user_locale'],
		);
	}
}
