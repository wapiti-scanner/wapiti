<?php
/**
 * The Jetpack Connection package Utils class file.
 *
 * @package automattic/jetpack-connection
 */

namespace Automattic\Jetpack\Connection;

use Automattic\Jetpack\Tracking;

/**
 * Provides utility methods for the Connection package.
 */
class Utils {

	const DEFAULT_JETPACK__API_VERSION         = 1;
	const DEFAULT_JETPACK__API_BASE            = 'https://jetpack.wordpress.com/jetpack.';
	const DEFAULT_JETPACK__WPCOM_JSON_API_BASE = 'https://public-api.wordpress.com';

	/**
	 * Enters a user token into the user_tokens option
	 *
	 * @deprecated 1.24.0 Use Automattic\Jetpack\Connection\Tokens->update_user_token() instead.
	 *
	 * @param int    $user_id The user id.
	 * @param string $token The user token.
	 * @param bool   $is_master_user Whether the user is the master user.
	 * @return bool
	 */
	public static function update_user_token( $user_id, $token, $is_master_user ) {
		_deprecated_function( __METHOD__, '1.24.0', 'Automattic\\Jetpack\\Connection\\Tokens->update_user_token' );
		return ( new Tokens() )->update_user_token( $user_id, $token, $is_master_user );
	}

	/**
	 * Filters the value of the api constant.
	 *
	 * @param String $constant_value The constant value.
	 * @param String $constant_name The constant name.
	 * @return mixed | null
	 */
	public static function jetpack_api_constant_filter( $constant_value, $constant_name ) {
		if ( $constant_value !== null ) {
			// If the constant value was already set elsewhere, use that value.
			return $constant_value;
		}

		if ( defined( "self::DEFAULT_$constant_name" ) ) {
			return constant( "self::DEFAULT_$constant_name" );
		}

		return null;
	}

	/**
	 * Add a filter to initialize default values of the constants.
	 */
	public static function init_default_constants() {
		add_filter(
			'jetpack_constant_default_value',
			array( __CLASS__, 'jetpack_api_constant_filter' ),
			10,
			2
		);
	}

	/**
	 * Filters the registration request body to include tracking properties.
	 *
	 * @param array $properties Already prepared tracking properties.
	 * @return array amended properties.
	 */
	public static function filter_register_request_body( $properties ) {
		$tracking        = new Tracking();
		$tracks_identity = $tracking->tracks_get_identity( get_current_user_id() );

		return array_merge(
			$properties,
			array(
				'_ui' => $tracks_identity['_ui'],
				'_ut' => $tracks_identity['_ut'],
			)
		);
	}
}
