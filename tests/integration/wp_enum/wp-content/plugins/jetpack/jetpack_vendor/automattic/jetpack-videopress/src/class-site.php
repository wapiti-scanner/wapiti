<?php
/**
 * Provides site data sourced from WPCOM
 *
 * @package automattic/jetpack-videopress
 */

namespace Automattic\Jetpack\VideoPress;

use Automattic\Jetpack\Connection\Client;
use WP_Error;

/**
 * Provides site data sourced from WPCOM
 */
class Site {

	/**
	 * Returns all the data provided by WPCOM for the site.
	 *
	 * @return int|WP_Error the total of plays for today, or WP_Error on failure.
	 */
	public static function get_site_info() {
		$error = new WP_Error(
			'videopress_site_error',
			__( 'Could not fetch site information from the service', 'jetpack-videopress-pkg' )
		);

		$request_path = sprintf( 'sites/%d?force=wpcom', Data::get_blog_id() );
		$response     = Client::wpcom_json_api_request_as_blog( $request_path, '1.1', array(), null, 'rest' );

		if ( is_wp_error( $response ) ) {
			return $error;
		}

		$response_code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $response_code ) {
			return $error;
		}

		$body = wp_remote_retrieve_body( $response );

		return json_decode( $body, true );
	}

	/**
	 * Returns all the purchases provided by WPCOM for the site.
	 *
	 * @return array the list of purchases, or an empty list on failure.
	 */
	public static function get_purchases() {
		$request_path = sprintf( 'sites/%1$d/purchases?locale=%2$s', Data::get_blog_id(), get_user_locale() );
		$response     = Client::wpcom_json_api_request_as_blog( $request_path, '1.1', array(), null, 'rest' );

		if ( is_wp_error( $response ) ) {
			return array();
		}

		$response_code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $response_code ) {
			return array();
		}

		$body = wp_remote_retrieve_body( $response );

		return json_decode( $body, true );
	}
}
