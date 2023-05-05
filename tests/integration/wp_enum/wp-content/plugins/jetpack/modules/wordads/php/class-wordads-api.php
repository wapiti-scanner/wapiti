<?php
/**
 * The WordAds API.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\Status;

/**
 * Methods for accessing data through the WPCOM REST API
 *
 * @since 4.5.0
 */
class WordAds_API {

	/**
	 * Get the site's WordAds status
	 *
	 * @return array|WP_Error Array of site status values, or WP_Error if no response from the API.
	 *
	 * @since 4.5.0
	 */
	public static function get_wordads_status() {
		global $wordads_status_response;

		// If the site is not connected, we can put it in a safe "house ad" mode.
		if ( ( new Status() )->is_offline_mode() ) {
			return array(
				'approved' => true,
				'active'   => true,
				'house'    => true,
				'unsafe'   => false,
			);
		}

		// Fetch the status from WPCOM endpoint.
		$endpoint                = sprintf( '/sites/%d/wordads/status', Jetpack::get_option( 'id' ) );
		$response                = Client::wpcom_json_api_request_as_blog( $endpoint );
		$wordads_status_response = $response;

		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return new WP_Error( 'api_error', __( 'Error connecting to API.', 'jetpack' ), $response );
		}

		$body = json_decode( wp_remote_retrieve_body( $response ) );

		return array(
			'approved' => (bool) $body->approved,
			'active'   => (bool) $body->active,
			'house'    => (bool) $body->house,
			'unsafe'   => (bool) $body->unsafe,
		);
	}

	/**
	 * Grab WordAds status from WP.com API and store as option
	 *
	 * @since 4.5.0
	 */
	public static function update_wordads_status_from_api() {
		$status = self::get_wordads_status();

		if ( ! is_wp_error( $status ) ) {

			// Convert boolean options to string first to work around update_option not setting the option if the value is false.
			// This sets the option to either '1' if true or '' if false.
			update_option( 'wordads_approved', (string) $status['approved'], true );
			update_option( 'wordads_active', (string) $status['active'], true );
			update_option( 'wordads_house', (string) $status['house'], true );
			update_option( 'wordads_unsafe', (string) $status['unsafe'], true );
		}
	}

	/**
	 * Returns the ads.txt content needed to run WordAds.
	 *
	 * @return array string contents of the ads.txt file.
	 *
	 * @since 6.1.0
	 */
	public static function get_wordads_ads_txt() {
		global $wordads_status_response;

		$endpoint                = sprintf( '/sites/%d/wordads/ads-txt', Jetpack::get_option( 'id' ) );
		$response                = Client::wpcom_json_api_request_as_blog( $endpoint );
		$wordads_status_response = $response;
		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return new WP_Error( 'api_error', __( 'Error connecting to API.', 'jetpack' ), $response );
		}

		$body    = json_decode( wp_remote_retrieve_body( $response ) );
		$ads_txt = str_replace( '\\n', PHP_EOL, $body->adstxt );

		return $ads_txt;
	}
}
