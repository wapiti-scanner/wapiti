<?php
/**
 * VideoPress Token
 *
 * @package automattic/jetpack-videopress
 */

namespace Automattic\Jetpack\VideoPress;

use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Jetpack_Options;
/**
 * VideoPress token utility class
 */
class VideoPressToken {
	/**
	 * Check if user is connected.
	 *
	 * @return bool
	 * @throws Upload_Exception - If user is not connected.
	 */
	private static function check_connection() {
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			return true;
		}
		if ( ! ( new Connection_Manager() )->has_connected_owner() ) {
			throw new Upload_Exception( __( 'You need to connect Jetpack before being able to upload a video to VideoPress.', 'jetpack-videopress-pkg' ) );
		}
		return true;
	}

	/**
	 * Get current blog id.
	 *
	 * @return string - Blog id.
	 */
	public static function blog_id() {
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$blog_id = get_current_blog_id();
		} else {
			$blog_id = Jetpack_Options::get_option( 'id' );
		}

		return $blog_id;
	}

	/**
	 * Retrieve a Playback JWT via WPCOM api.
	 *
	 * @param string $guid The VideoPress GUID.
	 * @return string
	 */
	public static function videopress_playback_jwt( $guid ) {
		$blog_id = static::blog_id();

		$args = array(
			'method' => 'POST',
		);

		$endpoint = "sites/{$blog_id}/media/videopress-playback-jwt/{$guid}";

		$result = Client::wpcom_json_api_request_as_blog( $endpoint, 'v2', $args, null, 'wpcom' );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$response = json_decode( $result['body'], true );

		if ( empty( $response['metadata_token'] ) ) {
			return false;
		}

		return $response['metadata_token'];
	}

	/**
	 * Retrieve a One Time Upload Token via WPCOM api.
	 *
	 * @return string
	 * @throws Upload_Exception If token is empty or is had an error.
	 */
	public static function videopress_onetime_upload_token() {
		if ( static::check_connection() ) {
			$blog_id = static::blog_id();

			$args = array(
				'method' => 'POST',
			);

			$endpoint = "sites/{$blog_id}/media/token";
			$result   = Client::wpcom_json_api_request_as_blog( $endpoint, Client::WPCOM_JSON_API_VERSION, $args );

			if ( is_wp_error( $result ) ) {
				throw new Upload_Exception( __( 'Could not obtain a VideoPress upload token. Please try again later.', 'jetpack-videopress-pkg' ) );
			}

			$response = json_decode( $result['body'], true );

			if ( empty( $response['upload_token'] ) ) {
				throw new Upload_Exception( __( 'Could not obtain a VideoPress upload token. Please try again later.', 'jetpack-videopress-pkg' ) );
			}

			return $response['upload_token'];
		}
	}

	/**
	 * Gets the VideoPress Upload JWT
	 *
	 * @return string
	 * @throws Upload_Exception - If user is not connected, if token is empty or failed to obtain.
	 */
	public static function videopress_upload_jwt() {
		if ( static::check_connection() ) {
			$blog_id  = static::blog_id();
			$endpoint = "sites/{$blog_id}/media/videopress-upload-jwt";
			$args     = array( 'method' => 'POST' );
			$result   = Client::wpcom_json_api_request_as_blog( $endpoint, 'v2', $args, null, 'wpcom' );

			if ( is_wp_error( $result ) ) {
				throw new Upload_Exception(
					__( 'Could not obtain a VideoPress upload JWT. Please try again later.', 'jetpack-videopress-pkg' ) .
					'(' . $result->get_error_message() . ')'
				);
			}

			$response = json_decode( $result['body'], true );

			if ( empty( $response['upload_token'] ) ) {
				throw new Upload_Exception( __( 'Could not obtain a VideoPress upload JWT. Please try again later. (empty upload token)', 'jetpack-videopress-pkg' ) );
			}

			return $response['upload_token'];
		}
	}
}
