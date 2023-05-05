<?php
/**
 * Google Drive helper.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Forms\Service;

use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\Connection\Manager;
use Automattic\Jetpack\Status\Visitor;

/**
 * Class Google_Drive
 */
class Google_Drive {
	/**
	 * Checks if the user has a valid connection to Google Drive
	 *
	 * @param int $user_id The user ID.
	 * @return array       Array with single 'valid' (bool) entry.
	 */
	public static function has_valid_connection( $user_id ) {
		$site_id = Manager::get_site_id();
		if ( is_wp_error( $site_id ) ) {
			return false;
		}

		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			// check for gdrive helper class, call synchronously on .com
			require_lib( 'google-sheets-helper' );
			$user_id = (int) get_current_user_id();
			$token   = \WPCOM_Google_Sheets_helper::get_google_drive_token_for_user_id( $user_id );

			return ! is_wp_error( $token ) && ! $token->is_expired();
		}

		$request_path  = sprintf( '/sites/%d/google-drive/connection', $site_id );
		$wpcom_request = Client::wpcom_json_api_request_as_user(
			$request_path,
			'2',
			array(
				'method'  => 'GET',
				'headers' => array(
					'content-type'    => 'application/json',
					'X-Forwarded-For' => ( new Visitor() )->get_ip( true ),
				),
			)
		);

		$response_code = wp_remote_retrieve_response_code( $wpcom_request );
		if ( 200 !== $response_code ) {
			return new \WP_Error(
				'failed_to_fetch_data',
				esc_html__( 'Unable to fetch the requested data.', 'jetpack-forms' ),
				array( 'status' => $response_code )
			);
		}
		$result = json_decode( wp_remote_retrieve_body( $wpcom_request ), true );

		return ! empty( $result ) && ! empty( $result['valid'] );
	}

	/**
	 * Creates a Google Spreadsheet and returns some of its meta
	 *
	 * @param int    $user_id The user ID.
	 * @param string $title   The spreadsheet title.
	 * @param array  $rows    Array of arrays with values.
	 * @return array
	 */
	public static function create_sheet( $user_id, $title, $rows = array() ) {
		$site_id = Manager::get_site_id();
		if ( is_wp_error( $site_id ) ) {
			return false;
		}

		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			// check for gdrive helper class, call synchronously on .com
			require_lib( 'google-sheets-helper' );
			$helper = \WPCOM_Google_Sheets_helper::create_for_user( $user_id );

			if ( is_wp_error( $helper ) ) {
				return $helper;
			}

			$spreadsheet = $helper->create_spreadsheet( $title, $rows );

			if ( is_wp_error( $spreadsheet ) ) {
				return $spreadsheet;
			}

			return array(
				// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- as is on google client
				'sheet_link' => $spreadsheet->spreadsheetUrl,
				// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- as is on google client
				'sheet_id'   => $spreadsheet->spreadsheetId,
			);
		}

		$request_path  = sprintf( '/sites/%d/google-drive/sheets', $site_id );
		$wpcom_request = Client::wpcom_json_api_request_as_user(
			$request_path,
			'2',
			array(
				'method'  => 'POST',
				'headers' => array(
					'content-type'    => 'application/json',
					'X-Forwarded-For' => ( new Visitor() )->get_ip( true ),
				),
			),
			array(
				'title' => $title,
				'rows'  => $rows,
			)
		);
		$response_code = wp_remote_retrieve_response_code( $wpcom_request );
		if ( 200 !== $response_code ) {
			return new \WP_Error(
				'failed_to_fetch_data',
				esc_html__( 'Unable to fetch the requested data.', 'jetpack-forms' ),
				array( 'status' => $response_code )
			);
		}
		return json_decode( wp_remote_retrieve_body( $wpcom_request ), true );
	}
}
