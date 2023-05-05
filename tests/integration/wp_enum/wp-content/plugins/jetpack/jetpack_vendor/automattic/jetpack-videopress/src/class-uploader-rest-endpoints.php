<?php
/**
 * VideoPress Uploader
 *
 * @package automattic/jetpack-videopress
 */

namespace Automattic\Jetpack\VideoPress;

use WP_Error;

/**
 * VideoPress Uploader class
 *
 * Handles the upload from the Media Library to VideoPress servers
 */
class Uploader_Rest_Endpoints {

	/**
	 * Initializes the endpoints
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'rest_api_init', array( __CLASS__, 'register_rest_endpoints' ) );
	}

	/**
	 * Register the REST API routes.
	 *
	 * @return void
	 */
	public static function register_rest_endpoints() {
		$id_arg = array(
			'description'       => __( 'The ID of the attachment you want to upload to VideoPress', 'jetpack-videopress-pkg' ),
			'type'              => 'integer',
			'required'          => true,
			'validate_callback' => __CLASS__ . '::validate_attachment_id',
		);
		register_rest_route(
			'videopress/v1',
			'upload/(?P<attachment_id>\d+)',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => __CLASS__ . '::check_status',
					'permission_callback' => __CLASS__ . '::permissions_callback',
					'args'                => array(
						'attachment_id' => $id_arg,
					),
				),
				array(
					'methods'             => \WP_REST_Server::EDITABLE,
					'callback'            => __CLASS__ . '::do_upload',
					'permission_callback' => __CLASS__ . '::permissions_callback',
					'args'                => array(
						'attachment_id' => $id_arg,
					),
				),
			)
		);
	}

	/**
	 * Checks wether the user have permission to perform the upload
	 *
	 * @return boolean
	 */
	public static function permissions_callback() {
		return current_user_can( 'upload_files' );
	}

	/**
	 * Validates the attachment ID argument
	 *
	 * @param integer|string $value The attachment ID passed as an argument to the endpoint.
	 * @return boolean|WP_Error
	 */
	public static function validate_attachment_id( $value ) {
		return Uploader::is_valid_attachment_id( $value );
	}

	/**
	 * Endpoint callback for the GET method. Checks the upload status
	 *
	 * @param \WP_REST_Request $request The request object.
	 * @return array|WP_Error
	 */
	public static function check_status( $request ) {
		$attachment_id = $request->get_param( 'attachment_id' );
		try {
			$uploader = new Uploader( $attachment_id );
			$status   = $uploader->check_status();
			return rest_ensure_response( $status, 200 );
		} catch ( Upload_Exception $e ) {
			return new WP_Error(
				'rest_invalid_param',
				$e->getMessage(),
				array( 'status' => 400 )
			);
		}
	}

	/**
	 * Endpoint callback for the POST method. Uploads the video
	 *
	 * @param \WP_REST_Request $request The request object.
	 * @return array|WP_Error
	 */
	public static function do_upload( $request ) {
		$attachment_id = $request->get_param( 'attachment_id' );
		try {
			$uploader = new Uploader( $attachment_id );
			$status   = $uploader->upload();
			return rest_ensure_response( $status, 200 );
		} catch ( Upload_Exception $e ) {
			return new WP_Error(
				'rest_invalid_param',
				$e->getMessage(),
				array( 'status' => 400 )
			);
		}
	}

}
