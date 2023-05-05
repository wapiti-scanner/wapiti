<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

namespace Automattic\Jetpack\VideoPress;

use Automattic\Jetpack\Connection\Client;
use \VIDEOPRESS_PRIVACY;

/**
 * VideoPress AJAX action handlers and utilities.
 */
class AJAX {

	/**
	 * Singleton AJAX instance.
	 *
	 * @var AJAX
	 **/
	private static $instance = null;

	/**
	 * Private AJAX constructor.
	 *
	 * Use the AJAX::init() method to get an instance.
	 */
	private function __construct() {
		add_action( 'wp_ajax_videopress-get-upload-token', array( $this, 'wp_ajax_videopress_get_upload_token' ) );
		add_action( 'wp_ajax_videopress-get-upload-jwt', array( $this, 'wp_ajax_videopress_get_upload_jwt' ) );
		add_action( 'wp_ajax_nopriv_videopress-get-playback-jwt', array( $this, 'wp_ajax_videopress_get_playback_jwt' ) );
		add_action( 'wp_ajax_videopress-get-playback-jwt', array( $this, 'wp_ajax_videopress_get_playback_jwt' ) );

		add_action(
			'wp_ajax_videopress-update-transcoding-status',
			array(
				$this,
				'wp_ajax_update_transcoding_status',
			),
			-1
		);
	}

	/**
	 * Initialize the AJAX and get back a singleton instance.
	 *
	 * @return AJAX
	 */
	public static function init() {
		if ( self::$instance === null ) {
			self::$instance = new AJAX();
		}

		return self::$instance;
	}

	/**
	 * Validate a guid.
	 *
	 * @param string $guid The guid to validate.
	 *
	 * @return bool
	 **/
	private function is_valid_guid( $guid ) {
		if ( empty( $guid ) ) {
			return false;
		}

		preg_match( '/^[a-z0-9]+$/i', $guid, $matches );

		if ( empty( $matches ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Ajax method that is used by the VideoPress player to get a token to play a video.
	 *
	 * This is used for both logged in and logged out users.
	 *
	 * @return void
	 */
	public function wp_ajax_videopress_get_playback_jwt() {
		$guid             = filter_input( INPUT_POST, 'guid' );
		$embedded_post_id = filter_input( INPUT_POST, 'post_id', FILTER_VALIDATE_INT );

		if ( empty( $embedded_post_id ) ) {
			$embedded_post_id = 0;
		}

		if ( empty( $guid ) || ! $this->is_valid_guid( $guid ) ) {
			wp_send_json_error( array( 'message' => __( 'need a guid', 'jetpack-videopress-pkg' ) ) );
			return;
		}

		if ( ! $this->is_current_user_authed_for_video( $guid, $embedded_post_id ) ) {
			wp_send_json_error( array( 'message' => __( 'You cannot view this video.', 'jetpack-videopress-pkg' ) ) );
			return;
		}

		$token = $this->request_jwt_from_wpcom( $guid );

		if ( empty( $token ) ) {
			wp_send_json_error( array( 'message' => __( 'Could not obtain a VideoPress playback JWT. Please try again later. (empty upload token)', 'jetpack-videopress-pkg' ) ) );
			return;
		}

		if ( is_wp_error( $token ) ) {
			wp_send_json_error( array( 'message' => __( 'Could not obtain a VideoPress upload JWT. Please try again later.', 'jetpack-videopress-pkg' ) ) );
			return;
		}

		wp_send_json_success( array( 'jwt' => $token ) );
	}

	/**
	 * Determines if the current user can view the provided video. Only ever gets fired if site-wide private videos are enabled.
	 *
	 * Filterable for 3rd party plugins.
	 *
	 * @param string $guid             The video id being checked.
	 * @param int    $embedded_post_id The post id the video is embedded in or 0.
	 */
	private function is_current_user_authed_for_video( $guid, $embedded_post_id ) {
		$attachment = videopress_get_post_by_guid( $guid );
		if ( ! $attachment ) {
			return false;
		}

		$video_info = video_get_info_by_blogpostid( get_current_blog_id(), $attachment->ID );
		if ( null === $video_info->guid ) {
			return false;
		}

		$is_user_authed = false;
		// Determine if video is public, private or use site default.
		switch ( $video_info->privacy_setting ) {
			case VIDEOPRESS_PRIVACY::IS_PUBLIC:
				$is_user_authed = true;
				break;
			case VIDEOPRESS_PRIVACY::IS_PRIVATE:
				$is_user_authed = current_user_can( 'read' );
				break;
			case VIDEOPRESS_PRIVACY::SITE_DEFAULT:
			default:
				$is_videopress_private_for_site = Data::get_videopress_videos_private_for_site();
				$is_user_authed                 = false === $is_videopress_private_for_site || ( $is_videopress_private_for_site && current_user_can( 'read' ) );
				break;
		}

		/**
		 * Overrides video view authorization for current user.
		 *
		 * Example of making all videos public:
		 *
		 * function jp_example_override_video_auth( $is_user_authed, $guid ) {
		 *  return true
		 * };
		 * add_filter( 'videopress_is_current_user_authed_for_video', 'jp_example_override_video_auth', 10, 2 );
		 *
		 * @param bool     $is_user_authed   The current user authorization state.
		 * @param string   $guid             The video's unique identifier.
		 * @param int|null $embedded_post_id The post the video is embedded..
		 *
		 * @return bool
		 */
		return (bool) apply_filters( 'videopress_is_current_user_authed_for_video', $is_user_authed, $guid, $embedded_post_id );
	}

	/**
	 * Requests JWT from wpcom.
	 *
	 * @param string $guid The video id being checked.
	 */
	private function request_jwt_from_wpcom( $guid ) {
		$options = Options::get_options();

		$args = array(
			'method' => 'POST',
		);

		$endpoint = "sites/{$options['shadow_blog_id']}/media/videopress-playback-jwt/{$guid}";
		$result   = Client::wpcom_json_api_request_as_blog( $endpoint, 'v2', $args, null, 'wpcom' );
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
	 * Ajax method that is used by the VideoPress uploader to get a token to upload a file to the wpcom api.
	 *
	 * @return void
	 */
	public function wp_ajax_videopress_get_upload_jwt() {

		$options = Options::get_options();

		$args = array(
			'method' => 'POST',
		);

		$endpoint = "sites/{$options['shadow_blog_id']}/media/videopress-upload-jwt";
		$result   = Client::wpcom_json_api_request_as_blog( $endpoint, 'v2', $args, null, 'wpcom' );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => __( 'Could not obtain a VideoPress upload JWT. Please try again later.', 'jetpack-videopress-pkg' ) ) );
			return;
		}

		$response = json_decode( $result['body'], true );

		if ( empty( $response['upload_token'] ) ) {
			wp_send_json_error( array( 'message' => __( 'Could not obtain a VideoPress upload JWT. Please try again later. (empty upload token)', 'jetpack-videopress-pkg' ) ) );
			return;
		}

		$response['upload_action_url'] = videopress_make_resumable_upload_path( $options['shadow_blog_id'] );

		wp_send_json_success( $response );
	}

	/**
	 * Ajax method that is used by the VideoPress uploader to get a token to upload a file to the wpcom api.
	 *
	 * @return void
	 */
	public function wp_ajax_videopress_get_upload_token() {

		$options = Options::get_options();

		$args = array(
			'method' => 'POST',
		);

		$endpoint = "sites/{$options['shadow_blog_id']}/media/token";
		$result   = Client::wpcom_json_api_request_as_blog( $endpoint, Client::WPCOM_JSON_API_VERSION, $args );

		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => __( 'Could not obtain a VideoPress upload token. Please try again later.', 'jetpack-videopress-pkg' ) ) );
			return;
		}

		$response = json_decode( $result['body'], true );

		if ( empty( $response['upload_token'] ) ) {
			wp_send_json_error( array( 'message' => __( 'Could not obtain a VideoPress upload token. Please try again later.', 'jetpack-videopress-pkg' ) ) );
			return;
		}

		$response['upload_action_url'] = videopress_make_media_upload_path( $options['shadow_blog_id'] );

		wp_send_json_success( $response );
	}

	/**
	 * Ajax action to update the video transcoding status from the WPCOM API.
	 *
	 * @return void
	 */
	public function wp_ajax_update_transcoding_status() {
		if ( ! isset( $_POST['post_id'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Informational AJAX response.
			wp_send_json_error( array( 'message' => __( 'A valid post_id is required.', 'jetpack-videopress-pkg' ) ) );
			return;
		}

		$post_id = (int) $_POST['post_id']; // phpcs:ignore WordPress.Security.NonceVerification.Missing

		if ( ! videopress_update_meta_data( $post_id ) ) {
			wp_send_json_error( array( 'message' => __( 'That post does not have a VideoPress video associated to it.', 'jetpack-videopress-pkg' ) ) );
			return;
		}

		wp_send_json_success(
			array(
				'message' => __( 'Status updated', 'jetpack-videopress-pkg' ),
				'status'  => videopress_get_transcoding_status( $post_id ),
			)
		);
	}
}
