<?php
/**
 * The VIdeoPress XMLRPC class
 *
 * @package automattic/jetpack-videopress
 */

namespace Automattic\Jetpack\VideoPress;

/**
 * VideoPress playback module markup generator.
 *
 * @since 0.1.1
 */
class XMLRPC {

	/**
	 * Singleton XMLRPC instance.
	 *
	 * @var XMLRPC
	 **/
	private static $instance = null;

	/**
	 * The current user object.
	 *
	 * @var WP_User
	 */
	private $current_user;

	/**
	 * Private VideoPress_XMLRPC constructor.
	 *
	 * Use the VideoPress_XMLRPC::init() method to get an instance.
	 */
	private function __construct() {
		add_filter( 'jetpack_xmlrpc_methods', array( $this, 'xmlrpc_methods' ), 10, 3 );
	}

	/**
	 * Initialize the VideoPress_XMLRPC and get back a singleton instance.
	 *
	 * @return XMLRPC
	 */
	public static function init() {
		if ( self::$instance === null ) {
			self::$instance = new XMLRPC();
		}

		return self::$instance;
	}

	/**
	 * Adds additional methods the WordPress xmlrpc API for handling VideoPress specific features
	 *
	 * @param array   $methods The Jetpack API methods.
	 * @param array   $core_methods The WordPress Core API methods (ignored).
	 * @param WP_User $user The user object the API request is signed by.
	 *
	 * @return array
	 */
	public function xmlrpc_methods( $methods, $core_methods, $user ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		if ( $user && $user instanceof WP_User ) {
			$this->current_user = $user;
		}

		$methods['jetpack.createMediaItem']             = array( $this, 'create_media_item' );
		$methods['jetpack.updateVideoPressMediaItem']   = array( $this, 'update_videopress_media_item' );
		$methods['jetpack.updateVideoPressPosterImage'] = array( $this, 'update_poster_image' );

		return $methods;
	}

	/**
	 * This is used by the WPCOM VideoPress uploader in order to create a media item with
	 * specific meta data about an uploaded file. After this, the transcoding session will
	 * update the meta information via the update_videopress_media_item() method.
	 *
	 * Note: This method technically handles the creation of multiple media objects, though
	 * in practice this is never done.
	 *
	 * @param array $media Media items being uploaded.
	 * @return array
	 */
	public function create_media_item( $media ) {
		$this->authenticate_user();

		foreach ( $media as & $media_item ) {
			$title = sanitize_title( basename( $media_item['url'] ) );
			$guid  = isset( $media['guid'] ) ? $media['guid'] : null;

			$media_id = videopress_create_new_media_item( $title, $guid );

			wp_update_attachment_metadata(
				$media_id,
				array(
					'original' => array(
						'url' => $media_item['url'],
					),
				)
			);

			$media_item['post'] = get_post( $media_id );
		}

		return array( 'media' => $media );
	}

	/**
	 * Update VideoPress metadata for a media item.
	 *
	 * @param array $request Media item to update.
	 *
	 * @return bool
	 */
	public function update_videopress_media_item( $request ) {
		$this->authenticate_user();

		$id     = $request['post_id'];
		$status = $request['status'];
		$format = $request['format'];
		$info   = $request['info'];

		$attachment = get_post( $id );
		if ( ! $attachment ) {
			return false;
		}

		$attachment->guid           = $info['original'];
		$attachment->post_mime_type = 'video/videopress';

		wp_update_post( $attachment );

		// Update the vp guid and set it to a direct meta property.
		update_post_meta( $id, 'videopress_guid', $info['guid'] );

		$meta = wp_get_attachment_metadata( $id );

		$meta['width']             = $info['width'];
		$meta['height']            = $info['height'];
		$meta['original']['url']   = $info['original'];
		$meta['videopress']        = $info;
		$meta['videopress']['url'] = 'https://videopress.com/v/' . $info['guid'];

		// Update file statuses
		if ( ! empty( $format ) ) {
			$meta['file_statuses'][ $format ] = $status;
		}

		if ( ! get_post_meta( $id, '_thumbnail_id', true ) ) {
			// Update the poster in the VideoPress info.
			$thumbnail_id = videopress_download_poster_image( $info['poster'], $id );

			if ( is_int( $thumbnail_id ) ) {
				update_post_meta( $id, '_thumbnail_id', $thumbnail_id );
			}
		}

		wp_update_attachment_metadata( $id, $meta );

		videopress_update_meta_data( $id );

		// update the meta to tell us that we're processing or complete
		update_post_meta( $id, 'videopress_status', videopress_is_finished_processing( $id ) ? 'complete' : 'processing' );

		return true;
	}

	/**
	 * Update poster image for a VideoPress media item.
	 *
	 * @param array $request The media item to update.
	 * @return bool
	 */
	public function update_poster_image( $request ) {
		$this->authenticate_user();

		$post_id = $request['post_id'];
		$poster  = $request['poster'];

		$attachment = get_post( $post_id );
		if ( ! $attachment ) {
			return false;
		}

		$poster = apply_filters( 'jetpack_photon_url', $poster );

		$meta                         = wp_get_attachment_metadata( $post_id );
		$meta['videopress']['poster'] = $poster;
		wp_update_attachment_metadata( $post_id, $meta );

		// Update the poster in the VideoPress info.
		$thumbnail_id = videopress_download_poster_image( $poster, $post_id );

		if ( ! is_int( $thumbnail_id ) ) {
			return false;
		}

		update_post_meta( $post_id, '_thumbnail_id', $thumbnail_id );

		return true;
	}

	/**
	 * Check if the XML-RPC request is signed by a user token, and authenticate the user in WordPress.
	 *
	 * @return bool
	 */
	private function authenticate_user() {
		if ( $this->current_user ) {
			wp_set_current_user( $this->current_user->ID );

			return true;
		}

		return false;
	}
}
