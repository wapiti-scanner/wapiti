<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Upload media item API endpoint.
 *
 * Endpoint: /sites/%s/media/new
 */

new WPCOM_JSON_API_Upload_Media_Endpoint(
	array(
		'description'          => 'Upload a new media item.',
		'group'                => 'media',
		'stat'                 => 'media:new',
		'method'               => 'POST',
		'path'                 => '/sites/%s/media/new',
		'deprecated'           => true,
		'new_version'          => '1.1',
		'max_version'          => '1',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
		),

		'request_format'       => array(
			'media'      => '(media) An array of media to attach to the post. To upload media, the entire request should be multipart/form-data encoded. Accepts images (image/gif, image/jpeg, image/png) only at this time.<br /><br /><strong>Example</strong>:<br />' .
							"<code>curl \<br />--form 'media[]=@/path/to/file.jpg' \<br />-H 'Authorization: BEARER your-token' \<br />'https://public-api.wordpress.com/rest/v1/sites/123/media/new'</code>",
			'media_urls' => '(array) An array of URLs to upload to the post.',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/media/new/',

		'response_format'      => array(
			'media'  => '(array) Array of uploaded media',
			'errors' => '(array) Array of error messages of uploading media failures',
		),
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'media_urls' => 'https://s.w.org/about/images/logos/codeispoetry-rgb.png',
			),
		),
	)
);

/**
 * Upload media item API class.
 */
class WPCOM_JSON_API_Upload_Media_Endpoint extends WPCOM_JSON_API_Endpoint {
	/**
	 * Upload media item API endpoint callback.
	 *
	 * @param string $path API path.
	 * @param int    $blog_id Blog ID.
	 */
	public function callback( $path = '', $blog_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		if ( ! current_user_can( 'upload_files' ) ) {
			return new WP_Error( 'unauthorized', 'User cannot upload media.', 403 );
		}

		$input = $this->input( true );

		$has_media      = isset( $input['media'] ) && $input['media'] ? count( $input['media'] ) : false;
		$has_media_urls = isset( $input['media_urls'] ) && $input['media_urls'] ? count( $input['media_urls'] ) : false;

		$errors    = array();
		$files     = array();
		$media_ids = array();

		if ( $has_media ) {
			$this->api->trap_wp_die( 'upload_error' );
			foreach ( $input['media'] as $index => $media_item ) {
				$_FILES['.api.media.item.'] = $media_item;
				// check for WP_Error if we ever actually need $media_id.
				$media_id = media_handle_upload( '.api.media.item.', 0 );
				if ( is_wp_error( $media_id ) ) {
					if ( 1 === count( $input['media'] ) && ! $has_media_urls ) {
						unset( $_FILES['.api.media.item.'] );
						return $media_id;
					}
					$errors[ $index ]['error']   = $media_id->get_error_code();
					$errors[ $index ]['message'] = $media_id->get_error_message();
				} else {
					$media_ids[ $index ] = $media_id;
				}
				$files[] = $media_item;
			}
			$this->api->trap_wp_die( null );

			unset( $_FILES['.api.media.item.'] );
		}

		if ( $has_media_urls ) {
			foreach ( $input['media_urls'] as $url ) {
				$id = $this->handle_media_sideload( $url );
				if ( ! empty( $id ) && is_int( $id ) ) {
					$media_ids[] = $id;
				}
			}
		}

		$results = array();
		foreach ( $media_ids as $media_id ) {
			$results[] = $this->get_media_item( $media_id );
		}

		return array(
			'media'  => $results,
			'errors' => $errors,
		);
	}
}
