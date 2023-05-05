<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Update media item info endpoint.
 *
 * Endpoint: /sites/%s/media/%d
 */

new WPCOM_JSON_API_Update_Media_Endpoint(
	array(
		'description'          => 'Edit basic information about a media item.',
		'group'                => 'media',
		'stat'                 => 'media:1:POST',
		'method'               => 'POST',
		'path'                 => '/sites/%s/media/%d',
		'deprecated'           => true,
		'max_version'          => '1',
		'new_version'          => '1.1',
		'path_labels'          => array(
			'$site'     => '(int|string) Site ID or domain',
			'$media_ID' => '(int) The ID of the media item',
		),

		'request_format'       => array(
			'title'       => '(string) The file name.',
			'caption'     => '(string) File caption.',
			'description' => '(HTML) Description of the file.',
		),

		'response_format'      => array(
			'id'          => '(int) The ID of the media item',
			'date'        => '(ISO 8601 datetime) The date the media was uploaded',
			'parent'      => '(int) ID of the post this media is attached to',
			'link'        => '(string) URL to the file',
			'title'       => '(string) File name',
			'caption'     => '(string) User provided caption of the file',
			'description' => '(string) Description of the file',
			'metadata'    => '(array) Array of metadata about the file, such as Exif data or sizes',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1.1/sites/82974409/media/446',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'title' => 'Updated Title',
			),
		),
	)
);

/**
 * Update media item info class.
 */
class WPCOM_JSON_API_Update_Media_Endpoint extends WPCOM_JSON_API_Endpoint {
	/**
	 * Update media item info API callback.
	 *
	 * @param string $path API path.
	 * @param int    $blog_id Blog ID.
	 * @param int    $media_id Media ID.
	 *
	 * @return object|WP_Error
	 */
	public function callback( $path = '', $blog_id = 0, $media_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		if ( ! current_user_can( 'upload_files', $media_id ) ) {
			return new WP_Error( 'unauthorized', 'User cannot view media', 403 );
		}

		$item = $this->get_media_item( $media_id );

		if ( is_wp_error( $item ) ) {
			return new WP_Error( 'unknown_media', 'Unknown Media', 404 );
		}

		$input  = $this->input( true );
		$insert = array();

		if ( ! empty( $input['title'] ) ) {
			$insert['post_title'] = $input['title'];
		}

		if ( ! empty( $input['caption'] ) ) {
			$insert['post_excerpt'] = $input['caption'];
		}

		if ( ! empty( $input['description'] ) ) {
			$insert['post_content'] = $input['description'];
		}

		$insert['ID'] = $media_id;
		wp_update_post( (object) $insert );

		$item = $this->get_media_item( $media_id );
		return $item;
	}
}
