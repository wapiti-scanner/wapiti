<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

new WPCOM_JSON_API_Get_Media_Endpoint(
	array(
		'description'          => 'Get a single media item (by ID).',
		'group'                => 'media',
		'stat'                 => 'media:1',
		'method'               => 'GET',
		'path'                 => '/sites/%s/media/%d',
		'deprecated'           => true,
		'new_version'          => '1.1',
		'max_version'          => '1',
		'path_labels'          => array(
			'$site'     => '(int|string) Site ID or domain',
			'$media_ID' => '(int) The ID of the media item',
		),
		'response_format'      => array(
			'id'          => '(int) The ID of the media item',
			'date'        => '(ISO 8601 datetime) The date the media was uploaded',
			'parent'      => '(int) ID of the post this media is attached to',
			'link'        => '(string) URL to the file',
			'title'       => '(string) Filename',
			'caption'     => '(string) User-provided caption of the file',
			'description' => '(string) Description of the file',
			'metadata'    => '(array) Array of metadata about the file, such as Exif data or sizes',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/media/934',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
	)
);

/**
 * GET Media endpoint class.
 */
class WPCOM_JSON_API_Get_Media_Endpoint extends WPCOM_JSON_API_Endpoint {
	/**
	 *
	 * API callback.
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 * @param int    $media_id - the media ID.
	 */
	public function callback( $path = '', $blog_id = 0, $media_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		// upload_files can probably be used for other endpoints but we want contributors to be able to use media too.
		if ( ! current_user_can( 'edit_posts', $media_id ) ) {
			return new WP_Error( 'unauthorized', 'User cannot view media', 403 );
		}

		return $this->get_media_item( $media_id );
	}
}
