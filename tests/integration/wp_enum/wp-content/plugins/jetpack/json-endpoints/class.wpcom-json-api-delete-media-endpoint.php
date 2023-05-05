<?php // phpcs:ignore Squiz.Commenting.FileComment.Missing

new WPCOM_JSON_API_Delete_Media_Endpoint(
	array(
		'description'          => 'Delete a piece of media.',
		'group'                => 'media',
		'stat'                 => 'media:1:delete',
		'method'               => 'POST',
		'path'                 => '/sites/%s/media/%d/delete',
		'deprecated'           => true,
		'new_version'          => '1.1',
		'max_version'          => '1',
		'path_labels'          => array(
			'$site'     => '(int|string) Site ID or domain',
			'$media_ID' => '(int) The media ID',
		),

		'response_format'      => array(
			'status'      => '(string) Returns deleted if the media was successfully deleted',
			'id'          => '(int) The ID of the media item',
			'date'        => '(ISO 8601 datetime) The date the media was uploaded',
			'parent'      => '(int) ID of the post this media is attached to',
			'link'        => '(string) URL to the file',
			'title'       => '(string) File name',
			'caption'     => '(string) User provided caption of the file',
			'description' => '(string) Description of the file',
			'metadata'    => '(array) Misc array of information about the file, such as exif data or sizes',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1.1/sites/82974409/media/$media_ID/delete',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
	)
);

/**
 * Delete media endpoint class.
 */
class WPCOM_JSON_API_Delete_Media_Endpoint extends WPCOM_JSON_API_Endpoint {
	/**
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

		if ( ! current_user_can( 'delete_post', $media_id ) ) {
			return new WP_Error( 'unauthorized', 'User cannot view media', 403 );
		}

		$item = $this->get_media_item( $media_id );

		if ( is_wp_error( $item ) ) {
			return new WP_Error( 'unknown_media', 'Unknown Media', 404 );
		}

		wp_delete_post( $media_id );
		$item->status = 'deleted';
		return $item;
	}
}
