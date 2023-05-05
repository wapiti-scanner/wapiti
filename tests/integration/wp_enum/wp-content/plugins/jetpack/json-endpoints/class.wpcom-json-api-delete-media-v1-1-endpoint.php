<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

new WPCOM_JSON_API_Delete_Media_v1_1_Endpoint(
	array(
		'description'          => 'Delete a piece of media. Note: Media is deleted and not trashed.',
		'group'                => 'media',
		'stat'                 => 'media:1:delete',
		'min_version'          => '1.1',
		'max_version'          => '1.1',
		'method'               => 'POST',
		'path'                 => '/sites/%s/media/%d/delete',
		'path_labels'          => array(
			'$site'     => '(int|string) Site ID or domain',
			'$media_ID' => '(int) The media ID',
		),

		'response_format'      => array(
			'status'                     => '(string) Returns deleted if the media was successfully deleted',
			'ID'                         => '(int) The ID of the media item',
			'date'                       => '(ISO 8601 datetime) The date the media was uploaded',
			'post_ID'                    => '(int) ID of the post this media is attached to',
			'author_ID'                  => '(int) ID of the user who uploaded the media',
			'URL'                        => '(string) URL to the file',
			'guid'                       => '(string) Unique identifier',
			'file'                       => '(string) File name',
			'extension'                  => '(string) File extension',
			'mime_type'                  => '(string) File mime type',
			'title'                      => '(string) File name',
			'caption'                    => '(string) User-provided caption of the file',
			'description'                => '(string) Description of the file',
			'alt'                        => '(string)  Alternative text for image files.',
			'thumbnails'                 => '(object) Media item thumbnail URL options',
			'height'                     => '(int) (Image & video only) Height of the media item',
			'width'                      => '(int) (Image & video only) Width of the media item',
			'length'                     => '(int) (Video & audio only) Duration of the media item, in seconds',
			'exif'                       => '(array) (Image & audio only) Exif (meta) information about the media item',
			'videopress_guid'            => '(string) (Video only) VideoPress GUID of the video when uploaded on a blog with VideoPress',
			'videopress_processing_done' => '(bool) (Video only) If the video is Uuploaded on a blog with VideoPress, this will return the status of processing on the Video',
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
 * Delete media v1_1 endpoint class.
 */
class WPCOM_JSON_API_Delete_Media_v1_1_Endpoint extends WPCOM_JSON_API_Endpoint { //phpcs:ignore
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
			return new WP_Error( 'unauthorized', 'User is not authorized delete media', 403 );
		}

		$item = $this->get_media_item_v1_1( $media_id );

		if ( is_wp_error( $item ) ) {
			return new WP_Error( 'unknown_media', 'Unknown Media', 404 );
		}

		wp_delete_post( $media_id, true );
		$item->status = 'deleted';
		return $item;
	}
}
