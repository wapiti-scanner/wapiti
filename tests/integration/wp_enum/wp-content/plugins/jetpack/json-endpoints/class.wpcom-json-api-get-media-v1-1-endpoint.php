<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

new WPCOM_JSON_API_Get_Media_v1_1_Endpoint(
	array(
		'description'          => 'Get a single media item (by ID).',
		'group'                => 'media',
		'stat'                 => 'media:1',
		'min_version'          => '1.1',
		'max_version'          => '1.1',
		'method'               => 'GET',
		'path'                 => '/sites/%s/media/%d',
		'path_labels'          => array(
			'$site'     => '(int|string) Site ID or domain',
			'$media_ID' => '(int) The ID of the media item',
		),
		'response_format'      => array(
			'ID'                         => '(int) The ID of the media item',
			'date'                       => '(ISO 8601 datetime) The date the media was uploaded',
			'post_ID'                    => '(int) ID of the post this media is attached to',
			'author_ID'                  => '(int) ID of the user who uploaded the media',
			'URL'                        => '(string) URL to the file',
			'guid'                       => '(string) Unique identifier',
			'file'                       => '(string) Filename',
			'extension'                  => '(string) File extension',
			'mime_type'                  => '(string) File MIME type',
			'title'                      => '(string) Filename',
			'caption'                    => '(string) User-provided caption of the file',
			'description'                => '(string) Description of the file',
			'alt'                        => '(string)  Alternative text for image files.',
			'thumbnails'                 => '(object) Media item thumbnail URL options',
			'height'                     => '(int) (Image & video only) Height of the media item',
			'width'                      => '(int) (Image & video only) Width of the media item',
			'length'                     => '(int) (Video & audio only) Duration of the media item, in seconds',
			'exif'                       => '(array) (Image & audio only) Exif (meta) information about the media item',
			'rating'                     => '(string) (Video only) VideoPress rating of the video',
			'display_embed'              => '(string) Video only. Whether to share or not the video.',
			'allow_download'             => '(string) Video only. Whether the video can be downloaded or not.',
			'videopress_guid'            => '(string) (Video only) VideoPress GUID of the video when uploaded on a blog with VideoPress',
			'videopress_processing_done' => '(bool) (Video only) If the video is uploaded on a blog with VideoPress, this will return the status of processing on the video.',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1.1/sites/82974409/media/934',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
	)
);

/**
 * GET Media v1_1 endpoint.
 */
class WPCOM_JSON_API_Get_Media_v1_1_Endpoint extends WPCOM_JSON_API_Endpoint { //phpcs:ignore
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

		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$this->load_theme_functions();
		}

		// upload_files can probably be used for other endpoints but we want contributors to be able to use media too.
		if ( ! current_user_can( 'edit_posts', $media_id ) ) {
			return new WP_Error( 'unauthorized', 'User cannot view media', 403 );
		}

		return $this->get_media_item_v1_1( $media_id );
	}
}
