<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

require_once JETPACK__PLUGIN_DIR . '_inc/lib/class.media.php';

new WPCOM_JSON_API_Get_Media_v1_2_Endpoint(
	array(
		'description'          => 'Get a single media item (by ID).',
		'group'                => 'media',
		'stat'                 => 'media:1',
		'min_version'          => '1.2',
		'max_version'          => '1.2',
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
			'revision_history'           => '(object) An object with `items` and `original` keys. ' .
									'`original` is an object with data about the original image. ' .
									'`items` is an array of snapshots of the previous images of this Media. ' .
									'Each item has the `URL`, `file, `extension`, `date`, and `mime_type` fields.',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1.2/sites/82974409/media/934',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
	)
);

/**
 * GET Media v1_2 endpoint class.
 */
class WPCOM_JSON_API_Get_Media_v1_2_Endpoint extends WPCOM_JSON_API_Get_Media_v1_1_Endpoint { //phpcs:ignore
	/**
	 *
	 * API callback.
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 * @param int    $media_id - the media ID.
	 */
	public function callback( $path = '', $blog_id = 0, $media_id = 0 ) {
		$response = parent::callback( $path, $blog_id, $media_id );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$media_item         = get_post( $media_id );
		$response->modified = (string) $this->format_date( $media_item->post_modified_gmt, $media_item->post_modified );

		// expose `revision_history` object.
		$response->revision_history = (object) array(
			'items'    => (array) Jetpack_Media::get_revision_history( $media_id ),
			'original' => (object) Jetpack_Media::get_original_media( $media_id ),
		);

		return $response;
	}
}

