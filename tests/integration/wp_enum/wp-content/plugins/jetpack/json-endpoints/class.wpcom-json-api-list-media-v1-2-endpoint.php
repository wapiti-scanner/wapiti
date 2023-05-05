<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

require_once JETPACK__PLUGIN_DIR . '_inc/lib/class.media.php';

/**
 * List media v1_2 endpoint.
 */
new WPCOM_JSON_API_List_Media_v1_2_Endpoint(
	array(
		'description'          => 'Get a list of items in the media library.',
		'group'                => 'media',
		'stat'                 => 'media',
		'min_version'          => '1.2',
		'max_version'          => '1.2',
		'method'               => 'GET',
		'path'                 => '/sites/%s/media/',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
		),

		'query_parameters'     => array(
			'number'      => '(int=20) The number of media items to return. Limit: 100.',
			'offset'      => '(int=0) 0-indexed offset.',
			'page'        => '(int) Return the Nth 1-indexed page of posts. Takes precedence over the <code>offset</code> parameter.',
			'page_handle' => '(string) A page handle, returned from a previous API call as a <code>meta.next_page</code> property. This is the most efficient way to fetch the next page of results.',
			'order'       => array(
				'DESC' => 'Return files in descending order. For dates, that means newest to oldest.',
				'ASC'  => 'Return files in ascending order. For dates, that means oldest to newest.',
			),
			'order_by'    => array(
				'date'  => 'Order by the uploaded time of each file.',
				'title' => 'Order lexicographically by file titles.',
				'ID'    => 'Order by media ID.',
			),
			'search'      => '(string) Search query.',
			'post_ID'     => '(int) Default is showing all items. The post where the media item is attached. 0 shows unattached media items.',
			'mime_type'   => "(string) Default is empty. Filter by mime type (e.g., 'image/jpeg', 'application/pdf'). Partial searches also work (e.g. passing 'image' will search for all image files).",
			'after'       => '(ISO 8601 datetime) Return media items uploaded after the specified datetime.',
			'before'      => '(ISO 8601 datetime) Return media items uploaded before the specified datetime.',
		),

		'response_format'      => array(
			'media' => '(array) Array of media objects',
			'found' => '(int) The number of total results found',
			'meta'  => '(object) Meta data',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1.2/sites/82974409/media',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
	)
);

/**
 * List Media v1_2 endpoint.
 */
class WPCOM_JSON_API_List_Media_v1_2_Endpoint extends WPCOM_JSON_API_List_Media_v1_1_Endpoint { // phpcs:ignore
	/**
	 * API callback.
	 *
	 * @param string $path - the path.
	 * @param string $blog_id - the blog ID.
	 */
	public function callback( $path = '', $blog_id = 0 ) {
		$response = parent::callback( $path, $blog_id );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$media_list = $response['media'];

		if ( count( $media_list ) < 1 ) {
			return $response;
		}

		foreach ( $media_list as $media_item ) {
			// expose `revision_history` object for each image.
			$media_item->revision_history = (object) array(
				'items'    => (array) Jetpack_Media::get_revision_history( $media_item->ID ),
				'original' => (object) Jetpack_Media::get_original_media( $media_item->ID ),
			);
		}

		return $response;
	}
}

