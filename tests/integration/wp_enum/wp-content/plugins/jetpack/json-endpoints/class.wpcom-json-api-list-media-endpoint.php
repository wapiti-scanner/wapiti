<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * List media endpoint.
 */
new WPCOM_JSON_API_List_Media_Endpoint(
	array(
		'description'          => 'Get a list of items in the media library.',
		'group'                => 'media',
		'stat'                 => 'media',

		'method'               => 'GET',
		'path'                 => '/sites/%s/media/',
		'deprecated'           => true,
		'new_version'          => '1.1',
		'max_version'          => '1',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
		),

		'query_parameters'     => array(
			'number'    => '(int=20) The number of media items to return. Limit: 100.',
			'offset'    => '(int=0) 0-indexed offset.',
			'parent_id' => '(int) Default is showing all items. The post where the media item is attached. 0 shows unattached media items.',
			'mime_type' => "(string) Default is empty. Filter by mime type (e.g., 'image/jpeg', 'application/pdf'). Partial searches also work (e.g. passing 'image' will search for all image files).",
		),

		'response_format'      => array(
			'media' => '(array) Array of media',
			'found' => '(int) The number of total results found',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/media/?number=2',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
	)
);

/**
 * API List media endpoint class.
 */
class WPCOM_JSON_API_List_Media_Endpoint extends WPCOM_JSON_API_Endpoint {

	/**
	 * API callback.
	 *
	 * @param string $path - the path.
	 * @param string $blog_id - the blog ID.
	 */
	public function callback( $path = '', $blog_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		// upload_files can probably be used for other endpoints but we want contributors to be able to use media too.
		if ( ! current_user_can( 'edit_posts' ) ) {
			return new WP_Error( 'unauthorized', 'User cannot view media', 403 );
		}

		$args = $this->query_args();

		if ( $args['number'] < 1 ) {
			$args['number'] = 20;
		} elseif ( 100 < $args['number'] ) {
			return new WP_Error( 'invalid_number', 'The NUMBER parameter must be less than or equal to 100.', 400 );
		}

		$media = get_posts(
			array(
				'post_type'      => 'attachment',
				'post_parent'    => $args['parent_id'],
				'offset'         => $args['offset'],
				'numberposts'    => $args['number'],
				'post_mime_type' => $args['mime_type'],
			)
		);

		$response = array();
		foreach ( $media as $item ) {
			$response[] = $this->get_media_item( $item->ID );
		}

		$_num         = (array) wp_count_attachments();
		$_total_media = array_sum( $_num ) - $_num['trash'];

		$return = array(
			'found' => $_total_media,
			'media' => $response,
		);

		return $return;
	}

}
