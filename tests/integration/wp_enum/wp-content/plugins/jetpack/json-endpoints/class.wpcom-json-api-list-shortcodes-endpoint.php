<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * List shortcodes endpoint.
 */
new WPCOM_JSON_API_List_Shortcodes_Endpoint(
	array(
		'description'          => 'Get a list of shortcodes available on a site. Note: The current user must have publishing access.',
		'group'                => 'sites',
		'stat'                 => 'shortcodes',
		'method'               => 'GET',
		'path'                 => '/sites/%s/shortcodes',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
		),
		'response_format'      => array(
			'shortcodes' => '(array) A list of supported shortcodes by their handle.',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/shortcodes',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
	)
);

/**
 * List shortcodes endpoint class
 *
 * /sites/%s/shortcodes -> $blog_id
 */
class WPCOM_JSON_API_List_Shortcodes_Endpoint extends WPCOM_JSON_API_Endpoint {
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

		// permissions check.
		if ( ! current_user_can( 'edit_posts' ) ) {
			return new WP_Error( 'unauthorized', 'Your token must have permission to post on this blog.', 403 );
		}

		// list em.
		global $shortcode_tags;
		$output = array( 'shortcodes' => array() );

		foreach ( $shortcode_tags as $tag => $class ) {
			if ( '__return_false' === $class ) {
				continue;
			}
			$output['shortcodes'][] = $tag;
		}

		return $output;
	}
}
