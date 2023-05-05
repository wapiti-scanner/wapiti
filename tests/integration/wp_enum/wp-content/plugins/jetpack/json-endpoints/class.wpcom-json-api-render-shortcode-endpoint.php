<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

new WPCOM_JSON_API_Render_Shortcode_Endpoint(
	array(
		'description'          => 'Get a rendered shortcode for a site. Note: The current user must have publishing access.',
		'group'                => 'sites',
		'stat'                 => 'shortcodes:render',
		'method'               => 'GET',
		'path'                 => '/sites/%s/shortcodes/render',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
		),
		'query_parameters'     => array(
			'shortcode' => '(string) The query-string encoded shortcode string to render. Required. Only accepts one at a time.',
		),
		'response_format'      => array(
			'shortcode' => '(string) The shortcode that was passed in for rendering.',
			'result'    => '(html) The rendered HTML result of the shortcode.',
			'scripts'   => '(array) An array of JavaScript files needed to render the shortcode. Returned in the format of <code>{ "script-slug" : { "src": "http://example.com/file.js", "extra" : "" } }</code> where extra contains any neccessary extra JS for initializing the source file and src contains the script to load. Omitted if no scripts are neccessary.',
			'styles'    => '(array) An array of CSS files needed to render the shortcode. Returned in the format of <code>{ "style-slug" : { "src": "http://example.com/file.css", "media" : "all" } }</code>. Omitted if no styles are neccessary.',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/shortcodes/render?shortcode=%5Bgallery%20ids%3D%22729%2C732%2C731%2C720%22%5D',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
	)
);

/**
 * Render shortcode endpoint class.
 *
 * /sites/%s/shortcodes/render -> $blog_id
 */
class WPCOM_JSON_API_Render_Shortcode_Endpoint extends WPCOM_JSON_API_Render_Endpoint {
	/**
	 * The API callback.
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 *
	 * @return array|WP_Error
	 */
	public function callback( $path = '', $blog_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		if ( ! current_user_can( 'edit_posts' ) ) {
			return new WP_Error( 'unauthorized', 'Your token must have permission to post on this blog.', 403 );
		}

		$args      = $this->query_args();
		$shortcode = trim( $args['shortcode'] );

		// Quick validation - shortcodes should always be enclosed in brackets []
		if ( ! wp_startswith( $shortcode, '[' ) || ! wp_endswith( $shortcode, ']' ) ) {
			return new WP_Error( 'invalid_shortcode', 'The shortcode parameter must begin and end with square brackets.', 400 );
		}

		// Make sure only one shortcode is being rendered at a time
		$pattern = get_shortcode_regex();
		preg_match_all( "/$pattern/s", $shortcode, $matches );
		if ( count( $matches[0] ) > 1 ) {
			return new WP_Error( 'invalid_shortcode', 'Only one shortcode can be rendered at a time.', 400 );
		}

		$render = $this->process_render( array( $this, 'do_shortcode' ), $shortcode );

		// if nothing happened, then the shortcode does not exist.
		if ( $shortcode === $render['result'] ) {
			return new WP_Error( 'invalid_shortcode', 'The requested shortcode does not exist.', 400 );
		}

		// our output for this endpoint..
		$return              = array();
		$return['shortcode'] = $shortcode;
		$return['result']    = $render['result'];

		$return = $this->add_assets( $return, $render['loaded_scripts'], $render['loaded_styles'] );

		return $return;
	}
}
