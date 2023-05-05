<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

new WPCOM_JSON_API_Render_Embed_Endpoint(
	array(
		'description'          => 'Get a rendered embed for a site. Note: The current user must have publishing access.',
		'group'                => 'sites',
		'stat'                 => 'embeds:render',
		'method'               => 'GET',
		'path'                 => '/sites/%s/embeds/render',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
		),
		'query_parameters'     => array(
			'embed_url' => '(string) The query-string encoded embed URL to render. Required. Only accepts one at a time.',
		),
		'response_format'      => array(
			'embed_url' => '(string) The embed_url that was passed in for rendering.',
			'result'    => '(html) The rendered HTML result of the embed.',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/apiexamples.wordpress.com/embeds/render?embed_url=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3DSQEQr7c0-dw',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
	)
);

/**
 * Render embed endpoint class.
 *
 * /sites/%s/embeds/render -> $blog_id
 */
class WPCOM_JSON_API_Render_Embed_Endpoint extends WPCOM_JSON_API_Render_Endpoint {
	/**
	 * API Callback.
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
			return new WP_Error( 'unauthorized', __( 'Your token must have permission to post on this blog.', 'jetpack' ), 403 );
		}

		$args      = $this->query_args();
		$embed_url = trim( $args['embed_url'] );

		// quick validation
		if ( ! preg_match_all( '|^\s*(https?://[^\s"]+)\s*$|im', $embed_url, $matches ) ) {
			return new WP_Error( 'invalid_embed_url', __( 'The embed_url parameter must be a valid URL.', 'jetpack' ), 400 );
		}

		if ( count( $matches[1] ) > 1 ) {
			return new WP_Error( 'invalid_embed', __( 'Only one embed can be rendered at a time.', 'jetpack' ), 400 );
		}

		$embed_url = array_shift( $matches[1] );
		$parts     = wp_parse_url( $embed_url );
		if ( ! $parts ) {
			return new WP_Error( 'invalid_embed_url', __( 'The embed_url parameter must be a valid URL.', 'jetpack' ), 400 );
		}

		global $wp_embed;
		$render = $this->process_render( array( $this, 'do_embed' ), $embed_url );

		// if nothing happened, then the shortcode does not exist.
		$is_an_embed = ( $embed_url !== $render['result'] && $wp_embed->maybe_make_link( $embed_url ) !== $render['result'] );
		if ( ! $is_an_embed ) {
			return new WP_Error( 'invalid_embed', __( 'The requested URL is not an embed.', 'jetpack' ), 400 );
		}

		// our output for this endpoint..
		$return              = array();
		$return['embed_url'] = $embed_url;
		$return['result']    = $render['result'];

		$return = $this->add_assets( $return, $render['loaded_scripts'], $render['loaded_styles'] );

		return $return;
	}

}
