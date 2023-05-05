<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

new WPCOM_JSON_API_Render_Embed_Reversal_Endpoint(
	array(
		'description'          => 'Determines if the given embed code can be reversed into a single line embed or a shortcode, and if so returns the embed or shortcode. Note: The current user must have publishing access.',
		'group'                => '__do_not_document',
		'stat'                 => 'embeds:reversal',
		'method'               => 'POST',
		'path'                 => '/sites/%s/embeds/reversal',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
		),
		'request_format'       => array(
			'maybe_embed' => '(string) The embed code to reverse. Required. Only accepts one at a time.',
		),
		'response_format'      => array(
			'maybe_embed'   => '(string) The original embed code that was passed in for rendering.',
			'reversal_type' => '(string) The type of reversal. Either an embed or a shortcode.',
			'render_result' => '(html) The rendered HTML result of the embed or shortcode.',
			'result'        => '(string) The reversed content. Either a single line embed or a shortcode.',
			'scripts'       => '(array) An array of JavaScript files needed to render the embed or shortcode. Returned in the format of <code>{ "script-slug" : { "src": "http://example.com/file.js", "extra" : "" } }</code> where extra contains any neccessary extra JS for initializing the source file and src contains the script to load. Omitted if no scripts are neccessary.',
			'styles'        => '(array) An array of CSS files needed to render the embed or shortcode. Returned in the format of <code>{ "style-slug" : { "src": "http://example.com/file.css", "media" : "all" } }</code>. Omitted if no styles are neccessary.',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/shortcode-reversals/render/',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),

			'body'    => array(
				'maybe_embed' => '<iframe width="480" height="302" src="http://www.ustream.tv/embed/recorded/26370522/highlight/299667?v=3&amp;wmode=direct" scrolling="no" frameborder="0"></iframe>',
			),
		),
	)
);

/**
 * Render embed reversal class.
 *
 * /sites/%s/embeds/reversal -> $blog_id
 */
class WPCOM_JSON_API_Render_Embed_Reversal_Endpoint extends WPCOM_JSON_API_Render_Endpoint {
	/**
	 * API callback.
	 *
	 * @param string $path - the path (unused).
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

		$is_embed     = false;
		$is_shortcode = false;

		$input       = $this->input( true );
		$maybe_embed = trim( $input['maybe_embed'] );
		if ( empty( $maybe_embed ) ) {
			return new WP_Error( 'empty_embed', 'Please provide an embed code to process.', 400 );
		}

		$ksesed_content = trim( wp_strip_all_tags( wp_kses_post( $maybe_embed ), true ) );
		if ( empty( $ksesed_content ) ) {
			return new WP_Error( 'invalid_embed', 'Invalid or empty embed provided.', 400 );
		}

		$shortcode_pattern = get_shortcode_regex();
		$url_pattern       = '/^http(s)?:\/\/[a-z0-9-]+(.[a-z0-9-]+)*(:[0-9]+)?(\/.*)?$/i';
		preg_match_all( "/$shortcode_pattern/s", $ksesed_content, $shortcode_matches );
		preg_match_all( "$url_pattern", $ksesed_content, $url_matches );

		if ( empty( $shortcode_matches[0] ) && empty( $url_matches[0] ) ) {
			return new WP_Error( 'invalid_embed', 'The provided embed is not supported.', 400 );
		}

		if ( ( count( $shortcode_matches[0] ) + count( $url_matches[0] ) ) > 1 ) {
			return new WP_Error( 'invalid_embed', 'Only one embed/shortcode reversal can be rendered at a time.', 400 );
		}

		if ( ! empty( $shortcode_matches[0] ) ) {
			$is_shortcode = true;
		} elseif ( ! empty( $url_matches[0] ) ) {
			$is_embed = true;
		}

		$render = $this->process_render(
			array( $this, 'render_shortcode_reversal' ),
			array(
				'shortcode_reversal' => $ksesed_content,
				'is_shortcode'       => $is_shortcode,
				'is_embed'           => $is_embed,
			)
		);

		// if nothing happened, then the shortcode does not exist.
		global $wp_embed;
		if ( empty( $render ) || empty( $render['result'] ) || $ksesed_content === $render['result'] || $wp_embed->maybe_make_link( $maybe_embed ) === $render['result'] ) {
			return new WP_Error( 'invalid_embed', 'The provided embed is not supported.', 400 );
		}

		// our output for this endpoint..
		$return                  = array();
		$return['maybe_embed']   = $maybe_embed;
		$return['result']        = $ksesed_content;
		$return['reversal_type'] = ( $is_embed ) ? 'embed' : 'shortcode';
		$return['render_result'] = $render['result'];

		$return = $this->add_assets( $return, $render['loaded_scripts'], $render['loaded_styles'] );

		return $return;
	}

	/**
	 * Render the shortcode reversal.
	 *
	 * @param array $args - the arguments.
	 *
	 * @return mixed|false
	 */
	public function render_shortcode_reversal( $args ) {
		if ( $args['is_shortcode'] ) {
			return $this->do_shortcode( $args['shortcode_reversal'] );
		} elseif ( $args['is_embed'] ) {
			return $this->do_embed( $args['shortcode_reversal'] );
		}
		return false;
	}

}
