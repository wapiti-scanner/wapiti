<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * WPCOM_JSON_API_Autosave_Post_v1_1_Endpoint
 *
 * @package automattic/jetpack
 */

new WPCOM_JSON_API_Autosave_Post_v1_1_Endpoint(
	array(
		'description'          => 'Create a post autosave.',
		'group'                => '__do_not_document',
		'stat'                 => 'posts:autosave',
		'min_version'          => '1.1',
		'method'               => 'POST',
		'path'                 => '/sites/%s/posts/%d/autosave',
		'path_labels'          => array(
			'$site'    => '(int|string) Site ID or domain',
			'$post_ID' => '(int) The post ID',
		),
		'request_format'       => array(
			'content' => '(HTML) The post content.',
			'title'   => '(HTML) The post title.',
			'excerpt' => '(HTML) The post excerpt.',
		),
		'response_format'      => array(
			'ID'          => '(int) autodraft post ID',
			'post_ID'     => '(int) post ID',
			'preview_URL' => '(string) preview URL for the post',
			'modified'    => '(ISO 8601 datetime) modified time',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1.1/sites/82974409/posts/1/autosave',

		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),

			'body'    => array(
				'title'   => 'Howdy',
				'content' => 'Hello. I am a test post. I was created by the API',
			),
		),
	)
);

// phpcs:disable PEAR.NamingConventions.ValidClassName.Invalid

/**
 * Class WPCOM_JSON_API_Autosave_Post_v1_1_Endpoint
 */
class WPCOM_JSON_API_Autosave_Post_v1_1_Endpoint extends WPCOM_JSON_API_Post_v1_1_Endpoint {

	/**
	 * Autosave Post callback.
	 * /sites/%s/posts/%d/autosave -> $blog_id, $post_id
	 *
	 * @param string $path Path.
	 * @param int    $blog_id Blog ID.
	 * @param int    $post_id Post ID.
	 */
	public function callback( $path = '', $blog_id = 0, $post_id = 0 ) {
		if ( ! defined( 'DOING_AUTOSAVE' ) ) {
			define( 'DOING_AUTOSAVE', true );
		}

		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		$input = $this->input( false );

		if ( ! is_array( $input ) || ! $input ) {
			return new WP_Error( 'invalid_input', 'Invalid request input', 400 );
		}

		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			// Make sure Custom Post Types, etc. get registered.
			$this->load_theme_functions();
		}

		$post = get_post( $post_id );

		if ( ! $post || is_wp_error( $post ) ) {
			return new WP_Error( 'unknown_post', 'Unknown post', 404 );
		}

		if ( ! current_user_can( 'edit_post', $post->ID ) ) {
			return new WP_Error( 'unauthorized', 'User cannot edit post', 403 );
		}

		$post_data = array(
			'post_ID'      => $post_id,
			'post_type'    => $post->post_type,
			'post_title'   => $input['title'],
			'post_content' => $input['content'],
			'post_excerpt' => $input['excerpt'],
		);

		$preview_url = add_query_arg( 'preview', 'true', get_permalink( $post->ID ) );

		if ( ! wp_check_post_lock( $post->ID ) &&
			get_current_user_id() === (int) $post->post_author &&
			( 'auto-draft' === $post->post_status || 'draft' === $post->post_status )
		) {
			// Drafts and auto-drafts are just overwritten by autosave for the same user if the post is not locked.
			$auto_id = edit_post( wp_slash( $post_data ) );
		} else {
			// Non drafts or other users drafts are not overwritten. The autosave is stored in a special post revision for each user.
			$auto_id     = wp_create_post_autosave( wp_slash( $post_data ) );
			$nonce       = wp_create_nonce( 'post_preview_' . $post->ID );
			$preview_url = add_query_arg(
				array(
					'preview_id'    => $post->ID,
					'preview_nonce' => $nonce,
				),
				$preview_url
			);
		}

		$updated_post = get_post( $auto_id );

		if ( $updated_post && $updated_post->ID && $updated_post->post_modified ) {
			return array(
				'ID'          => $auto_id,
				'post_ID'     => $post->ID,
				'modified'    => $this->format_date( $updated_post->post_modified_gmt, $updated_post->post_modified ),
				'preview_URL' => $preview_url,
			);
		} else {
			return new WP_Error( 'autosave_error', __( 'Autosave encountered an unexpected error', 'jetpack' ), 500 );
		}
	}
}
