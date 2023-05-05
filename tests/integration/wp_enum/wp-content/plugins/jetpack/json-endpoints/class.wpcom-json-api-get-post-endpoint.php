<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Endpoints: /sites/%s/posts/%d      -> $blog_id, $post_id
 *            /sites/%s/posts/name:%s -> $blog_id, $post_id // not documented
 *            /sites/%s/posts/slug:%s -> $blog_id, $post_id
 */

new WPCOM_JSON_API_Get_Post_Endpoint(
	array(
		'description'                          => 'Get a single post (by ID).',
		'group'                                => 'posts',
		'stat'                                 => 'posts:1',
		'new_version'                          => '1.1',
		'max_version'                          => '1',
		'method'                               => 'GET',
		'path'                                 => '/sites/%s/posts/%d',
		'path_labels'                          => array(
			'$site'    => '(int|string) Site ID or domain',
			'$post_ID' => '(int) The post ID',
		),

		'allow_fallback_to_jetpack_blog_token' => true,

		'example_request'                      => 'https://public-api.wordpress.com/rest/v1/sites/en.blog.wordpress.com/posts/7',
	)
);

new WPCOM_JSON_API_Get_Post_Endpoint(
	array(
		'description'     => 'Get a single post (by name)',
		'group'           => '__do_not_document',
		'stat'            => 'posts:name',
		'method'          => 'GET',
		'path'            => '/sites/%s/posts/name:%s',
		'path_labels'     => array(
			'$site'      => '(int|string) Site ID or domain',
			'$post_name' => '(string) The post name (a.k.a. slug)',
		),

		'example_request' => 'https://public-api.wordpress.com/rest/v1/sites/en.blog.wordpress.com/posts/name:blogging-and-stuff',
	)
);

new WPCOM_JSON_API_Get_Post_Endpoint(
	array(
		'description'                          => 'Get a single post (by slug).',
		'group'                                => 'posts',
		'stat'                                 => 'posts:slug',
		'new_version'                          => '1.1',
		'max_version'                          => '1',
		'method'                               => 'GET',
		'path'                                 => '/sites/%s/posts/slug:%s',
		'path_labels'                          => array(
			'$site'      => '(int|string) Site ID or domain',
			'$post_slug' => '(string) The post slug (a.k.a. sanitized name)',
		),

		'allow_fallback_to_jetpack_blog_token' => true,

		'example_request'                      => 'https://public-api.wordpress.com/rest/v1/sites/en.blog.wordpress.com/posts/slug:blogging-and-stuff',
	)
);

/**
 * Get post endpoint class.
 */
class WPCOM_JSON_API_Get_Post_Endpoint extends WPCOM_JSON_API_Post_Endpoint {
	/**
	 *
	 * API callback.
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 * @param int    $post_id - the post ID.
	 */
	public function callback( $path = '', $blog_id = 0, $post_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		$args = $this->query_args();

		if ( false === strpos( $path, '/posts/slug:' ) && false === strpos( $path, '/posts/name:' ) ) {
			$get_by = 'ID';
		} else {
			$get_by = 'name';
		}

		$return = $this->get_post_by( $get_by, $post_id, $args['context'] );
		if ( ! $return || is_wp_error( $return ) ) {
			return $return;
		}

		if ( ! $this->current_user_can_access_post_type( $return['type'], $args['context'] ) ) {
			return new WP_Error( 'unknown_post', 'Unknown post', 404 );
		}

		/** This action is documented in json-endpoints/class.wpcom-json-api-site-settings-endpoint.php */
		do_action( 'wpcom_json_api_objects', 'posts' );

		return $return;
	}
}
