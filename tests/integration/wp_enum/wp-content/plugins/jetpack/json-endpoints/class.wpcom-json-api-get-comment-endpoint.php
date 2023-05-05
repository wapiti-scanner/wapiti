<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Endpoint: /sites/%s/comments/%d -> $blog_id, $comment_id
 */
new WPCOM_JSON_API_Get_Comment_Endpoint(
	array(
		'description'                          => 'Get a single comment.',
		'group'                                => 'comments',
		'stat'                                 => 'comments:1',

		'method'                               => 'GET',
		'path'                                 => '/sites/%s/comments/%d',
		'path_labels'                          => array(
			'$site'       => '(int|string) Site ID or domain',
			'$comment_ID' => '(int) The comment ID',
		),

		'allow_fallback_to_jetpack_blog_token' => true,

		'example_request'                      => 'https://public-api.wordpress.com/rest/v1/sites/en.blog.wordpress.com/comments/147564',
	)
);

/**
 * Get Comment endpoint class.
 */
class WPCOM_JSON_API_Get_Comment_Endpoint extends WPCOM_JSON_API_Comment_Endpoint {
	/**
	 *
	 * API callback.
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 * @param int    $comment_id - the comment ID.
	 */
	public function callback( $path = '', $blog_id = 0, $comment_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		$args = $this->query_args();

		$return = $this->get_comment( $comment_id, $args['context'] );
		if ( ! $return || is_wp_error( $return ) ) {
			return $return;
		}

		/** This action is documented in json-endpoints/class.wpcom-json-api-site-settings-endpoint.php */
		do_action( 'wpcom_json_api_objects', 'comments' );

		return $return;
	}
}
