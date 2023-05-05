<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

new WPCOM_JSON_API_Get_Taxonomy_Endpoint(
	array(
		'description'                          => 'Get information about a single category.',
		'group'                                => 'taxonomy',
		'stat'                                 => 'categories:1',

		'method'                               => 'GET',
		'path'                                 => '/sites/%s/categories/slug:%s',
		'path_labels'                          => array(
			'$site'     => '(int|string) Site ID or domain',
			'$category' => '(string) The category slug',
		),

		'allow_fallback_to_jetpack_blog_token' => true,

		'example_request'                      => 'https://public-api.wordpress.com/rest/v1/sites/en.blog.wordpress.com/categories/slug:community',
	)
);

new WPCOM_JSON_API_Get_Taxonomy_Endpoint(
	array(
		'description'                          => 'Get information about a single tag.',
		'group'                                => 'taxonomy',
		'stat'                                 => 'tags:1',

		'method'                               => 'GET',
		'path'                                 => '/sites/%s/tags/slug:%s',
		'path_labels'                          => array(
			'$site' => '(int|string) Site ID or domain',
			'$tag'  => '(string) The tag slug',
		),

		'allow_fallback_to_jetpack_blog_token' => true,

		'example_request'                      => 'https://public-api.wordpress.com/rest/v1/sites/en.blog.wordpress.com/tags/slug:wordpresscom',
	)
);

/**
 * GET Taxonomy endpoint class.
 */
class WPCOM_JSON_API_Get_Taxonomy_Endpoint extends WPCOM_JSON_API_Taxonomy_Endpoint {
	/**
	 *
	 * API callback.
	 *
	 * /sites/%s/tags/slug:%s       -> $blog_id, $tag_id
	 * /sites/%s/categories/slug:%s -> $blog_id, $tag_id
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 * @param int    $taxonomy_id - the taxonomy ID.
	 */
	public function callback( $path = '', $blog_id = 0, $taxonomy_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		$args = $this->query_args();
		if ( preg_match( '#/tags/#i', $path ) ) {
			$taxonomy_type = 'post_tag';
		} else {
			$taxonomy_type = 'category';
		}

		$return = $this->get_taxonomy( $taxonomy_id, $taxonomy_type, $args['context'] );
		if ( ! $return || is_wp_error( $return ) ) {
			return $return;
		}

		/** This action is documented in json-endpoints/class.wpcom-json-api-site-settings-endpoint.php */
		do_action( 'wpcom_json_api_objects', 'taxonomies' );

		return $return;
	}
}
