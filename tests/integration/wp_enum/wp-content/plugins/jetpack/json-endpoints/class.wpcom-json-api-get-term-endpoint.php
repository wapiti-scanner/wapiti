<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

new WPCOM_JSON_API_Get_Term_Endpoint(
	array(
		'description'                          => 'Get information about a single term.',
		'group'                                => 'taxonomy',
		'stat'                                 => 'terms:1',
		'method'                               => 'GET',
		'path'                                 => '/sites/%s/taxonomies/%s/terms/slug:%s',
		'path_labels'                          => array(
			'$site'     => '(int|string) Site ID or domain',
			'$taxonomy' => '(string) Taxonomy',
			'$slug'     => '(string) Term slug',
		),
		'response_format'                      => array(
			'ID'          => '(int) The term ID.',
			'name'        => '(string) The name of the term.',
			'slug'        => '(string) The slug of the term.',
			'description' => '(string) The description of the term.',
			'post_count'  => '(int) The number of posts using this term.',
			'parent'      => '(int) The parent ID for the term, if hierarchical.',
		),

		'allow_fallback_to_jetpack_blog_token' => true,

		'example_request'                      => 'https://public-api.wordpress.com/rest/v1/sites/en.blog.wordpress.com/taxonomies/post_tag/terms/slug:wordpresscom',
	)
);

/**
 * GET Term endpoint class.
 */
class WPCOM_JSON_API_Get_Term_Endpoint extends WPCOM_JSON_API_Endpoint {
	/**
	 *
	 * API callback.
	 *
	 * /sites/%s/taxonomies/%s/terms/slug:%s -> $blog_id, $taxonomy, $slug
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 * @param string $taxonomy - the taxonomy type.
	 * @param int    $slug - the slug.
	 */
	public function callback( $path = '', $blog_id = 0, $taxonomy = 'category', $slug = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$this->load_theme_functions();
		}

		$taxonomy_meta = get_taxonomy( $taxonomy );
		if ( false === $taxonomy_meta || ( ! $taxonomy_meta->public &&
				! current_user_can( $taxonomy_meta->cap->assign_terms ) ) ) {
			return new WP_Error( 'invalid_taxonomy', 'The taxonomy does not exist', 400 );
		}

		$args = $this->query_args();
		$term = $this->get_taxonomy( $slug, $taxonomy, $args['context'] );
		if ( ! $term || is_wp_error( $term ) ) {
			return $term;
		}

		/** This action is documented in json-endpoints/class.wpcom-json-api-site-settings-endpoint.php */
		do_action( 'wpcom_json_api_objects', 'terms' );

		return $term;
	}
}
