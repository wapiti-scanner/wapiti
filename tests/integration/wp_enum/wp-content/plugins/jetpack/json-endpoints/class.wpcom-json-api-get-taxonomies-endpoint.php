<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

new WPCOM_JSON_API_Get_Taxonomies_Endpoint(
	array(
		'description'                          => "Get a list of a site's categories.",
		'group'                                => 'taxonomy',
		'stat'                                 => 'categories',
		'method'                               => 'GET',
		'path'                                 => '/sites/%s/categories',
		'path_labels'                          => array(
			'$site' => '(int|string) Site ID or domain',
		),
		'query_parameters'                     => array(
			'number'   => '(int=100) The number of categories to return. Limit: 1000.',
			'offset'   => '(int=0) 0-indexed offset.',
			'page'     => '(int) Return the Nth 1-indexed page of categories. Takes precedence over the <code>offset</code> parameter.',
			'search'   => '(string) Limit response to include only categories whose names or slugs match the provided search query.',
			'order'    => array(
				'ASC'  => 'Return categories in ascending order.',
				'DESC' => 'Return categories in descending order.',
			),
			'order_by' => array(
				'name'  => 'Order by the name of each category.',
				'count' => 'Order by the number of posts in each category.',
			),
		),
		'response_format'                      => array(
			'found'      => '(int) The number of categories returned.',
			'categories' => '(array) Array of category objects.',
		),

		'allow_fallback_to_jetpack_blog_token' => true,

		'example_request'                      => 'https://public-api.wordpress.com/rest/v1/sites/en.blog.wordpress.com/categories/?number=5',
	)
);

new WPCOM_JSON_API_Get_Taxonomies_Endpoint(
	array(
		'description'                          => "Get a list of a site's tags.",
		'group'                                => 'taxonomy',
		'stat'                                 => 'tags',
		'method'                               => 'GET',
		'path'                                 => '/sites/%s/tags',
		'path_labels'                          => array(
			'$site' => '(int|string) Site ID or domain',
		),
		'query_parameters'                     => array(
			'number'   => '(int=100) The number of tags to return. Limit: 1000.',
			'offset'   => '(int=0) 0-indexed offset.',
			'page'     => '(int) Return the Nth 1-indexed page of tags. Takes precedence over the <code>offset</code> parameter.',
			'search'   => '(string) Limit response to include only tags whose names or slugs match the provided search query.',
			'order'    => array(
				'ASC'  => 'Return tags in ascending order.',
				'DESC' => 'Return tags in descending order.',
			),
			'order_by' => array(
				'name'  => 'Order by the name of each tag.',
				'count' => 'Order by the number of posts in each tag.',
			),
		),

		'allow_fallback_to_jetpack_blog_token' => true,

		'response_format'                      => array(
			'found' => '(int) The number of tags returned.',
			'tags'  => '(array) Array of tag objects.',
		),
		'example_request'                      => 'https://public-api.wordpress.com/rest/v1/sites/en.blog.wordpress.com/tags/?number=5',
	)
);

/**
 * GET taxonomies endpoint class.
 */
class WPCOM_JSON_API_Get_Taxonomies_Endpoint extends WPCOM_JSON_API_Endpoint {
	/**
	 *
	 * API callback.
	 * /sites/%s/tags       -> $blog_id
	 * /sites/%s/categories -> $blog_id
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 */
	public function callback( $path = '', $blog_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		$args = $this->query_args();
		$args = $this->process_args( $args );

		if ( preg_match( '#/tags#i', $path ) ) {
			return $this->tags( $args );
		} else {
			return $this->categories( $args );
		}
	}

	/**
	 * Process args.
	 *
	 * @param array $args - the arguments.
	 */
	public function process_args( $args ) {
		if ( $args['number'] < 1 ) {
			$args['number'] = 100;
		} elseif ( 1000 < $args['number'] ) {
			return new WP_Error( 'invalid_number', 'The NUMBER parameter must be less than or equal to 1000.', 400 );
		}

		if ( isset( $args['page'] ) ) {
			if ( $args['page'] < 1 ) {
				$args['page'] = 1;
			}

			$args['offset'] = ( $args['page'] - 1 ) * $args['number'];
			unset( $args['page'] );
		}

		if ( $args['offset'] < 0 ) {
			$args['offset'] = 0;
		}

		$args['orderby'] = $args['order_by'];
		unset( $args['order_by'] );

		unset( $args['context'], $args['pretty'], $args['http_envelope'], $args['fields'] );
		return $args;
	}

	/**
	 * Get categories.
	 *
	 * @param array $args - the arguments.
	 */
	public function categories( $args ) {
		$args['get'] = 'all';

		$cats = get_categories( $args );
		unset( $args['offset'] );
		$found = wp_count_terms( 'category', $args );

		$cats_obj = array();
		foreach ( $cats as $cat ) {
			$cats_obj[] = $this->format_taxonomy( $cat, 'category', 'display' );
		}

		return array(
			'found'      => (int) $found,
			'categories' => $cats_obj,
		);
	}

	/**
	 * Get tags.
	 *
	 * @param array $args - the arguments.
	 */
	public function tags( $args ) {
		$args['get'] = 'all';

		$tags = (array) get_tags( $args );
		unset( $args['offset'] );
		$found = wp_count_terms( 'post_tag', $args );

		$tags_obj = array();
		foreach ( $tags as $tag ) {
			$tags_obj[] = $this->format_taxonomy( $tag, 'post_tag', 'display' );
		}

		return array(
			'found' => (int) $found,
			'tags'  => $tags_obj,
		);
	}
}
