<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * List terms endpoint.
 */
new WPCOM_JSON_API_List_Terms_Endpoint(
	array(
		'description'                          => 'Get a list of a site\'s terms by taxonomy.',
		'group'                                => 'taxonomy',
		'stat'                                 => 'terms',
		'method'                               => 'GET',
		'path'                                 => '/sites/%s/taxonomies/%s/terms',
		'path_labels'                          => array(
			'$site'     => '(int|string) Site ID or domain',
			'$taxonomy' => '(string) Taxonomy',
		),
		'query_parameters'                     => array(
			'number'   => '(int=100) The number of terms to return. Limit: 1000.',
			'offset'   => '(int=0) 0-indexed offset.',
			'page'     => '(int) Return the Nth 1-indexed page of terms. Takes precedence over the <code>offset</code> parameter.',
			'search'   => '(string) Limit response to include only terms whose names or slugs match the provided search query.',
			'order'    => array(
				'ASC'  => 'Return terms in ascending order.',
				'DESC' => 'Return terms in descending order.',
			),
			'order_by' => array(
				'name'  => 'Order by the name of each tag.',
				'count' => 'Order by the number of posts in each tag.',
			),
		),

		'allow_fallback_to_jetpack_blog_token' => true,

		'response_format'                      => array(
			'found' => '(int) The number of terms returned.',
			'terms' => '(array) Array of tag objects.',
		),
		'example_request'                      => 'https://public-api.wordpress.com/rest/v1/sites/en.blog.wordpress.com/taxonomies/post_tags/terms?number=5',
	)
);

/**
 * List terms endpoint class.
 *
 * /sites/%s/taxonomies/%s/terms -> $blog_id, $taxonomy
 */
class WPCOM_JSON_API_List_Terms_Endpoint extends WPCOM_JSON_API_Endpoint {

	/**
	 * API callback.
	 *
	 * @param string $path - the path.
	 * @param string $blog_id - the blog ID.
	 * @param string $taxonomy - the taxonomy.
	 */
	public function callback( $path = '', $blog_id = 0, $taxonomy = 'category' ) {
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
		$args = $this->process_args( $args );

		$formatted_terms = $this->get_formatted_terms( $taxonomy, $args );

		if ( ! empty( $formatted_terms ) ) {
			/** This action is documented in json-endpoints/class.wpcom-json-api-site-settings-endpoint.php */
			do_action( 'wpcom_json_api_objects', 'terms', count( $formatted_terms ) );
		}

		return array(
			'found' => (int) $this->get_found( $taxonomy, $args ),
			'terms' => (array) $formatted_terms,
		);
	}

	/**
	 * Process args.
	 *
	 * @param array $args - the arguments.
	 */
	public function process_args( $args ) {
		$args['get'] = 'all';

		if ( $args['number'] < 1 ) {
			$args['number'] = 100;
		} elseif ( 1000 < $args['number'] ) {
			return new WP_Error( 'invalid_number', 'The number parameter must be less than or equal to 1000.', 400 );
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
	 * Get found taxonomy term count.
	 *
	 * @param string $taxonomy - the taxonomy.
	 * @param array  $args - the arguments.
	 */
	public function get_found( $taxonomy, $args ) {
		unset( $args['offset'] );
		return wp_count_terms( $taxonomy, $args );
	}

	/**
	 * Format the taxonomy terms.
	 *
	 * @param string $taxonomy - the taxonomy.
	 * @param array  $args - the arguments.
	 */
	public function get_formatted_terms( $taxonomy, $args ) {
		$terms = get_terms( $taxonomy, $args );

		$formatted_terms = array();
		foreach ( $terms as $term ) {
			$formatted_terms[] = $this->format_taxonomy( $term, $taxonomy, 'display' );
		}

		return $formatted_terms;
	}
}
