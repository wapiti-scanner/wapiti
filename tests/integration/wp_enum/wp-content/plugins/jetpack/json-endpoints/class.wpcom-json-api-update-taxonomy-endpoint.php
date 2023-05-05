<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Update site taxonomy API endpoints.
 *
 * Endpoints:
 * Create a new category: /sites/%s/categories/new
 * Create a new tag:      /sites/%s/tags/new
 * Edit a category:       /sites/%s/categories/slug:%s
 * Edit a tag:            /sites/%s/tags/slug:%s
 * Delete a category:     /sites/%s/categories/slug:%s/delete
 * Delete a tag:          /sites/%s/tags/slug:%s/delete
 */

new WPCOM_JSON_API_Update_Taxonomy_Endpoint(
	array(
		'description'          => 'Create a new category.',
		'group'                => 'taxonomy',
		'stat'                 => 'categories:new',

		'method'               => 'POST',
		'path'                 => '/sites/%s/categories/new',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
		),

		'request_format'       => array(
			'name'        => '(string) Name of the category',
			'description' => '(string) A description of the category',
			'parent'      => '(int) ID of the parent category',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/categories/new/',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'name' => 'Puppies',
			),
		),
	)
);

new WPCOM_JSON_API_Update_Taxonomy_Endpoint(
	array(
		'description'          => 'Create a new tag.',
		'group'                => 'taxonomy',
		'stat'                 => 'tags:new',

		'method'               => 'POST',
		'path'                 => '/sites/%s/tags/new',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
		),

		'request_format'       => array(
			'name'        => '(string) Name of the tag',
			'description' => '(string) A description of the tag',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/tags/new/',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'name' => 'Kitties',
			),
		),
	)
);

new WPCOM_JSON_API_Update_Taxonomy_Endpoint(
	array(
		'description'          => 'Edit a tag.',
		'group'                => 'taxonomy',
		'stat'                 => 'tags:1:POST',

		'method'               => 'POST',
		'path'                 => '/sites/%s/tags/slug:%s',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
			'$tag'  => '(string) The tag slug',
		),

		'request_format'       => array(
			'name'        => '(string) Name of the tag',
			'description' => '(string) A description of the tag',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/tags/slug:testing-tag',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'description' => 'Kitties are awesome!',
			),
		),
	)
);

new WPCOM_JSON_API_Update_Taxonomy_Endpoint(
	array(
		'description'          => 'Edit a category.',
		'group'                => 'taxonomy',
		'stat'                 => 'categories:1:POST',

		'method'               => 'POST',
		'path'                 => '/sites/%s/categories/slug:%s',
		'path_labels'          => array(
			'$site'     => '(int|string) Site ID or domain',
			'$category' => '(string) The category slug',
		),

		'request_format'       => array(
			'name'        => '(string) Name of the category',
			'description' => '(string) A description of the category',
			'parent'      => '(int) ID of the parent category',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/categories/slug:testing-category',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'description' => 'Puppies are great!',
			),
		),
	)
);

new WPCOM_JSON_API_Update_Taxonomy_Endpoint(
	array(
		'description'          => 'Delete a category.',
		'group'                => 'taxonomy',
		'stat'                 => 'categories:1:delete',

		'method'               => 'POST',
		'path'                 => '/sites/%s/categories/slug:%s/delete',
		'path_labels'          => array(
			'$site'     => '(int|string) Site ID or domain',
			'$category' => '(string) The category slug',
		),
		'response_format'      => array(
			'slug'    => '(string) The slug of the deleted category',
			'success' => '(bool) Was the operation successful?',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/categories/slug:$category/delete',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
	)
);

new WPCOM_JSON_API_Update_Taxonomy_Endpoint(
	array(
		'description'          => 'Delete a tag.',
		'group'                => 'taxonomy',
		'stat'                 => 'tags:1:delete',

		'method'               => 'POST',
		'path'                 => '/sites/%s/tags/slug:%s/delete',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
			'$tag'  => '(string) The tag slug',
		),
		'response_format'      => array(
			'slug'    => '(string) The slug of the deleted tag',
			'success' => '(bool) Was the operation successful?',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/tags/slug:$tag/delete',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
	)
);

/**
 * Update site taxonomy API class.
 */
class WPCOM_JSON_API_Update_Taxonomy_Endpoint extends WPCOM_JSON_API_Taxonomy_Endpoint {
	/**
	 * Update site taxonomy API callback.
	 *
	 * - /sites/%s/tags|categories/new            -> $blog_id
	 * - /sites/%s/tags|categories/slug:%s        -> $blog_id, $taxonomy_id
	 * - /sites/%s/tags|categories/slug:%s/delete -> $blog_id, $taxonomy_id
	 *
	 * @param string     $path API path.
	 * @param int        $blog_id Blog ID.
	 * @param int|string $object_id Term.
	 */
	public function callback( $path = '', $blog_id = 0, $object_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		if ( preg_match( '#/tags/#i', $path ) ) {
			$taxonomy_type = 'post_tag';
		} else {
			$taxonomy_type = 'category';
		}

		if ( $this->api->ends_with( $path, '/delete' ) ) {
			return $this->delete_taxonomy( $path, $blog_id, $object_id, $taxonomy_type );
		} elseif ( $this->api->ends_with( $path, '/new' ) ) {
			return $this->new_taxonomy( $path, $blog_id, $taxonomy_type );
		}

		return $this->update_taxonomy( $path, $blog_id, $object_id, $taxonomy_type );
	}

	/**
	 * Create a new taxonomy.
	 *
	 * - /sites/%s/tags|categories/new -> $blog_id
	 *
	 * @param string $path API path.
	 * @param int    $blog_id Blog ID.
	 * @param string $taxonomy_type Taxonomy type (category, post_tag).
	 */
	public function new_taxonomy( $path, $blog_id, $taxonomy_type ) {
		$args  = $this->query_args();
		$input = $this->input();
		if ( ! is_array( $input ) || ! $input || ! strlen( $input['name'] ) ) {
			return new WP_Error( 'invalid_input', 'Unknown data passed', 400 );
		}

		$user = wp_get_current_user();
		if ( ! $user || is_wp_error( $user ) || ! $user->ID ) {
			return new WP_Error( 'authorization_required', 'An active access token must be used to manage taxonomies.', 403 );
		}

		$tax = get_taxonomy( $taxonomy_type );
		if ( ! current_user_can( $tax->cap->edit_terms ) ) {
			return new WP_Error( 'unauthorized', 'User cannot edit taxonomy', 403 );
		}

		if ( 'category' !== $taxonomy_type || ! isset( $input['parent'] ) ) {
			$input['parent'] = 0;
		}

		$term = get_term_by( 'name', $input['name'], $taxonomy_type );
		if ( $term ) {
			// the same name is allowed as long as the parents are different.
			if ( $input['parent'] === $term->parent ) {
				return new WP_Error( 'duplicate', 'A taxonomy with that name already exists', 400 );
			}
		}

		$data = wp_insert_term(
			addslashes( $input['name'] ),
			$taxonomy_type,
			array(
				'description' => isset( $input['description'] ) ? addslashes( $input['description'] ) : '',
				'parent'      => $input['parent'],
			)
		);

		if ( is_wp_error( $data ) ) {
			return $data;
		}

		$taxonomy = get_term_by( 'id', $data['term_id'], $taxonomy_type );

		$return = $this->get_taxonomy( $taxonomy->slug, $taxonomy_type, $args['context'] );
		if ( ! $return || is_wp_error( $return ) ) {
			return $return;
		}

		/** This action is documented in json-endpoints/class.wpcom-json-api-site-settings-endpoint.php */
		do_action( 'wpcom_json_api_objects', 'taxonomies' );
		return $return;
	}

	/**
	 * Update a taxonomy.
	 *
	 * - /sites/%s/tags|categories/slug:%s -> $blog_id, $taxonomy_id
	 *
	 * @param string     $path API path.
	 * @param int        $blog_id Blog ID.
	 * @param int|string $object_id Term.
	 * @param string     $taxonomy_type Taxonomy type (category, post_tag).
	 */
	public function update_taxonomy( $path, $blog_id, $object_id, $taxonomy_type ) {
		$taxonomy = get_term_by( 'slug', $object_id, $taxonomy_type );
		$tax      = get_taxonomy( $taxonomy_type );
		if ( ! current_user_can( $tax->cap->edit_terms ) ) {
			return new WP_Error( 'unauthorized', 'User cannot edit taxonomy', 403 );
		}

		if ( ! $taxonomy || is_wp_error( $taxonomy ) ) {
			return new WP_Error( 'unknown_taxonomy', 'Unknown taxonomy', 404 );
		}

		if ( false === term_exists( $object_id, $taxonomy_type ) ) {
			return new WP_Error( 'unknown_taxonomy', 'That taxonomy does not exist', 404 );
		}

		$args  = $this->query_args();
		$input = $this->input( false );
		if ( ! is_array( $input ) || ! $input ) {
			return new WP_Error( 'invalid_input', 'Invalid request input', 400 );
		}

		$update = array();
		if ( 'category' === $taxonomy_type && ! empty( $input['parent'] ) ) {
			$update['parent'] = $input['parent'];
		}

		if ( ! empty( $input['description'] ) ) {
			$update['description'] = addslashes( $input['description'] );
		}

		if ( ! empty( $input['name'] ) ) {
			$update['name'] = addslashes( $input['name'] );
		}

		$data     = wp_update_term( $taxonomy->term_id, $taxonomy_type, $update );
		$taxonomy = get_term_by( 'id', $data['term_id'], $taxonomy_type );

		$return = $this->get_taxonomy( $taxonomy->slug, $taxonomy_type, $args['context'] );
		if ( ! $return || is_wp_error( $return ) ) {
			return $return;
		}

		/** This action is documented in json-endpoints/class.wpcom-json-api-site-settings-endpoint.php */
		do_action( 'wpcom_json_api_objects', 'taxonomies' );
		return $return;
	}

	/**
	 * Delete a taxonomy.
	 *
	 * - /sites/%s/tags|categories/%s/delete -> $blog_id, $taxonomy_id
	 *
	 * @param string     $path API path.
	 * @param int        $blog_id Blog ID.
	 * @param int|string $object_id Term.
	 * @param string     $taxonomy_type Taxonomy type (category, post_tag).
	 */
	public function delete_taxonomy( $path, $blog_id, $object_id, $taxonomy_type ) {
		$taxonomy = get_term_by( 'slug', $object_id, $taxonomy_type );
		$tax      = get_taxonomy( $taxonomy_type );
		if ( ! current_user_can( $tax->cap->delete_terms ) ) {
			return new WP_Error( 'unauthorized', 'User cannot edit taxonomy', 403 );
		}

		if ( ! $taxonomy || is_wp_error( $taxonomy ) ) {
			return new WP_Error( 'unknown_taxonomy', 'Unknown taxonomy', 404 );
		}

		if ( false === term_exists( $object_id, $taxonomy_type ) ) {
			return new WP_Error( 'unknown_taxonomy', 'That taxonomy does not exist', 404 );
		}

		$args   = $this->query_args();
		$return = $this->get_taxonomy( $taxonomy->slug, $taxonomy_type, $args['context'] );
		if ( ! $return || is_wp_error( $return ) ) {
			return $return;
		}

		/** This action is documented in json-endpoints/class.wpcom-json-api-site-settings-endpoint.php */
		do_action( 'wpcom_json_api_objects', 'taxonomies' );

		wp_delete_term( $taxonomy->term_id, $taxonomy_type );

		return array(
			'slug'    => (string) $taxonomy->slug,
			'success' => 'true',
		);
	}
}
