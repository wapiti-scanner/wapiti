<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Update site terms API endpoints.
 *
 * Endpoints:
 * Create a new term: /sites/%s/taxonomies/%s/terms/new
 * Edit a term:       /sites/%s/taxonomies/%s/terms/slug:%s
 * Delete a term:     /sites/%s/taxonomies/%s/terms/slug:%s/delete
 */

new WPCOM_JSON_API_Update_Term_Endpoint(
	array(
		'description'          => 'Create a new term.',
		'group'                => 'taxonomy',
		'stat'                 => 'terms:new',
		'method'               => 'POST',
		'path'                 => '/sites/%s/taxonomies/%s/terms/new',
		'path_labels'          => array(
			'$site'     => '(int|string) Site ID or domain',
			'$taxonomy' => '(string) Taxonomy',
		),
		'request_format'       => array(
			'name'        => '(string) Name of the term',
			'description' => '(string) A description of the term',
			'parent'      => '(int) The parent ID for the term, if hierarchical',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/taxonomies/post_tag/terms/new',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'name' => 'Ribs & Chicken',
			),
		),
	)
);

new WPCOM_JSON_API_Update_Term_Endpoint(
	array(
		'description'          => 'Edit a term.',
		'group'                => 'taxonomy',
		'stat'                 => 'terms:1:POST',
		'method'               => 'POST',
		'path'                 => '/sites/%s/taxonomies/%s/terms/slug:%s',
		'path_labels'          => array(
			'$site'     => '(int|string) Site ID or domain',
			'$taxonomy' => '(string) Taxonomy',
			'$slug'     => '(string) The term slug',
		),
		'request_format'       => array(
			'name'        => '(string) Name of the term',
			'description' => '(string) A description of the term',
			'parent'      => '(int) The parent ID for the term, if hierarchical',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/taxonomies/post_tag/terms/slug:testing-term',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'description' => 'The most delicious',
			),
		),
	)
);

new WPCOM_JSON_API_Update_Term_Endpoint(
	array(
		'description'          => 'Delete a term.',
		'group'                => 'taxonomy',
		'stat'                 => 'terms:1:delete',
		'method'               => 'POST',
		'path'                 => '/sites/%s/taxonomies/%s/terms/slug:%s/delete',
		'path_labels'          => array(
			'$site'     => '(int|string) Site ID or domain',
			'$taxonomy' => '(string) Taxonomy',
			'$slug'     => '(string) The term slug',
		),
		'response_format'      => array(
			'slug'    => '(string) The slug of the deleted term',
			'success' => '(bool) Whether the operation was successful',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/taxonomies/post_tag/terms/slug:$term/delete',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
	)
);

/**
 * Update site terms API endpoint class.
 */
class WPCOM_JSON_API_Update_Term_Endpoint extends WPCOM_JSON_API_Taxonomy_Endpoint {
	/**
	 * Update site terms API callback.
	 *
	 * - /sites/%s/taxonomies/%s/terms/new            -> $blog_id, $taxonomy
	 * - /sites/%s/taxonomies/%s/terms/slug:%s        -> $blog_id, $taxonomy, $slug
	 * - /sites/%s/taxonomies/%s/terms/slug:%s/delete -> $blog_id, $taxonomy, $slug
	 *
	 * @param string     $path API path.
	 * @param int        $blog_id Blog ID.
	 * @param string     $taxonomy Taxonomy.
	 * @param int|string $slug Slug, term name.
	 */
	public function callback( $path = '', $blog_id = 0, $taxonomy = 'category', $slug = 0 ) {
		$slug    = urldecode( $slug );
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$this->load_theme_functions();
		}

		$user = wp_get_current_user();
		if ( ! $user || is_wp_error( $user ) || ! $user->ID ) {
			return new WP_Error( 'authorization_required', 'An active access token must be used to manage taxonomies.', 403 );
		}

		$taxonomy_meta = get_taxonomy( $taxonomy );
		if ( false === $taxonomy_meta || (
				! $taxonomy_meta->public &&
				! current_user_can( $taxonomy_meta->cap->manage_terms ) &&
				! current_user_can( $taxonomy_meta->cap->edit_terms ) &&
				! current_user_can( $taxonomy_meta->cap->delete_terms ) ) ) {
			return new WP_Error( 'invalid_taxonomy', 'The taxonomy does not exist', 400 );
		}

		if ( $this->api->ends_with( $path, '/delete' ) ) {
			return $this->delete_term( $path, $blog_id, $slug, $taxonomy );
		} elseif ( $this->api->ends_with( $path, '/new' ) ) {
			return $this->new_term( $path, $blog_id, $taxonomy );
		}

		return $this->update_term( $path, $blog_id, $slug, $taxonomy );
	}

	/**
	 * Create a new term.
	 *
	 * - /sites/%s/taxonomies/%s/terms/new -> $blog_id, $taxonomy
	 *
	 * @param string $path API path.
	 * @param int    $blog_id Blog ID.
	 * @param string $taxonomy Taxonomy.
	 */
	public function new_term( $path, $blog_id, $taxonomy ) {
		$args  = $this->query_args();
		$input = $this->input();
		if ( ! is_array( $input ) || ! $input || ! strlen( $input['name'] ) ) {
			return new WP_Error( 'invalid_input', 'Unknown data passed', 400 );
		}

		$tax = get_taxonomy( $taxonomy );
		if ( ! current_user_can( $tax->cap->manage_terms ) ) {
			return new WP_Error( 'unauthorized', 'User cannot edit taxonomy', 403 );
		}

		if ( ! isset( $input['parent'] ) || ! is_taxonomy_hierarchical( $taxonomy ) ) {
			$input['parent'] = 0;
		}

		$term = get_term_by( 'name', $input['name'], $taxonomy );
		if ( $term ) {
			// the same name is allowed as long as the parents are different.
			if ( $input['parent'] === $term->parent ) {
				return new WP_Error( 'duplicate', 'A taxonomy with that name already exists', 409 );
			}
		}

		$data = wp_insert_term(
			addslashes( $input['name'] ),
			$taxonomy,
			array(
				'description' => isset( $input['description'] ) ? addslashes( $input['description'] ) : '',
				'parent'      => $input['parent'],
			)
		);

		if ( is_wp_error( $data ) ) {
			return $data;
		}

		$term = get_term_by( 'id', $data['term_id'], $taxonomy );

		$return = $this->get_taxonomy( $term->slug, $taxonomy, $args['context'] );
		if ( ! $return || is_wp_error( $return ) ) {
			return $return;
		}

		/** This action is documented in json-endpoints/class.wpcom-json-api-site-settings-endpoint.php */
		do_action( 'wpcom_json_api_objects', 'terms' );
		return $return;
	}

	/**
	 * Update a term.
	 *
	 * - /sites/%s/taxonomies/%s/terms/slug:%s -> $blog_id, $taxonomy, $slug
	 *
	 * @param string     $path API path.
	 * @param int        $blog_id Blog ID.
	 * @param int|string $slug Slug, term name.
	 * @param string     $taxonomy Taxonomy.
	 */
	public function update_term( $path, $blog_id, $slug, $taxonomy ) {
		$tax = get_taxonomy( $taxonomy );
		if ( ! current_user_can( $tax->cap->edit_terms ) ) {
			return new WP_Error( 'unauthorized', 'User cannot edit taxonomy', 403 );
		}

		$term = get_term_by( 'slug', $slug, $taxonomy );
		if ( ! $term || is_wp_error( $term ) ) {
			return new WP_Error( 'unknown_taxonomy', 'Unknown taxonomy', 404 );
		}

		$args  = $this->query_args();
		$input = $this->input( false );
		if ( ! is_array( $input ) || ! $input ) {
			return new WP_Error( 'invalid_input', 'Invalid request input', 400 );
		}

		$update = array();
		if ( ! empty( $input['parent'] ) || is_taxonomy_hierarchical( $taxonomy ) ) {
			$update['parent'] = $input['parent'];
		}

		if ( isset( $input['description'] ) ) {
			$update['description'] = addslashes( $input['description'] );
		}

		if ( ! empty( $input['name'] ) ) {
			$update['name'] = addslashes( $input['name'] );
		}

		$data = wp_update_term( $term->term_id, $taxonomy, $update );
		if ( is_wp_error( $data ) ) {
			return $data;
		}

		$term = get_term_by( 'id', $data['term_id'], $taxonomy );

		$return = $this->get_taxonomy( $term->slug, $taxonomy, $args['context'] );
		if ( ! $return || is_wp_error( $return ) ) {
			return $return;
		}

		/** This action is documented in json-endpoints/class.wpcom-json-api-site-settings-endpoint.php */
		do_action( 'wpcom_json_api_objects', 'terms' );
		return $return;
	}

	/**
	 * Delete a term.
	 *
	 * - /sites/%s/taxonomies/%s/terms/slug:%s/delete -> $blog_id, $taxonomy, $slug
	 *
	 * @param string     $path API path.
	 * @param int        $blog_id Blog ID.
	 * @param int|string $slug Slug, term name.
	 * @param string     $taxonomy Taxonomy.
	 */
	public function delete_term( $path, $blog_id, $slug, $taxonomy ) {
		$term = get_term_by( 'slug', $slug, $taxonomy );
		$tax  = get_taxonomy( $taxonomy );
		if ( ! current_user_can( $tax->cap->delete_terms ) ) {
			return new WP_Error( 'unauthorized', 'User cannot edit taxonomy', 403 );
		}

		if ( ! $term || is_wp_error( $term ) ) {
			return new WP_Error( 'unknown_taxonomy', 'Unknown taxonomy', 404 );
		}

		$args   = $this->query_args();
		$return = $this->get_taxonomy( $term->slug, $taxonomy, $args['context'] );
		if ( ! $return || is_wp_error( $return ) ) {
			return $return;
		}

		/** This action is documented in json-endpoints/class.wpcom-json-api-site-settings-endpoint.php */
		do_action( 'wpcom_json_api_objects', 'terms' );

		wp_delete_term( $term->term_id, $taxonomy );

		return array(
			'slug'    => (string) $term->slug,
			'success' => true,
		);
	}
}
