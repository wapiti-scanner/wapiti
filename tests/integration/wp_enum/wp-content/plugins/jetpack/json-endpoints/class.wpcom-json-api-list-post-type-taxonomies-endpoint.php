<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * List post type taxonomies endpoint.
 */

new WPCOM_JSON_API_List_Post_Type_Taxonomies_Endpoint(
	array(
		'description'     => 'Get a list of taxonomies associated with a post type.',
		'group'           => 'taxonomy',
		'stat'            => 'sites:X:post-types:X:taxonomies',
		'method'          => 'GET',
		'path'            => '/sites/%s/post-types/%s/taxonomies',
		'path_labels'     => array(
			'$site'      => '(int|string) Site ID or domain',
			'$post_type' => '(string) Post type',
		),
		'response_format' => array(
			'found'      => '(int) The number of taxonomies found',
			'taxonomies' => '(array:taxonomy) A list of available taxonomies',
		),
		'example_request' => 'https://public-api.wordpress.com/rest/v1.1/sites/33534099/post-types/post/taxonomies',
	)
);

/**
 * List post type taxonomies endpoint class.
 *
 * /sites/%s/post-types/%s/taxonomies -> $blog_id, $post_type
 */
class WPCOM_JSON_API_List_Post_Type_Taxonomies_Endpoint extends WPCOM_JSON_API_Endpoint {

	/**
	 * Included taxonomy keys.
	 *
	 * @var array
	 */
	public static $taxonomy_keys_to_include = array(
		'name'         => 'name',
		'label'        => 'label',
		'labels'       => 'labels',
		'description'  => 'description',
		'hierarchical' => 'hierarchical',
		'public'       => 'public',
		'cap'          => 'capabilities',
	);

	/**
	 * API callback.
	 *
	 * @param string $path - the path.
	 * @param string $blog_id - the blog ID.
	 * @param string $post_type - the post type.
	 */
	public function callback( $path = '', $blog_id = 0, $post_type = 'post' ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$this->load_theme_functions();
		}

		$this->localize_initial_taxonomies( $post_type );

		$post_type_object = get_post_type_object( $post_type );
		if ( ! $post_type_object || ( ! $post_type_object->publicly_queryable && (
				! current_user_can( $post_type_object->cap->edit_posts ) ) ) ) {
			return new WP_Error( 'unknown_post_type', 'Unknown post type', 404 );
		}

		// Get a list of available taxonomies.
		$taxonomy_objects = get_object_taxonomies( $post_type, 'objects' );

		// Construct array of formatted objects.
		$formatted_taxonomy_objects = array();
		foreach ( $taxonomy_objects as $taxonomy_object ) {
			// Omit private taxonomies unless user has assign capability.
			if ( ! $taxonomy_object->public && ! current_user_can( $taxonomy_object->cap->assign_terms ) ) {
				continue;
			}

			// Include only the desired keys in the response.
			$formatted_taxonomy_object = array();
			foreach ( self::$taxonomy_keys_to_include as $key => $value ) {
				$formatted_taxonomy_object[ $value ] = $taxonomy_object->{ $key };
			}

			$formatted_taxonomy_objects[] = $formatted_taxonomy_object;
		}

		return array(
			'found'      => count( $formatted_taxonomy_objects ),
			'taxonomies' => $formatted_taxonomy_objects,
		);
	}

	/**
	 * Handle localizing initial taxonomies.
	 *
	 * @param string $post_type - the post type.
	 */
	protected function localize_initial_taxonomies( $post_type ) {
		/** This filter is documented in jetpack/json-endpoints/class.wpcom-json-api-list-post-types-endpoint.php */
		if ( ! apply_filters( 'rest_api_localize_response', false ) ) {
			return;
		}

		// Since recreating initial taxonomies will restore the default post
		// types to which they are associated, save post type's taxonomies in
		// case it was customized via `register_taxonomy_for_object_type`.
		$post_type_taxonomies = get_object_taxonomies( $post_type );

		// API localization occurs after the initial taxonomies have been
		// registered, so re-register if localizing response.
		create_initial_taxonomies();

		// Restore registered taxonomies for post type.
		foreach ( $post_type_taxonomies as $taxonomy ) {
			register_taxonomy_for_object_type( $taxonomy, $post_type );
		}
	}
}
