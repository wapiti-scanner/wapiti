<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * List post types endpoint.
 */
new WPCOM_JSON_API_List_Post_Types_Endpoint(
	array(
		'description'                          => 'Get a list of post types available for a site.',
		'group'                                => 'sites',
		'stat'                                 => 'sites:X:post-types',

		'method'                               => 'GET',
		'path'                                 => '/sites/%s/post-types',
		'path_labels'                          => array(
			'$site' => '(int|string) Site ID or domain',
		),

		'allow_fallback_to_jetpack_blog_token' => true,

		'query_parameters'                     => array(
			'api_queryable' => '(bool) If true, only queryable post types are returned',
		),

		'response_format'                      => array(
			'found'      => '(int) The number of post types found',
			'post_types' => '(array) A list of available post types',
		),
		'example_request'                      => 'https://public-api.wordpress.com/rest/v1.1/sites/33534099/post-types',
	)
);

/**
 * List Post types endpoint class.
 *
 * /sites/%s/post-types -> $blog_id
 */
class WPCOM_JSON_API_List_Post_Types_Endpoint extends WPCOM_JSON_API_Endpoint {

	/**
	 * Post type keys to include.
	 *
	 * @var array
	 */
	public static $post_type_keys_to_include = array(
		'name'               => 'name',
		'label'              => 'label',
		'labels'             => 'labels',
		'description'        => 'description',
		'map_meta_cap'       => 'map_meta_cap',
		'cap'                => 'capabilities',
		'hierarchical'       => 'hierarchical',
		'public'             => 'public',
		'show_ui'            => 'show_ui',
		'publicly_queryable' => 'publicly_queryable',
	);

	/**
	 * API callback.
	 *
	 * @param string $path - the path.
	 * @param string $blog_id - the blog ID.
	 */
	public function callback( $path = '', $blog_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$this->load_theme_functions();

			/**
			 * Whether API responses should be returned in a custom locale.  False
			 * for Jetpack; may be true for WP.com requests.
			 *
			 * @since 3.9.2
			 */
			if ( apply_filters( 'rest_api_localize_response', false ) ) {
				// API localization occurs after the initial post types have been
				// registered, so let's get the post type labels translated.
				if ( 'en' !== get_locale() ) {
					global $wp_post_types;
					foreach ( $wp_post_types as $post_type_object ) {
						foreach ( array_keys( (array) $post_type_object->labels ) as $label_key ) {
							// Direct use of translate call because this doesn't need to be extracted.
							// phpcs:ignore WordPress.WP.I18n
							$post_type_object->labels->$label_key = translate( $post_type_object->labels->$label_key, 'default' );
						}
					}
				}
			}
		}

		// Get a list of available post types.
		$post_types                  = get_post_types();
		$formatted_post_type_objects = array();

		// Retrieve post type object for each post type.
		foreach ( $post_types as $post_type ) {
			// Skip non-queryable if filtering on queryable only.
			$is_queryable = $this->is_post_type_allowed( $post_type );
			if ( ! $is_queryable ) {
				continue;
			}

			$post_type_object           = get_post_type_object( $post_type );
			$formatted_post_type_object = array();

			// Include only the desired keys in the response.
			foreach ( self::$post_type_keys_to_include as $key => $value ) {
				$formatted_post_type_object[ $value ] = $post_type_object->{ $key };
			}
			$formatted_post_type_object['api_queryable'] = $is_queryable;
			$formatted_post_type_object['supports']      = get_all_post_type_supports( $post_type );
			if ( $this->post_type_supports_tags( $post_type ) ) {
				$formatted_post_type_object['supports']['tags'] = true;
			}

			$formatted_post_type_objects[] = $formatted_post_type_object;
		}

		return array(
			'found'      => count( $formatted_post_type_objects ),
			'post_types' => $formatted_post_type_objects,
		);
	}

	/**
	 * See if post type supports tags.
	 *
	 * @param string $post_type - the post type.
	 */
	public function post_type_supports_tags( $post_type ) {
		if ( in_array( 'post_tag', get_object_taxonomies( $post_type ), true ) ) {
			return true;
		}

		// the featured content module adds post_tag support
		// to the post types that are registered for it
		// however it does so in a way that isn't available
		// to get_object_taxonomies.
		$featured_content = get_theme_support( 'featured-content' );
		if ( ! $featured_content || empty( $featured_content[0] ) || empty( $featured_content[0]['post_types'] ) ) {
			return false;
		}

		if ( is_array( $featured_content[0]['post_types'] ) ) {
			return in_array( $post_type, $featured_content[0]['post_types'], true );
		}
		return $post_type === $featured_content[0]['post_types'];
	}
}
