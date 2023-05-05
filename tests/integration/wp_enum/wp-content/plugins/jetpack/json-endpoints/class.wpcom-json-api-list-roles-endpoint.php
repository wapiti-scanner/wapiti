<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * List roles endpoint.
 */
new WPCOM_JSON_API_List_Roles_Endpoint(
	array(
		'description'          => 'List the user roles of a site.',
		'group'                => '__do_not_document',
		'stat'                 => 'roles:list',
		'max_version'          => '1.1',
		'method'               => 'GET',
		'path'                 => '/sites/%s/roles',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
		),

		'query_parameters'     => array(),

		'response_format'      => array(
			'roles' => '(array:role) Array of role objects.',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/roles',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
	)
);

new WPCOM_JSON_API_List_Roles_Endpoint(
	array(
		'description'          => 'List the user roles of a site.',
		'group'                => '__do_not_document',
		'stat'                 => 'roles:list',
		'min_version'          => '1.2',
		'force'                => 'wpcom',
		'method'               => 'GET',
		'path'                 => '/sites/%s/roles',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
		),

		'query_parameters'     => array(),

		'response_format'      => array(
			'roles' => '(array:role) Array of role objects.',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/roles',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
	)
);

/**
 * List Roles endpoint class.
 *
 * /sites/%s/roles/ -> $blog_id
 */
class WPCOM_JSON_API_List_Roles_Endpoint extends WPCOM_JSON_API_Endpoint {

	/**
	 * Response format.
	 *
	 * @var array
	 */
	public $response_format = array(
		'roles' => '(array:role) Array of role objects',
	);

	/**
	 * Sort so roles with the most number of capabilities comes first, then the next role, and so on.
	 *
	 * @param object $a - the first object we're comparing.
	 * @param object $b - the second object we're comparing.
	 */
	public static function role_sort( $a, $b ) {
		$core_role_names = array( 'administrator', 'editor', 'author', 'contributor', 'subscriber' );
		$a_is_core_role  = in_array( $a->name, $core_role_names, true );
		$b_is_core_role  = in_array( $b->name, $core_role_names, true );

		// if $a is a core_role and $b is not, $a always comes first.
		if ( $a_is_core_role && ! $b_is_core_role ) {
			return -1;
		}

		// if $b is a core_role and $a is not, $b always comes first.
		if ( $b_is_core_role && ! $a_is_core_role ) {
			return 1;
		}

		// otherwise the one with the > number of capabilities comes first.
		$a_cap_count = count( $a->capabilities );
		$b_cap_count = count( $b->capabilities );

		if ( $a_cap_count === $b_cap_count ) {
			return 0;
		}

		return ( $a_cap_count > $b_cap_count ) ? -1 : 1;
	}

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

		$roles = array();

		$sal_site = $this->get_platform()->get_site( $blog_id );
		$wp_roles = $sal_site->get_roles();

		// Check if the site is connected and talks to us on a regular basis.
		$is_connected = $sal_site->is_connected_site();
		if ( is_wp_error( $is_connected ) ) {
			return $is_connected;
		}

		if ( ! $sal_site->current_user_can( 'list_users' ) ) {
			return new WP_Error( 'unauthorized', 'User cannot view roles for specified site', 403 );
		}

		if ( method_exists( $wp_roles, 'get_names' ) ) {
			$role_names = $wp_roles->get_names();

			$role_keys = array_keys( $role_names );

			foreach ( (array) $role_keys as $role_key ) {
				$role_details               = get_role( $role_key );
				$role_details->display_name = translate_user_role( $role_names[ $role_key ] );
				$roles[]                    = $role_details;
			}
		} else {
			// Jetpack Shadow Site side of things.
			foreach ( $wp_roles as $role_key => $role ) {
				$roles[] = (object) array(
					'name'         => $role_key,
					'display_name' => $role['name'],
					'capabilities' => (object) $role['capabilities'],
				);
			}
		}

		usort( $roles, array( 'self', 'role_sort' ) );

		/**
		 * Filter for curating the list of roles available for a wpcom site.
		 *
		 * @module json-api
		 *
		 * @since 8.7.0
		 *
		 * @param array $roles List of role objects available to the site.
		 */
		$roles = apply_filters( 'wpcom_api_site_roles', $roles );

		return array( 'roles' => $roles );
	}
}
