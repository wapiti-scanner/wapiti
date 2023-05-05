<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * List users endpoint.
 */
new WPCOM_JSON_API_List_Users_Endpoint(
	array(
		'description'          => 'List the users of a site.',
		'group'                => 'users',
		'stat'                 => 'users:list',

		'method'               => 'GET',
		'path'                 => '/sites/%s/users',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
		),

		'query_parameters'     => array(
			'number'          => '(int=20) Limit the total number of authors returned.',
			'offset'          => '(int=0) The first n authors to be skipped in the returned array.',
			'order'           => array(
				'DESC' => 'Return authors in descending order.',
				'ASC'  => 'Return authors in ascending order.',
			),
			'order_by'        => array(
				'ID'           => 'Order by ID (default).',
				'login'        => 'Order by username.',
				'nicename'     => 'Order by nicename.',
				'email'        => 'Order by author email address.',
				'url'          => 'Order by author URL.',
				'registered'   => 'Order by registered date.',
				'display_name' => 'Order by display name.',
				'post_count'   => 'Order by number of posts published.',
			),
			'authors_only'    => '(bool) Set to true to fetch authors only',
			'include_viewers' => '(bool) Set to true to include viewers for Simple sites. When you pass in this parameter, order, order_by and search_columns are ignored. Currently, `search` is limited to the first page of results.',
			'type'            => "(string) Specify the post type to query authors for. Only works when combined with the `authors_only` flag. Defaults to 'post'. Post types besides post and page need to be whitelisted using the <code>rest_api_allowed_post_types</code> filter.",
			'search'          => '(string) Find matching users.',
			'search_columns'  => "(array) Specify which columns to check for matching users. Can be any of 'ID', 'user_login', 'user_email', 'user_url', 'user_nicename', and 'display_name'. Only works when combined with `search` parameter.",
			'role'            => '(string) Specify a specific user role to fetch.',
		),

		'response_format'      => array(
			'found'   => '(int) The total number of authors found that match the request (ignoring limits and offsets).',
			'authors' => '(array:author) Array of author objects.',
		),

		'example_response'     => '{
		"found": 1,
		"users": [
			{
				"ID": 78972699,
				"login": "apiexamples",
				"email": "justin+apiexamples@a8c.com",
				"name": "apiexamples",
				"first_name": "",
				"last_name": "",
				"nice_name": "apiexamples",
				"URL": "http://apiexamples.wordpress.com",
				"avatar_URL": "https://1.gravatar.com/avatar/a2afb7b6c0e23e5d363d8612fb1bd5ad?s=96&d=identicon&r=G",
				"profile_URL": "https://en.gravatar.com/apiexamples",
				"site_ID": 82974409,
				"roles": [
					"administrator"
				],
				"is_super_admin": false
			}
		]
	}',

		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/users',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
	)
);

/**
 * List users endpoint class.
 *
 * /sites/%s/users/ -> $blog_id
 */
class WPCOM_JSON_API_List_Users_Endpoint extends WPCOM_JSON_API_Endpoint {

	/**
	 * The response format.
	 *
	 * @var array
	 */
	public $response_format = array(
		'found' => '(int) The total number of authors found that match the request (ignoring limits and offsets).',
		'users' => '(array:author) Array of user objects',
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

		$args = $this->query_args();

		$authors_only = ( ! empty( $args['authors_only'] ) );

		if ( $args['number'] < 1 ) {
			$args['number'] = 20;
		} elseif ( 1000 < $args['number'] ) {
			return new WP_Error( 'invalid_number', 'The NUMBER parameter must be less than or equal to 1000.', 400 );
		}

		if ( $authors_only ) {
			if ( empty( $args['type'] ) ) {
				$args['type'] = 'post';
			}

			if ( ! $this->is_post_type_allowed( $args['type'] ) ) {
				return new WP_Error( 'unknown_post_type', 'Unknown post type', 404 );
			}

			$post_type_object = get_post_type_object( $args['type'] );
			if ( ! $post_type_object || ! current_user_can( $post_type_object->cap->edit_others_posts ) ) {
				return new WP_Error( 'unauthorized', 'User cannot view authors for specified post type', 403 );
			}
		} elseif ( ! current_user_can( 'list_users' ) ) {
			return new WP_Error( 'unauthorized', 'User cannot view users for specified site', 403 );
		}

		$query = array(
			'number'  => $args['number'],
			'offset'  => $args['offset'],
			'order'   => $args['order'],
			'orderby' => $args['order_by'],
			'fields'  => 'ID',
		);

		if ( $authors_only ) {
			$query['capability'] = array( 'edit_posts' );
		}

		if ( ! empty( $args['search'] ) ) {
			$query['search'] = $args['search'];
		}

		if ( ! empty( $args['search_columns'] ) ) {
			// this `user_search_columns` filter is necessary because WP_User_Query does not allow `display_name` as a search column.
			$this->search_columns = array_intersect( $args['search_columns'], array( 'ID', 'user_login', 'user_email', 'user_url', 'user_nicename', 'display_name' ) );
			add_filter( 'user_search_columns', array( $this, 'api_user_override_search_columns' ), 10, 3 );
		}

		if ( ! empty( $args['role'] ) ) {
			$query['role'] = $args['role'];
		}

		$user_query = new WP_User_Query( $query );

		remove_filter( 'user_search_columns', array( $this, 'api_user_override_search_columns' ) );

		$is_wpcom        = defined( 'IS_WPCOM' ) && IS_WPCOM;
		$include_viewers = (bool) isset( $args['include_viewers'] ) && $args['include_viewers'] && $is_wpcom;

		$page    = ( (int) ( $args['offset'] / $args['number'] ) ) + 1;
		$viewers = $include_viewers ? get_private_blog_users(
			$blog_id,
			array(
				'page'     => $page,
				'per_page' => $args['number'],
			)
		) : array();
		$viewers = array_map( array( $this, 'get_author' ), $viewers );

		// we restrict search field to name when include_viewers is true.
		if ( $include_viewers && ! empty( $args['search'] ) ) {
			$viewers = array_filter(
				$viewers,
				function ( $viewer ) use ( $args ) {
					// remove special database search characters from search term
					$search_term = str_replace( '*', '', $args['search'] );
					return strpos( $viewer->name, $search_term ) !== false;
				}
			);
		}

		$return = array();
		foreach ( array_keys( $this->response_format ) as $key ) {
			switch ( $key ) {
				case 'found':
					$user_count = (int) $user_query->get_total();

					$viewer_count = 0;
					if ( $include_viewers ) {
						if ( empty( $args['search'] ) ) {
							$viewer_count = (int) get_count_private_blog_users( $blog_id );
						} else {
							$viewer_count = count( $viewers );
						}
					}

					$return[ $key ] = $user_count + $viewer_count;
					break;
				case 'users':
					$users        = array();
					$is_multisite = is_multisite();
					foreach ( $user_query->get_results() as $u ) {
						$the_user = $this->get_author( $u, true );
						if ( $the_user && ! is_wp_error( $the_user ) ) {
							$userdata        = get_userdata( $u );
							$the_user->roles = ! is_wp_error( $userdata ) ? array_values( $userdata->roles ) : array();
							if ( $is_multisite ) {
								$the_user->is_super_admin = user_can( $the_user->ID, 'manage_network' );
							}
							$users[] = $the_user;
						}
					}

					$combined_users = array_merge( $users, $viewers );

					// When viewers are included, we ignore the order & orderby parameters.
					if ( $include_viewers ) {
						usort(
							$combined_users,
							function ( $a, $b ) {
								return strcmp( strtolower( $a->name ), strtolower( $b->name ) );
							}
						);
					}

					$return[ $key ] = $combined_users;
					break;
			}
		}

		return $return;
	}

	/**
	 * Override search columns.
	 *
	 * @param array $search_columns - the search column we're overriding.
	 * @param array $search - the search query.
	 */
	public function api_user_override_search_columns( $search_columns, $search ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return $this->search_columns;
	}
}
