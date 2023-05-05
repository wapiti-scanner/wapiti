<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

new WPCOM_JSON_API_Site_User_Endpoint(
	array(
		'description'          => 'Get details of a user of a site by ID.',
		'group'                => '__do_not_document', // 'users'
		'stat'                 => 'sites:1:user',
		'method'               => 'GET',
		'path'                 => '/sites/%s/users/%d',
		'path_labels'          => array(
			'$site'    => '(int|string) Site ID or domain',
			'$user_id' => '(int) User ID',
		),
		'response_format'      => WPCOM_JSON_API_Site_User_Endpoint::$user_format,
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/30434183/user/23',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_response'     => '{
		"ID": 18342963,
		"login": "binarysmash",
		"email": false,
		"name": "binarysmash",
		"URL": "http:\/\/binarysmash.wordpress.com",
		"avatar_URL": "http:\/\/0.gravatar.com\/avatar\/a178ebb1731d432338e6bb0158720fcc?s=96&d=identicon&r=G",
		"profile_URL": "http:\/\/en.gravatar.com\/binarysmash",
		"roles": [ "administrator" ]
	}',
	)
);

new WPCOM_JSON_API_Site_User_Endpoint(
	array(
		'description'          => 'Get details of a user of a site by login.',
		'group'                => 'users',
		'stat'                 => 'sites:1:user',
		'method'               => 'GET',
		'path'                 => '/sites/%s/users/login:%s',
		'path_labels'          => array(
			'$site'    => '(int|string) The site ID or domain.',
			'$user_id' => '(string) The user\'s login.',
		),
		'response_format'      => WPCOM_JSON_API_Site_User_Endpoint::$user_format,
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/30434183/user/login:binarysmash',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_response'     => '{
		"ID": 18342963,
		"login": "binarysmash",
		"email": false,
		"name": "binarysmash",
		"URL": "http:\/\/binarysmash.wordpress.com",
		"avatar_URL": "http:\/\/0.gravatar.com\/avatar\/a178ebb1731d432338e6bb0158720fcc?s=96&d=identicon&r=G",
		"profile_URL": "http:\/\/en.gravatar.com\/binarysmash",
		"roles": [ "administrator" ]
	}',
	)
);

new WPCOM_JSON_API_Site_User_Endpoint(
	array(
		'description'          => 'Update details of a user of a site.',
		'group'                => 'users',
		'stat'                 => 'sites:1:user',
		'method'               => 'POST',
		'path'                 => '/sites/%s/users/%d',
		'path_labels'          => array(
			'$site'    => '(int|string) The site ID or domain.',
			'$user_id' => '(int) The user\'s ID.',
		),
		'request_format'       => WPCOM_JSON_API_Site_User_Endpoint::$user_format,
		'response_format'      => WPCOM_JSON_API_Site_User_Endpoint::$user_format,
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/30434183/user/23',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'roles'      => array(
					array(
						'administrator',
					),
				),
				'first_name' => 'Rocco',
				'last_name'  => 'Tripaldi',
			),
		),
		'example_response'     => '{
		"ID": 18342963,
		"login": "binarysmash",
		"email": false,
		"name": "binarysmash",
		"URL": "http:\/\/binarysmash.wordpress.com",
		"avatar_URL": "http:\/\/0.gravatar.com\/avatar\/a178ebb1731d432338e6bb0158720fcc?s=96&d=identicon&r=G",
		"profile_URL": "http:\/\/en.gravatar.com\/binarysmash",
		"roles": [ "administrator" ]
	}',
	)
);

/**
 * Site user endpoint class.
 *
 * /sites/%s/users/%d -> $blog_id, $user_id
 */
class WPCOM_JSON_API_Site_User_Endpoint extends WPCOM_JSON_API_Endpoint {

	/**
	 * User format.
	 *
	 * @var array
	 */
	public static $user_format = array(
		'ID'          => '(int) The ID of the user',
		'login'       => '(string) The login username of the user',
		'email'       => '(string) The email of the user',
		'name'        => '(string) The name to display for the user',
		'first_name'  => '(string) The first name of the user',
		'last_name'   => '(string) The last name of the user',
		'nice_name'   => '(string) The nice_name to display for the user',
		'URL'         => '(string) The primary blog of the user',
		'avatar_URL'  => '(url) Gravatar image URL',
		'profile_URL' => '(url) Gravatar Profile URL',
		'site_ID'     => '(int) ID of the user\'s primary blog',
		'roles'       => '(array|string) The role or roles of the user',
	);

	/**
	 * API Callback.
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 * @param int    $user_id - the user ID.
	 *
	 * @return array|WP_Error
	 */
	public function callback( $path = '', $blog_id = 0, $user_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}
		if ( ! current_user_can_for_blog( $blog_id, 'list_users' ) ) {
			return new WP_Error( 'unauthorized', 'User cannot view users for specified site', 403 );
		}

		// Get the user by ID or login
		$get_by = false !== strpos( $path, '/users/login:' ) ? 'login' : 'id';
		$user   = get_user_by( $get_by, $user_id );

		if ( ! $user ) {
			return new WP_Error( 'unknown_user', 'Unknown user', 404 );
		}

		if ( ! is_user_member_of_blog( $user->ID, $blog_id ) ) {
			return new WP_Error( 'unknown_user_for_site', 'Unknown user for site', 404 );
		}

		if ( 'GET' === $this->api->method ) {
			return $this->get_user( $user->ID );
		} elseif ( 'POST' === $this->api->method ) {
			if ( ! current_user_can_for_blog( $blog_id, 'promote_users' ) ) {
				return new WP_Error( 'unauthorized_no_promote_cap', 'User cannot promote users for specified site', 403 );
			}
			return $this->update_user( $user_id, $blog_id );
		} else {
			return new WP_Error( 'bad_request', 'An unsupported request method was used.' );
		}
	}

	/**
	 * Get the user.
	 *
	 * @param int $user_id - the user ID.
	 *
	 * @return object
	 */
	public function get_user( $user_id ) {
		$the_user = $this->get_author( $user_id, true );
		if ( $the_user && ! is_wp_error( $the_user ) ) {
			$userdata        = get_userdata( $user_id );
			$the_user->roles = ! is_wp_error( $userdata ) ? array_values( $userdata->roles ) : array();
		}

		return $the_user;
	}

	/**
	 * Updates user data.
	 *
	 * @param int $user_id - the user ID.
	 * @param int $blog_id - the blog ID.
	 *
	 * @return array|WP_Error
	 */
	public function update_user( $user_id, $blog_id ) {
		$user       = array();
		$input      = $this->input();
		$user['ID'] = $user_id;
		$is_wpcom   = defined( 'IS_WPCOM' ) && IS_WPCOM;

		if ( get_current_user_id() === (int) $user_id && isset( $input['roles'] ) ) {
			return new WP_Error( 'unauthorized', 'You cannot change your own role', 403 );
		}

		if ( $is_wpcom && $user_id !== get_current_user_id() && (int) $user_id === wpcom_get_blog_owner( $blog_id ) ) {
			return new WP_Error( 'unauthorized_edit_owner', 'Current user can not edit blog owner', 403 );
		}

		if ( ! $is_wpcom ) {
			foreach ( $input as $key => $value ) {
				if ( ! is_array( $value ) ) {
					$value = trim( $value );
				}
				$value = wp_unslash( $value );
				switch ( $key ) {
					case 'first_name':
					case 'last_name':
						$user[ $key ] = $value;
						break;
					case 'display_name':
					case 'name':
						$user['display_name'] = $value;
						break;
				}
			}
		}

		if ( isset( $input['roles'] ) ) {
			// For now, we only use the first role in the array.
			if ( is_array( $input['roles'] ) ) {
				$user['role'] = $input['roles'][0];
			} elseif ( is_string( $input['roles'] ) ) {
				$user['role'] = $input['roles'];
			} else {
				return new WP_Error( 'invalid_input', __( 'The roles property must be a string or an array.', 'jetpack' ), 400 );
			}

			$editable_roles = array_keys( get_editable_roles() );
			if ( ! in_array( $user['role'], $editable_roles, true ) ) {
				return new WP_Error(
					'invalid_input',
					sprintf(
						/* Translators: placeholder is an invalid role name */
						esc_html__( '%s is not a valid role.', 'jetpack' ),
						$editable_roles
					),
					400
				);
			}
		}

		$result = wp_update_user( $user );
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		return $this->get_user( $user_id );
	}

}
