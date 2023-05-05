<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

// phpcs:disable Generic.Files.OneObjectStructurePerFile.MultipleFound
/**
 * Sharing button endpoint class.
 */
abstract class WPCOM_JSON_API_Sharing_Button_Endpoint extends WPCOM_JSON_API_Endpoint {

	/**
	 * All visibilties.
	 *
	 * @var array
	 */
	public static $all_visibilities = array( 'visible', 'hidden' );

	/**
	 * Sharing service.
	 *
	 * @var Sharing_Service
	 */
	protected $sharing_service;

	/**
	 * Setup function.
	 *
	 * @return null|WP_Error
	 */
	protected function setup() {
		if ( class_exists( 'Sharing_Service' ) ) {
			$this->sharing_service = new Sharing_Service();
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			return new WP_Error( 'forbidden', 'You do not have the capability to manage sharing buttons for this site', 403 );
		} elseif ( ! class_exists( 'Sharing_Service' ) || ! class_exists( 'Sharing_Source' ) ||
				( method_exists( 'Jetpack', 'is_module_active' ) && ! Jetpack::is_module_active( 'sharedaddy' ) ) ) {
			return new WP_Error( 'missing_jetpack_module', 'The Sharing module must be activated in order to use this endpoint', 400 );
		}
	}

	/**
	 * Format the sharing button.
	 *
	 * @param object $button - the button object.
	 * @return array
	 */
	public function format_sharing_button( $button ) {
		$response = array(
			'ID'        => $button->get_id(),
			'name'      => $button->get_name(),
			'shortname' => $button->shortname,
			'custom'    => is_a( $button, 'Share_Custom' ),
			'enabled'   => $this->is_button_enabled( $button ),
		);

		if ( $response['enabled'] ) {
			// Status is either "disabled" or the visibility value
			$response['visibility'] = $this->get_button_visibility( $button );
		}

		if ( ! empty( $button->icon ) ) {
			// Only pre-defined sharing buttons include genericon
			$response['genericon'] = $button->icon;
		}

		if ( method_exists( $button, 'get_options' ) ) {
			// merge get_options() values into response, primarily to account
			// for custom sharing button values
			foreach ( $button->get_options() as $key => $value ) {
				// Capitalize URL property
				if ( 'url' === strtolower( $key ) ) {
					$key = strtoupper( $key );
				}

				$response[ $key ] = $value;
			}
		}

		return $response;
	}

	/**
	 * Get the button visibility.
	 *
	 * @param object $button - the button object.
	 *
	 * @return string|false
	 */
	public function get_button_visibility( $button ) {
		$services     = $this->sharing_service->get_blog_services();
		$visibilities = self::$all_visibilities;
		$button_id    = $button->get_id();

		foreach ( $visibilities as $visibility ) {
			if ( isset( $services[ $visibility ][ $button_id ] ) ) {
				return $visibility;
			}
		}

		return false;
	}

	/**
	 * Check if the button is enabled.
	 *
	 * @param object $button - the button object.
	 *
	 * @return bool
	 */
	public function is_button_enabled( $button ) {
		return false !== $this->get_button_visibility( $button );
	}

	/**
	 * Check if button is for custom (?).
	 *
	 * @param array $button - the button array.
	 *
	 * @return bool
	 */
	protected function is_button_input_for_custom( $button ) {
		return ( isset( $button['custom'] ) && $button['custom'] ) ||
			( isset( $button['ID'] ) && 1 === preg_match( '/^custom-/', $button['ID'] ) ) ||
			! empty( $button['name'] ) || ! empty( $button['URL'] ) || ! empty( $button['icon'] );
	}

	/**
	 * Validate the button input.
	 *
	 * @param array $button - the button array.
	 * @param bool  $is_new - if the button is new.
	 *
	 * @return null|WP_Error
	 */
	protected function validate_button_input( $button, $is_new = false ) {
		if ( ! empty( $button['visibility'] ) && ! in_array( $button['visibility'], self::$all_visibilities, true ) ) {
			return new WP_Error( 'invalid_visibility', sprintf( 'The visibility field must be one of the following values: %s', implode( ', ', self::$all_visibilities ) ), 400 );
		} elseif ( $is_new && empty( $button['URL'] ) ) {
			return new WP_Error( 'invalid_request', 'The URL field is required', 400 );
		} elseif ( $is_new && empty( $button['icon'] ) ) {
			return new WP_Error( 'invalid_request', 'The icon field is required', 400 );
		}
	}

	/**
	 * Create a custom button.
	 *
	 * @param array $button - the button array.
	 *
	 * @return Share_Custom|false
	 */
	public function create_custom_button( $button ) {
		// Default visibility to 'visible' if enabled
		if ( empty( $button['visibility'] ) && true === $button['enabled'] ) {
			$button['visibility'] = 'visible';
		}

		$updated_service = $this->sharing_service->new_service( $button['name'], $button['URL'], $button['icon'] );
		if ( false !== $updated_service && ( true === $button['enabled'] || ! empty( $button['visibility'] ) ) ) {
			$blog_services = $this->sharing_service->get_blog_services();
			$blog_services[ $button['visibility'] ][ (string) $updated_service->get_id() ] = $updated_service;
			$this->sharing_service->set_blog_services( array_keys( $blog_services['visible'] ), array_keys( $blog_services['hidden'] ) );
		}

		return $updated_service;
	}

	/**
	 * Update the button.
	 *
	 * @param int   $button_id - the button id.
	 * @param array $button - the button array.
	 *
	 * @return Share_Custom|WP_Error
	 */
	public function update_button( $button_id, $button ) {
		$blog_services = $this->sharing_service->get_blog_services();

		// Find existing button
		$all_buttons = $this->sharing_service->get_all_services_blog();
		if ( ! array_key_exists( $button_id, $all_buttons ) ) {
			// Button doesn't exist
			return new WP_Error( 'not_found', 'The specified sharing button was not found', 404 );
		}

		$updated_service = $all_buttons[ $button_id ];
		$service_id      = $updated_service->get_id();
		if ( is_a( $all_buttons[ $button_id ], 'Share_Custom' ) ) {
			// Replace options for existing custom button
			$options         = $updated_service->get_options();
			$name            = isset( $button['name'] ) ? $button['name'] : $options['name'];
			$url             = isset( $button['URL'] ) ? $button['URL'] : $options['url'];
			$icon            = isset( $button['icon'] ) ? $button['icon'] : $options['icon'];
			$updated_service = new Share_Custom(
				$service_id,
				array(
					'name' => $name,
					'url'  => $url,
					'icon' => $icon,
				)
			);
			$this->sharing_service->set_service( $button_id, $updated_service );
		}

		// Default visibility to 'visible' if enabled
		if ( empty( $button['visibility'] ) && true === $button['enabled'] ) {
			$button['visibility'] = 'visible';
		} elseif ( false === $button['enabled'] ) {
			unset( $button['visibility'] );
		}

		// Update button visibility and enabled status
		$visibility_changed = ( isset( $button['visibility'] ) || true === $button['enabled'] ) && ! array_key_exists( $service_id, $blog_services[ $button['visibility'] ] );
		$is_disabling       = false === $button['enabled'];
		if ( $visibility_changed || $is_disabling ) {
			// Remove from all other visibilities
			foreach ( $blog_services as $service_visibility => $services ) {
				if ( $is_disabling || $service_visibility !== $button['visibility'] ) {
					unset( $blog_services[ $service_visibility ][ $service_id ] );
				}
			}

			if ( $visibility_changed ) {
				$blog_services[ $button['visibility'] ][ $service_id ] = $updated_service;
			}

			$this->sharing_service->set_blog_services( array_keys( $blog_services['visible'] ), array_keys( $blog_services['hidden'] ) );
		}

		return $updated_service;
	}

}

new WPCOM_JSON_API_Get_Sharing_Buttons_Endpoint(
	array(
		'description'          => 'Get a list of a site\'s sharing buttons.',
		'group'                => 'sharing',
		'stat'                 => 'sharing-buttons',
		'method'               => 'GET',
		'path'                 => '/sites/%s/sharing-buttons/',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
		),
		'query_parameters'     => array(
			'enabled_only' => '(bool) If true, only enabled sharing buttons are included in the response',
			'visibility'   => '(string) The type of enabled sharing buttons to filter by, either "visible" or "hidden"',
		),
		'response_format'      => array(
			'found'           => '(int) The total number of sharing buttons found that match the request.',
			'sharing_buttons' => '(array:object) Array of sharing button objects',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/30434183/sharing-buttons/',
		'example_request_data' => array(
			'headers' => array( 'authorization' => 'Bearer YOUR_API_TOKEN' ),
		),
		'example_response'     => '
{
    "found": 2,
    "sharing_buttons": [
        {
            "ID": "twitter",
            "name": "Twitter",
            "shortname": "twitter",
            "custom": false,
            "enabled": true,
            "visibility": "visible",
            "genericon": "\\f202"
        },
        {
            "ID": "facebook",
            "name": "Facebook",
            "shortname": "facebook",
            "custom": false,
            "enabled": true,
            "visibility": "visible",
            "genericon": "\\f203"
        }
    ]
}',
	)
);

/**
 * Get sharing buttons endpoint class.
 *
 * GET /sites/%s/sharing-buttons -> $blog_id
 */
class WPCOM_JSON_API_Get_Sharing_Buttons_Endpoint extends WPCOM_JSON_API_Sharing_Button_Endpoint {

	/**
	 * API Callback.
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 * @return array|WP_Error
	 */
	public function callback( $path = '', $blog_id = 0 ) {
		$args = $this->query_args();

		// Validate request
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		$continue = $this->setup();
		if ( is_wp_error( $continue ) ) {
			return $continue;
		}

		if ( ! empty( $args['visibility'] ) && ! in_array( $args['visibility'], self::$all_visibilities, true ) ) {
			return new WP_Error( 'invalid_visibility', sprintf( 'The visibility field must be one of the following values: %s', implode( ', ', self::$all_visibilities ) ), 400 );
		}

		// Determine which visibilities to include based on request
		$visibilities = empty( $args['visibility'] ) ? self::$all_visibilities : array( $args['visibility'] );

		// Discover enabled services
		$buttons          = array();
		$enabled_services = $this->sharing_service->get_blog_services();
		$all_services     = $this->sharing_service->get_all_services_blog();

		// Include buttons of desired visibility
		foreach ( $visibilities as $visibility ) {
			$buttons = array_merge( $buttons, $enabled_services[ $visibility ] );
		}

		// Unless `enabled_only` or `visibility` is specified, append the
		// remaining buttons to the end of the array
		if ( ( ! isset( $args['enabled_only'] ) || ! $args['enabled_only'] ) && empty( $args['visibility'] ) ) {
			foreach ( $all_services as $id => $button ) {
				if ( ! array_key_exists( $id, $buttons ) ) {
					$buttons[ $id ] = $button;
				}
			}
		}

		// Format each button in the response
		$response = array();
		foreach ( $buttons as $button ) {
			$response[] = $this->format_sharing_button( $button );
		}

		return array(
			'found'           => count( $response ),
			'sharing_buttons' => $response,
		);
	}
}

new WPCOM_JSON_API_Get_Sharing_Button_Endpoint(
	array(
		'description'          => 'Get information about a single sharing button.',
		'group'                => '__do_not_document',
		'stat'                 => 'sharing-buttons:1',
		'method'               => 'GET',
		'path'                 => '/sites/%s/sharing-buttons/%s',
		'path_labels'          => array(
			'$site'      => '(int|string) Site ID or domain',
			'$button_id' => '(string) The button ID',
		),
		'response_format'      => array(
			'ID'         => '(int) Sharing button ID',
			'name'       => '(string) Sharing button name, used as a label on the button itself',
			'shortname'  => '(string) A generated short name for the sharing button',
			'URL'        => '(string) The URL pattern defined for a custom sharing button',
			'icon'       => '(string) URL to the 16x16 icon defined for a custom sharing button',
			'genericon'  => '(string) Icon character in Genericons icon set',
			'custom'     => '(bool) Is the button a user-created custom sharing button?',
			'enabled'    => '(bool) Is the button currently enabled for the site?',
			'visibility' => '(string) If enabled, the current visibility of the sharing button, either "visible" or "hidden"',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/30434183/sharing-buttons/facebook',
		'example_request_data' => array(
			'headers' => array( 'authorization' => 'Bearer YOUR_API_TOKEN' ),
		),
		'example_response'     => '{
	"ID": "facebook",
	"name": "Facebook",
	"shortname": "facebook",
	"custom": false,
	"enabled": true,
	"visibility": "visible",
	"genericon": "\\f203"
}',
	)
);

/**
 * Get sharing button endpoint class.
 *
 * GET /sites/%s/sharing-buttons/%s -> $blog_id, $button_id
 */
class WPCOM_JSON_API_Get_Sharing_Button_Endpoint extends WPCOM_JSON_API_Sharing_Button_Endpoint {

	/**
	 * API Callback.
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 * @param int    $button_id - the button id.
	 * @return array|WP_Error
	 */
	public function callback( $path = '', $blog_id = 0, $button_id = 0 ) {
		// Validate request
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		$continue = $this->setup();
		if ( is_wp_error( $continue ) ) {
			return $continue;
		}

		// Search existing services for button
		$all_buttons = $this->sharing_service->get_all_services_blog();
		if ( ! array_key_exists( $button_id, $all_buttons ) ) {
			return new WP_Error( 'not_found', 'The specified sharing button was not found', 404 );
		} else {
			return $this->format_sharing_button( $all_buttons[ $button_id ] );
		}
	}

}

new WPCOM_JSON_API_Update_Sharing_Buttons_Endpoint(
	array(
		'description'          => 'Edit all sharing buttons for a site.',
		'group'                => 'sharing',
		'stat'                 => 'sharing-buttons:X:POST',
		'method'               => 'POST',
		'path'                 => '/sites/%s/sharing-buttons',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
		),
		'request_format'       => array(
			'sharing_buttons' => '(array:sharing_button) An array of sharing button objects',
		),
		'response_format'      => array(
			'success' => '(bool) Confirmation that all sharing buttons were updated as specified',
			'updated' => '(array) An array of updated sharing buttons',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/30434183/sharing-buttons',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'sharing_buttons' => array(
					array(
						'ID'         => 'facebook',
						'visibility' => 'hidden',
					),
				),
			),
		),
		'example_response'     => '{
	"success": true,
	"updated": [
		{
			"ID": "facebook",
			"name": "Facebook",
			"shortname": "facebook",
			"custom": false,
			"enabled": true,
			"visibility": "hidden",
			"genericon": "\\f204"
		}
	]
}',
	)
);

/**
 * Update sharing buttons endpoint.
 *
 * POST /sites/%s/sharing-buttons -> $blog_id
 */
class WPCOM_JSON_API_Update_Sharing_Buttons_Endpoint extends WPCOM_JSON_API_Sharing_Button_Endpoint {

	/**
	 * API Callback.
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 *
	 * @return array|WP_Error
	 */
	public function callback( $path = '', $blog_id = 0 ) {
		$input = $this->input();

		// Validate request
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		$continue = $this->setup();
		if ( is_wp_error( $continue ) ) {
			return $continue;
		}

		$all_buttons = $this->sharing_service->get_all_services_blog();

		if ( ! isset( $input['sharing_buttons'] ) ) {
			$input['sharing_buttons'] = array();
		}

		// We do a first pass of all buttons to verify that no validation
		// issues exist before continuing to update
		foreach ( $input['sharing_buttons'] as $button ) {
			$button_exists = isset( $button['ID'] ) && array_key_exists( $button['ID'], $all_buttons );
			$is_custom     = $this->is_button_input_for_custom( $button );

			// If neither custom nor existing, bail
			if ( ! $button_exists && ! $is_custom ) {
				return new WP_Error( 'not_found', 'The specified sharing button was not found', 404 );
			}

			// Validate input, only testing custom values if the button doesn't
			// already exist
			$validation_error = $this->validate_button_input( $button, ! $button_exists );
			if ( is_wp_error( $validation_error ) ) {
				return $validation_error;
			}
		}

		// Reset all existing buttons
		$this->sharing_service->set_blog_services( array(), array() );

		// Finally, we iterate over each button and update or create
		$success = true;
		$updated = array();
		foreach ( $input['sharing_buttons'] as $button ) {
			$button_exists = isset( $button['ID'] ) && array_key_exists( $button['ID'], $all_buttons );
			if ( $button_exists ) {
				$updated_service = $this->update_button( $button['ID'], $button );
			} else {
				$updated_service = $this->create_custom_button( $button );
			}

			// We'll allow the request to continue if a failure occurred, but
			// log it for the response
			if ( false === $updated_service ) {
				$success = false;
			} else {
				$updated[] = $this->format_sharing_button( $updated_service );
			}
		}

		return array(
			'success' => $success,
			'updated' => $updated,
		);
	}

}

new WPCOM_JSON_API_Update_Sharing_Button_Endpoint(
	array(
		'description'          => 'Create a new custom sharing button.',
		'group'                => '__do_not_document',
		'stat'                 => 'sharing-buttons:new',
		'method'               => 'POST',
		'path'                 => '/sites/%s/sharing-buttons/new',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
		),
		'request_format'       => array(
			'name'       => '(string) The name for your custom sharing button, used as a label on the button itself',
			'URL'        => '(string) The URL to use for share links, including optional placeholders (%post_id%, %post_title%, %post_slug%, %post_url%, %post_full_url%, %post_excerpt%, %post_tags%, %home_url%)',
			'icon'       => '(string) The full URL to a 16x16 icon to display on the sharing button',
			'enabled'    => '(bool) Is the button currently enabled for the site?',
			'visibility' => '(string) If enabled, the visibility of the sharing button, either "visible" (default) or "hidden"',
		),
		'response_format'      => array(
			'ID'         => '(string) Sharing button ID',
			'name'       => '(string) Sharing button name, used as a label on the button itself',
			'shortname'  => '(string) A generated short name for the sharing button',
			'URL'        => '(string) The URL pattern defined for a custom sharing button',
			'icon'       => '(string) URL to the 16x16 icon defined for a custom sharing button',
			'genericon'  => '(string) Icon character in Genericons icon set',
			'custom'     => '(bool) Is the button a user-created custom sharing button?',
			'enabled'    => '(bool) Is the button currently enabled for the site?',
			'visibility' => '(string) If enabled, the current visibility of the sharing button, either "visible" or "hidden"',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/30434183/sharing-buttons/new/',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'name'       => 'Custom',
				'URL'        => 'https://www.wordpress.com/%post_name%',
				'icon'       => 'https://en.wordpress.com/i/stats-icon.gif',
				'enabled'    => true,
				'visibility' => 'visible',
			),
		),
		'example_response'     => '{
	"ID": "custom-123456789",
	"name": "Custom",
	"shortname": "custom",
	"url": "https://www.wordpress.com/%post_name%",
	"icon": "https://en.wordpress.com/i/stats-icon.gif",
	"custom": true,
	"enabled": true,
	"visibility": "visible"
}',
	)
);

new WPCOM_JSON_API_Update_Sharing_Button_Endpoint(
	array(
		'description'          => 'Edit a sharing button.',
		'group'                => '__do_not_document',
		'stat'                 => 'sharing-buttons:1:POST',
		'method'               => 'POST',
		'path'                 => '/sites/%s/sharing-buttons/%s',
		'path_labels'          => array(
			'$site'      => '(int|string) Site ID or domain',
			'$button_id' => '(string) The button ID',
		),
		'request_format'       => array(
			'name'       => '(string) Only if a custom sharing button, a new name used as a label on the button itself',
			'URL'        => '(string) Only if a custom sharing button, the URL to use for share links, including optional placeholders (%post_title%, %post_url%, %post_full_url%, %post_excerpt%, %post_tags%)',
			'icon'       => '(string) Only if a custom sharing button, the full URL to a 16x16 icon to display on the sharing button',
			'enabled'    => '(bool) Is the button currently enabled for the site?',
			'visibility' => '(string) If enabled, the visibility of the sharing button, either "visible" (default) or "hidden"',
		),
		'response_format'      => array(
			'ID'         => '(string) Sharing button ID',
			'name'       => '(string) Sharing button name, used as a label on the button itself',
			'shortname'  => '(string) A generated short name for the sharing button',
			'URL'        => '(string) The URL pattern defined for a custom sharing button',
			'icon'       => '(string) URL to the 16x16 icon defined for a custom sharing button',
			'genericon'  => '(string) Icon character in Genericons icon set',
			'custom'     => '(bool) Is the button a user-created custom sharing button?',
			'enabled'    => '(bool) Is the button currently enabled for the site?',
			'visibility' => '(string) If enabled, the current visibility of the sharing button, either "visible" or "hidden"',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/30434183/sharing-buttons/custom-123456789/',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'enabled' => false,
			),
		),
		'example_response'     => '{
	"ID": "custom-123456789",
	"name": "Custom",
	"shortname": "custom",
	"custom": true,
	"enabled": false,
	"icon": "https://en.wordpress.com/i/stats-icon.gif",
	"url": "https://www.wordpress.com/%post_name%"
}',
	)
);

/**
 * Sharing button endpoint class.
 *
 * POST /sites/%s/sharing-buttons/new -> $blog_id
 * POST /sites/%s/sharing-buttons/%s -> $blog_id, $button_id
 */
class WPCOM_JSON_API_Update_Sharing_Button_Endpoint extends WPCOM_JSON_API_Sharing_Button_Endpoint {

	/**
	 * API Callback.
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 * @param int    $button_id - the button ID.
	 *
	 * @return array|WP_Error
	 */
	public function callback( $path = '', $blog_id = 0, $button_id = 0 ) {
		$new   = $this->api->ends_with( $path, '/new' );
		$input = $this->input();

		// Validate request
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		$continue = $this->setup();
		if ( is_wp_error( $continue ) ) {
			return $continue;
		}

		$validation_error = $this->validate_button_input( $input, $new );
		if ( is_wp_error( $validation_error ) ) {
			return $validation_error;
		}

		// Update or create button
		if ( $new ) {
			$updated_service = $this->create_custom_button( $input );
		} else {
			$updated_service = $this->update_button( $button_id, $input );
		}

		if ( false === $updated_service ) {
			return new WP_Error( 'invalid_request', sprintf( 'The sharing button was not %s', $new ? 'created' : 'updated' ), 400 );
		} elseif ( is_wp_error( $updated_service ) ) {
			return $updated_service;
		} else {
			return $this->format_sharing_button( $updated_service );
		}
	}

}

new WPCOM_JSON_API_Delete_Sharing_Button_Endpoint(
	array(
		'description'          => 'Delete a custom sharing button.',
		'group'                => '__do_not_document',
		'stat'                 => 'sharing-buttons:1:delete',
		'method'               => 'POST',
		'path'                 => '/sites/%s/sharing-buttons/%s/delete',
		'path_labels'          => array(
			'$site'      => '(int|string) Site ID or domain',
			'$button_id' => '(string) The button ID',
		),
		'response_format'      => array(
			'ID'      => '(int) The ID of the deleted sharing button',
			'success' => '(bool) Confirmation that the sharing button has been removed',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/30434183/sharing-buttons/custom-123456789/delete',
		'example_request_data' => array(
			'headers' => array( 'authorization' => 'Bearer YOUR_API_TOKEN' ),
		),
		'example_response'     => '{
	"ID": "custom-123456789",
	"success": "true"
}',
	)
);

/**
 * Delete sharing button endpoint class.
 *
 * POST /sites/%s/sharing-buttons/%s/delete -> $blog_id, $button_id
 */
class WPCOM_JSON_API_Delete_Sharing_Button_Endpoint extends WPCOM_JSON_API_Sharing_Button_Endpoint {
	/**
	 * API Callback.
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 * @param int    $button_id - the button ID.
	 *
	 * @return array|WP_Error
	 */
	public function callback( $path = '', $blog_id = 0, $button_id = 0 ) {
		// Validate request
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		$continue = $this->setup();
		if ( is_wp_error( $continue ) ) {
			return $continue;
		}

		// Find existing button
		$all_buttons = $this->sharing_service->get_all_services_blog();
		if ( ! array_key_exists( $button_id, $all_buttons ) ) {
			// Button doesn't exist
			return new WP_Error( 'not_found', 'The specified sharing button was not found', 404 );
		}

		// Verify button is custom
		if ( ! is_a( $all_buttons[ $button_id ], 'Share_Custom' ) ) {
			return new WP_Error( 'invalid_request', 'Only custom sharing buttons can be deleted', 400 );
		}

		$success = $this->sharing_service->delete_service( $button_id );
		return array(
			'ID'      => $button_id,
			'success' => $success,
		);
	}

}
