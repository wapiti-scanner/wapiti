<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Activate a widget on a site.
 *
 * Endpoint: https://public-api.wordpress.com/rest/v1.1/sites/$site/widgets/new
 */

new WPCOM_JSON_API_Add_Widgets_Endpoint(
	array(
		'description'          => 'Activate a group of widgets on a site. The bulk version of using the /new endpoint',
		'group'                => '__do_not_document',
		'stat'                 => 'widgets:new:bulk',
		'force'                => 'wpcom',
		'method'               => 'POST',
		'min_version'          => '1.1',
		'path'                 => '/sites/%s/widgets',
		'path_labels'          => array(
			'$site' => '(string) Site ID or domain.',
		),
		'request_format'       => array(
			'widgets' => '(array:widget) An array of widget objects to add.',
		),
		'response_format'      => array(
			'widgets' => '(array:widget) An array of widget objects added.',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1.1/sites/12345678/widgets',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'id_base'  => 'text',
				'sidebar'  => 'sidebar-2',
				'position' => '0',
				'settings' => array( 'title' => 'hello world' ),
			),
		),
		'example_response'     => '
	{
		"id": "text-3",
		"id_base": "text",
		"settings": {
			"title": "hello world"
		},
		"sidebar": "sidebar-2",
		"position": 0
	}',
	)
);

new WPCOM_JSON_API_Add_Widgets_Endpoint(
	array(
		'description'          => 'Activate a widget on a site.',
		'group'                => 'sites',
		'stat'                 => 'widgets:new',
		'method'               => 'POST',
		'min_version'          => '1.1',
		'path'                 => '/sites/%s/widgets/new',
		'path_labels'          => array(
			'$site' => '(string) Site ID or domain.',
		),
		'request_format'       => array(
			'id_base'  => '(string) The base ID of the widget.',
			'sidebar'  => '(string) Optional. The ID of the sidebar where this widget will be active. If empty, the widget will be added in the first sidebar available.',
			'position' => '(int) Optional. The position of the widget in the sidebar.',
			'settings' => '(object) Optional. The settings for the new widget.',
		),
		'response_format'      => array(
			'id'       => '(string) The actual ID of the widget.',
			'sidebar'  => '(string) The ID of the sidebar where this widget will be active.',
			'position' => '(int) The final position of the widget in the sidebar.',
			'settings' => '(array) The settings for the new widget.',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1.1/sites/12345678/widgets/new',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'id_base'  => 'text',
				'sidebar'  => 'sidebar-2',
				'position' => '0',
				'settings' => array( 'title' => 'hello world' ),
			),
		),
		'example_response'     => '
	{
		"id": "text-3",
		"id_base": "text",
		"settings": {
			"title": "hello world"
		},
		"sidebar": "sidebar-2",
		"position": 0
	}',
	)
);

/**
 * The Add Widgets endpoint class.
 */
class WPCOM_JSON_API_Add_Widgets_Endpoint extends WPCOM_JSON_API_Endpoint {
	/**
	 * API callback.
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 * @uses Jetpack_Widgets
	 *
	 * @return array|WP_Error
	 */
	public function callback( $path = '', $blog_id = 0 ) {
		// Switch to the given blog.
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		if ( ! current_user_can( 'edit_theme_options' ) ) {
			return new WP_Error( 'unauthorized', 'User is not authorized to access widgets', 403 );
		}

		require_once JETPACK__PLUGIN_DIR . '_inc/lib/widgets.php';
		$args = $this->input( false, false ); // Don't filter the input.
		if ( empty( $args ) || ! is_array( $args ) ) {
			return new WP_Error( 'no_data', 'No data was provided.', 400 );
		}
		if ( isset( $args['widgets'] ) || ! empty( $args['widgets'] ) ) {
			$widgets = Jetpack_Widgets::activate_widgets( $args['widgets'] );
			if ( is_wp_error( $widgets ) ) {
				return $widgets;
			}
			return array( 'widgets' => $widgets );
		}
		if ( ! isset( $args['id_base'] ) ) {
			return new WP_Error( 'missing_data', 'The data you provided was not accurate.', 400 );
		}

		if ( empty( $args['sidebar'] ) ) {
			$active_sidebars = Jetpack_Widgets::get_active_sidebars();
			reset( $active_sidebars );
			$args['sidebar'] = key( $active_sidebars );
		}

		return Jetpack_Widgets::activate_widget( $args['id_base'], $args['sidebar'], $args['position'], $args['settings'] );
	}

}

