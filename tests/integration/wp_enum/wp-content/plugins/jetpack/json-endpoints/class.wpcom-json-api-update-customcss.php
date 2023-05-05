<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Custom CSS update endpoint.
 *
 * Endpoint: /sites/%s/customcss
 */

new WPCOM_JSON_API_Update_CustomCss_Endpoint(
	array(
		'description'          => 'Set custom-css data for a site.',
		'group'                => '__do_not_document',
		'stat'                 => 'customcss:1:update',
		'method'               => 'POST',
		'min_version'          => '1.1',
		'path'                 => '/sites/%s/customcss',
		'path_labels'          => array(
			'$site' => '(string) Site ID or domain.',
		),
		'request_format'       => array(
			'css'             => '(string) Optional. The raw CSS.',
			'preprocessor'    => '(string) Optional. The name of the preprocessor if any.',
			'add_to_existing' => '(bool) Optional. False to skip the existing styles.',
		),
		'response_format'      => array(
			'css'             => '(string) The raw CSS.',
			'preprocessor'    => '(string) The name of the preprocessor if any.',
			'add_to_existing' => '(bool) False to skip the existing styles.',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1.1/sites/12345678/customcss',
		'example_request_data' => array(
			'headers' => array( 'authorization' => 'Bearer YOUR_API_TOKEN' ),
			'body'    => array(
				'css'          => '.stie-title { color: #fff; }',
				'preprocessor' => 'sass',
			),
		),
		'example_response'     => '
	{
		"css": ".site-title { color: #fff; }",
		"preprocessor": "sass",
		"add_to_existing": "true"
	}',
	)
);

/**
 * Custom CSS update endpoint class.
 */
class WPCOM_JSON_API_Update_CustomCss_Endpoint extends WPCOM_JSON_API_Endpoint {
	/**
	 * Custom CSS update endpoint API callback.
	 *
	 * @param string $path API path.
	 * @param int    $blog_id Blog ID.
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
			return new WP_Error( 'unauthorized', 'User is not authorized to access custom css', 403 );
		}

		$args = $this->input();
		if ( empty( $args ) || ! is_array( $args ) ) {
			return new WP_Error( 'no_data', 'No data was provided.', 400 );
		}
		$save_args = array(
			'css'             => $args['css'],
			'preprocessor'    => $args['preprocessor'],
			'add_to_existing' => $args['add_to_existing'],
		);
		Jetpack_Custom_CSS::save( $save_args );

		$current = array(
			'css'             => Jetpack_Custom_CSS::get_css(),
			'preprocessor'    => Jetpack_Custom_CSS::get_preprocessor_key(),
			'add_to_existing' => ! Jetpack_Custom_CSS::skip_stylesheet(),
		);

		$defaults = array(
			'css'             => '',
			'preprocessor'    => '',
			'add_to_existing' => true,
		);
		return wp_parse_args( $current, $defaults );
	}
}


