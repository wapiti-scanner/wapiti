<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Custom Css endpoint
 *
 * Endpoint: https://public-api.wordpress.com/rest/v1.1/sites/$site/customcss/
 */

new WPCOM_JSON_API_Get_CustomCss_Endpoint(
	array(
		'description'      => 'Retrieve custom-css data for a site.',
		'group'            => '__do_not_document',
		'stat'             => 'customcss:1:get',
		'method'           => 'GET',
		'min_version'      => '1.1',
		'path'             => '/sites/%s/customcss',
		'path_labels'      => array(
			'$site' => '(string) Site ID or domain.',
		),
		'response_format'  => array(
			'css'             => '(string) The raw CSS.',
			'preprocessor'    => '(string) The name of the preprocessor if any.',
			'add_to_existing' => '(bool) False to skip the existing styles.',
		),
		'example_request'  => 'https://public-api.wordpress.com/rest/v1.1/sites/12345678/customcss',
		'example_response' => '
	{
		"css": ".site-title { color: #fff; }",
		"preprocessor": "sass",
		"add_to_existing": "true"
	}',
	)
);
/**
 * GET Custom CSS Endpoint
 */
class WPCOM_JSON_API_Get_CustomCss_Endpoint extends WPCOM_JSON_API_Endpoint {
	/**
	 *
	 * API callback.
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 */
	public function callback( $path = '', $blog_id = 0 ) {
		// Switch to the given blog.
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		$args = array(
			'css'             => Jetpack_Custom_CSS::get_css(),
			'preprocessor'    => Jetpack_Custom_CSS::get_preprocessor_key(),
			'add_to_existing' => ! Jetpack_Custom_CSS::skip_stylesheet(),
		);

		$defaults = array(
			'css'             => '',
			'preprocessor'    => '',
			'add_to_existing' => true,
		);
		return wp_parse_args( $args, $defaults );
	}
}


