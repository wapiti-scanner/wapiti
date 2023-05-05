<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Set site logo settings API.
 *
 * Endpoints:
 * Set site logo settings:    /sites/%s/logo
 * Delete site logo settings: /sites/%s/logo/delete
 */

new WPCOM_JSON_API_Update_Site_Logo_Endpoint(
	array(
		'description'          => 'Set site logo settings',
		'group'                => '__do_not_document',
		'stat'                 => 'sites:1:logo',
		'method'               => 'POST',
		'min_version'          => '1.1',
		'path'                 => '/sites/%s/logo',
		'path_labels'          => array(
			'$site' => '(string) Site ID or domain.',
		),
		'request_format'       => array(
			'id'  => '(int) The ID of the logo post',
			'url' => '(string) The URL of the logo post (deprecated)',
		),
		'response_format'      => array(
			'id'  => '(int) The ID of the logo post',
			'url' => '(string) The URL of the logo post',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1.1/sites/82974409/logo',
		'example_request_data' => array(
			'headers' => array( 'authorization' => 'Bearer YOUR_API_TOKEN' ),
			'body'    => array(
				'id' => 12345,
			),
		),
		'example_response'     => '
	{
		"id": 12345,
		"url": "https:\/\/s.w.org\/about\/images\/logos\/codeispoetry-rgb.png"
	}',
	)
);

new WPCOM_JSON_API_Update_Site_Logo_Endpoint(
	array(
		'description'          => 'Delete site logo settings',
		'group'                => '__do_not_document',
		'stat'                 => 'sites:1:logo:delete',
		'method'               => 'POST',
		'min_version'          => '1.1',
		'path'                 => '/sites/%s/logo/delete',
		'path_labels'          => array(
			'$site' => '(string) Site ID or domain.',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1.1/sites/82974409/logo/delete',
		'example_request_data' => array(
			'headers' => array( 'authorization' => 'Bearer YOUR_API_TOKEN' ),
		),
	)
);

/**
 * Set site logo settings API class.
 */
class WPCOM_JSON_API_Update_Site_Logo_Endpoint extends WPCOM_JSON_API_Endpoint {
	/**
	 * Set site logo settings API callback.
	 *
	 * @param string $path API path.
	 * @param int    $site_id Blog ID.
	 */
	public function callback( $path = '', $site_id = 0 ) {
		// Switch to the given blog.
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $site_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		if ( ! current_user_can( 'edit_theme_options' ) ) {
			return new WP_Error( 'unauthorized', 'User is not authorized to access logo settings', 403 );
		}

		if ( strpos( $path, '/delete' ) ) {
			delete_option( 'site_logo' );
			return array();
		}

		$args          = $this->input();
		$logo_settings = $this->get_current_settings();

		if ( empty( $args ) || ! is_array( $args ) ) {
			return $logo_settings;
		}

		if ( isset( $args['id'] ) ) {
			update_option( 'site_logo', (int) $args['id'] );
		}

		return $this->get_current_settings();
	}

	/**
	 * Get current logo settings.
	 */
	public function get_current_settings() {
		$logo_id = get_option( 'site_logo' );

		if ( ! $logo_id ) {
			return array();
		}

		return array(
			'id'  => $logo_id,
			'url' => wp_get_attachment_url( $logo_id ),
		);
	}
}

