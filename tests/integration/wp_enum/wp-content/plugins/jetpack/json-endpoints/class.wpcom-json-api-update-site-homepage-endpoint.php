<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Set site homepage settings API endpoint.
 *
 * Endpoint: /sites/%s/homepage
 */

new WPCOM_JSON_API_Update_Site_Homepage_Endpoint(
	array(
		'description'          => 'Set site homepage settings',
		'group'                => '__do_not_document',
		'stat'                 => 'sites:1:homepage',
		'method'               => 'POST',
		'min_version'          => '1.1',
		'path'                 => '/sites/%s/homepage',
		'path_labels'          => array(
			'$site' => '(string) Site ID or domain.',
		),
		'request_format'       => array(
			'is_page_on_front'  => '(bool) True if we will use a page as the homepage; false to use a blog page as the homepage.',
			'page_on_front_id'  => '(int) Optional. The ID of the page to use as the homepage if is_page_on_front is true.',
			'page_for_posts_id' => '(int) Optional. The ID of the page to use as the blog page if is_page_on_front is true.',
		),
		'response_format'      => array(
			'is_page_on_front'  => '(bool) True if we will use a page as the homepage; false to use a blog page as the homepage.',
			'page_on_front_id'  => '(int) The ID of the page to use as the homepage if is_page_on_front is true.',
			'page_for_posts_id' => '(int) The ID of the page to use as the blog page if is_page_on_front is true.',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1.1/sites/82974409/homepage',
		'example_request_data' => array(
			'headers' => array( 'authorization' => 'Bearer YOUR_API_TOKEN' ),
			'body'    => array(
				'is_page_on_front'  => true,
				'page_on_front_id'  => 1,
				'page_for_posts_id' => 0,
			),
		),
		'example_response'     => '{"is_page_on_front":true,"page_on_front_id":1,"page_for_posts_id":0}',
	)
);

/**
 * Site homepage setting endpoint class.
 */
class WPCOM_JSON_API_Update_Site_Homepage_Endpoint extends WPCOM_JSON_API_Endpoint {
	/**
	 * Set site homepage setting API callback.
	 *
	 * @param string $path API path.
	 * @param int    $site_id Blog ID.
	 */
	public function callback( $path = '', $site_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $site_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		if ( ! current_user_can( 'edit_theme_options' ) ) {
			return new WP_Error( 'unauthorized', 'User is not authorized to access homepage settings', 403 );
		}

		$args = $this->input();
		if ( empty( $args ) || ! is_array( $args ) ) {
			return $this->get_current_settings();
		}

		if ( isset( $args['is_page_on_front'] ) ) {
			$show_on_front = $args['is_page_on_front'] ? 'page' : 'posts';
			update_option( 'show_on_front', $show_on_front );
		}
		if ( isset( $args['page_on_front_id'] ) ) {
			update_option( 'page_on_front', $args['page_on_front_id'] );
		}
		if ( isset( $args['page_for_posts_id'] ) ) {
			update_option( 'page_for_posts', $args['page_for_posts_id'] );
		}

		return $this->get_current_settings();
	}

	/**
	 * Get current site homepage settings.
	 *
	 * @return array
	 */
	public function get_current_settings() {
		$is_page_on_front  = ( get_option( 'show_on_front' ) === 'page' );
		$page_on_front_id  = get_option( 'page_on_front' );
		$page_for_posts_id = get_option( 'page_for_posts' );

		return array(
			'is_page_on_front'  => $is_page_on_front,
			'page_on_front_id'  => $page_on_front_id,
			'page_for_posts_id' => $page_for_posts_id,
		);
	}
}
