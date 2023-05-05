<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Endpoint: /sites/%s/posts/restore
 */
new WPCOM_JSON_API_Bulk_Restore_Post_Endpoint(
	array(
		'description'          => 'Restore multiple posts.',
		'group'                => 'posts',
		'stat'                 => 'posts:1:bulk-restore',
		'min_version'          => '1.1',
		'max_version'          => '1.1',
		'method'               => 'POST',
		'path'                 => '/sites/%s/posts/restore',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
		),
		'request_format'       => array(
			'post_ids' => '(array|string) An array, or comma-separated list, of Post IDs to restore.',
		),

		'response_format'      => array(
			'results' => '(object) An object containing results, ',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1.1/sites/82974409/posts/restore',

		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),

			'body'    => array(
				'post_ids' => array( 881, 882 ),
			),

		),
	)
);

/**
 * Bulk restore post endpoint class.
 */
class WPCOM_JSON_API_Bulk_Restore_Post_Endpoint extends WPCOM_JSON_API_Update_Post_v1_1_Endpoint {
	/**
	 *
	 * API callback.
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 * @param obj    $object - parameter is for making the method signature compatible with its parent class method.
	 */
	public function callback( $path = '', $blog_id = 0, $object = null ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		$input = $this->input();

		if ( is_array( $input['post_ids'] ) ) {
			$post_ids = (array) $input['post_ids'];
		} elseif ( ! empty( $input['post_ids'] ) ) {
			$post_ids = explode( ',', $input['post_ids'] );
		} else {
			$post_ids = array();
		}

		if ( count( $post_ids ) < 1 ) {
			return new WP_Error( 'empty_post_ids', 'The request must include post_ids' );
		}

		$result = array(
			'results' => array(),
		);

		foreach ( $post_ids as $post_id ) {
			$result['results'][ $post_id ] = $this->restore_post( $path, $blog_id, $post_id );
		}

		return $result;
	}
}
