<?php //phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Endpoints: /sites/%s/comments/status
 *            /sites/%s/comments/delete
 */
new WPCOM_JSON_API_Bulk_Update_Comments_Endpoint(
	array(
		'description'          => 'Update multiple comment\'s status.',
		'group'                => 'comments',
		'stat'                 => 'comments:1:bulk-update-status',
		'min_version'          => '1',
		'max_version'          => '1',
		'method'               => 'POST',
		'path'                 => '/sites/%s/comments/status',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
		),
		'request_format'       => array(
			'comment_ids' => '(array|string) An array, or comma-separated list, of Comment IDs to update.',
			'status'      => '(string) The new status value. Allowed values: approved, unapproved, spam, trash',
		),
		'response_format'      => array(
			'results' => '(array) An array of updated Comment IDs.',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/comments/status',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'comment_ids' => array( 881, 882 ),
				'status'      => 'approved',
			),
		),
	)
);

new WPCOM_JSON_API_Bulk_Update_Comments_Endpoint(
	array(
		'description'          => 'Permanently delete multiple comments. Note: this request will send non-trashed comments to the trash. Trashed comments will be permanently deleted.',
		'group'                => 'comments',
		'stat'                 => 'comments:1:bulk-delete',
		'min_version'          => '1',
		'max_version'          => '1',
		'method'               => 'POST',
		'path'                 => '/sites/%s/comments/delete',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
		),
		'request_format'       => array(
			'comment_ids'  => '(array|string) An array, or comma-separated list, of Comment IDs to delete or trash. (optional)',
			'empty_status' => '(string) Force to permanently delete all spam or trash comments. (optional). Allowed values: spam, trash',
		),
		'response_format'      => array(
			'results' => '(array) An array of deleted or trashed Comment IDs.',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/comments/delete',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'comment_ids' => array( 881, 882 ),
			),
		),
	)
);

/**
 * Bulk update comments endpoint class.
 */
class WPCOM_JSON_API_Bulk_Update_Comments_Endpoint extends WPCOM_JSON_API_Endpoint {
	/**
	 * API callback.
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 */
	public function callback( $path = '', $blog_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		$input = $this->input();

		if ( isset( $input['comment_ids'] ) && is_array( $input['comment_ids'] ) ) {
			$comment_ids = $input['comment_ids'];
		} elseif ( isset( $input['comment_ids'] ) && ! empty( $input['comment_ids'] ) ) {
			$comment_ids = explode( ',', $input['comment_ids'] );
		} else {
			$comment_ids = array();
		}

		$result = array(
			'results' => array(),
		);

		wp_defer_comment_counting( true );

		if ( $this->api->ends_with( $path, '/delete' ) ) {
			if ( isset( $input['empty_status'] ) && $this->validate_empty_status_param( $input['empty_status'] ) ) {
				$result['results'] = $this->delete_all( $input['empty_status'] );
			} else {
				$result['results'] = $this->bulk_delete_comments( $comment_ids );
			}
		} else {
			$status            = isset( $input['status'] ) ? $input['status'] : '';
			$result['results'] = $this->bulk_update_comments_status( $comment_ids, $status );
		}

		wp_defer_comment_counting( false );

		return $result;
	}

	/**
	 * Determine if the passed comment status is valid or not.
	 *
	 * @param string $status - status of passed comment.
	 *
	 * @return boolean
	 */
	public function validate_status_param( $status ) {
		return in_array( $status, array( 'approved', 'unapproved', 'pending', 'spam', 'trash' ), true );
	}

	/**
	 * Determine if the passed empty status is valid or not.
	 *
	 * @param string $empty_status - empty_status of comment.
	 *
	 * @return boolean
	 */
	public function validate_empty_status_param( $empty_status ) {
		return in_array( $empty_status, array( 'spam', 'trash' ), true );
	}

	/**
	 * Update the status of multiple comments.
	 *
	 * @param array  $comment_ids Comments to update.
	 * @param string $status New status value.
	 *
	 * @return array Updated comments IDs.
	 */
	public function bulk_update_comments_status( $comment_ids, $status ) {
		if ( count( $comment_ids ) < 1 ) {
			return new WP_Error( 'empty_comment_ids', 'The request must include comment_ids', 400 );
		}
		if ( ! $this->validate_status_param( $status ) ) {
			return new WP_Error( 'invalid_status', "Invalid comment status value provided: '$status'.", 400 );
		}
		$results = array();
		foreach ( $comment_ids as $comment_id ) {
			if ( ! current_user_can( 'edit_comment', $comment_id ) ) {
				continue;
			}
			$result = false;
			switch ( $status ) {
				case 'approved':
					$result = wp_set_comment_status( $comment_id, 'approve' );
					break;
				case 'unapproved':
				case 'pending':
					$result = wp_set_comment_status( $comment_id, 'hold' );
					break;
				case 'spam':
					$result = wp_spam_comment( $comment_id );
					break;
				case 'trash':
					$result = wp_trash_comment( $comment_id );
					break;
			}
			if ( $result ) {
				$results[] = $comment_id;
			}
		}
		return $results;
	}

	/**
	 * Permanenty delete multiple comments.
	 *
	 * Comments are only permanently deleted if trash is disabled or their status is `trash` or `spam`.
	 * Otherwise they are moved to trash.
	 *
	 * @param array $comment_ids Comments to trash or delete.
	 *
	 * @return array Deleted comments IDs.
	 */
	public function bulk_delete_comments( $comment_ids ) {
		if ( count( $comment_ids ) < 1 ) {
			return new WP_Error( 'empty_comment_ids', 'The request must include comment_ids', 400 );
		}
		$results = array();
		foreach ( $comment_ids as $comment_id ) {
			if ( ! current_user_can( 'edit_comment', $comment_id ) ) {
				continue;
			}
			if ( wp_delete_comment( $comment_id ) ) {
				$results[] = $comment_id;
			}
		}
		return $results;
	}

	/**
	 * Delete all spam or trash comments.
	 *
	 * Comments are only permanently deleted if trash is disabled or their status is `trash` or `spam`.
	 * Otherwise they are moved to trash.
	 *
	 * @param string $status Can be `spam` or `trash`.
	 *
	 * @return array Deleted comments IDs.
	 */
	public function delete_all( $status ) {
		global $wpdb;
		// This could potentially take a long time, so we only want to delete comments created
		// before this operation.
		// Comments marked `spam` or `trash` after this moment won't be touched.
		// Core uses the `pagegen_timestamp` hidden field for this same reason.
		$delete_time = gmdate( 'Y-m-d H:i:s' );
		$comment_ids = $wpdb->get_col( $wpdb->prepare( "SELECT comment_ID FROM $wpdb->comments WHERE comment_approved = %s AND %s > comment_date_gmt", $status, $delete_time ) );

		if ( count( $comment_ids ) < 1 ) {
			return array();
		}

		return $this->bulk_delete_comments( $comment_ids );
	}
}
