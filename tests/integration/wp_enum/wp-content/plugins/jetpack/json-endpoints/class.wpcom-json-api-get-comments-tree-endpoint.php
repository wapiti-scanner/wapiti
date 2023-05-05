<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

new WPCOM_JSON_API_Get_Comments_Tree_Endpoint(
	array(
		'description'      => 'Get a comments tree for site.',
		'max_version'      => '1',
		'new_version'      => '1.1',
		'group'            => 'comments-tree',
		'stat'             => 'comments-tree:1',

		'method'           => 'GET',
		'path'             => '/sites/%s/comments-tree',
		'path_labels'      => array(
			'$site' => '(int|string) Site ID or domain',
		),
		'query_parameters' => array(
			'status' => '(string) Filter returned comments based on this value (allowed values: all, approved, unapproved, pending, trash, spam).',
		),
		'response_format'  => array(
			'comments_count'   => '(int) Total number of comments on the site',
			'comments_tree'    => '(array) Array of arrays representing the comments tree for given site (max 50000)',
			'trackbacks_count' => '(int) Total number of trackbacks on the site',
			'trackbacks_tree'  => '(array) Array of arrays representing the trackbacks tree for given site (max 50000)',
			'pingbacks_count'  => '(int) Total number of pingbacks on the site',
			'pingbacks_tree'   => '(array) Array of arrays representing the pingbacks tree for given site (max 50000)',
		),

		'example_request'  => 'https://public-api.wordpress.com/rest/v1/sites/en.blog.wordpress.com/comments-tree?status=approved',
	)
);
/**
 * GET comments tree endpoint class.
 */
class WPCOM_JSON_API_Get_Comments_Tree_Endpoint extends WPCOM_JSON_API_Endpoint {
	/**
	 * Retrieves a list of comment data for a given site.
	 *
	 * @param string $status Filter by status: all, approved, pending, spam or trash.
	 * @param int    $start_at first comment to search from going back in time.
	 *
	 * @return array
	 */
	public function get_site_tree( $status, $start_at = PHP_INT_MAX ) {
		global $wpdb;
		$max_comment_count = 50000;
		$db_status         = $this->get_comment_db_status( $status );

		$db_comment_rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT comment_ID, comment_post_ID, comment_parent, comment_type ' .
				"FROM $wpdb->comments AS comments " .
				"INNER JOIN $wpdb->posts AS posts ON comments.comment_post_ID = posts.ID " .
				"WHERE comment_ID <= %d AND ( %s = 'all' OR comment_approved = %s ) " .
				'ORDER BY comment_ID DESC ' .
				'LIMIT %d',
				(int) $start_at,
				$db_status,
				$db_status,
				$max_comment_count
			),
			ARRAY_N
		);

		$comments   = array();
		$trackbacks = array();
		$pingbacks  = array();
		foreach ( $db_comment_rows as $row ) {
			list( $comment_id, $comment_post_id, $comment_parent, $comment_type ) = $row;
			switch ( $comment_type ) {
				case 'trackback':
					$trackbacks[] = array( $comment_id, $comment_post_id, $comment_parent );
					break;
				case 'pingback':
					$pingbacks[] = array( $comment_id, $comment_post_id, $comment_parent );
					break;
				default:
					$comments[] = array( $comment_id, $comment_post_id, $comment_parent );
			}
		}

		return array(
			'comments_count'   => $this->get_site_tree_total_count( $status, 'comment' ),
			'comments_tree'    => array_map( array( $this, 'array_map_all_as_ints' ), $comments ),
			'trackbacks_count' => $this->get_site_tree_total_count( $status, 'trackback' ),
			'trackbacks_tree'  => array_map( array( $this, 'array_map_all_as_ints' ), $trackbacks ),
			'pingbacks_count'  => $this->get_site_tree_total_count( $status, 'pingback' ),
			'pingbacks_tree'   => array_map( array( $this, 'array_map_all_as_ints' ), $pingbacks ),
		);
	}

	/**
	 * Ensure all values are integers.
	 *
	 * @param array $comments Collection of comments.
	 *
	 * @return array Comments with values as integers.
	 */
	public function array_map_all_as_ints( $comments ) {
		return array_map( 'intval', $comments );
	}

	/**
	 * Retrieves a total count of comments by type for the given site.
	 *
	 * @param string $status Filter by status: all, approved, pending, spam or trash.
	 * @param string $type Comment type: 'trackback', 'pingback', or 'comment'.
	 *
	 * @return int Total count of comments for a site.
	 */
	public function get_site_tree_total_count( $status, $type ) {
		global $wpdb;

		$db_status = $this->get_comment_db_status( $status );
		$type      = $this->get_sanitized_comment_type( $type );

		$result = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(1) ' .
				"FROM $wpdb->comments AS comments " .
				"INNER JOIN $wpdb->posts AS posts ON comments.comment_post_ID = posts.ID " .
				"WHERE comment_type = %s AND ( %s = 'all' OR comment_approved = %s )",
				$type,
				$db_status,
				$db_status
			)
		);
		return (int) $result;
	}

	/**
	 * Ensure a valid status is converted to a database-supported value if necessary.
	 *
	 * @param string $status Should be one of: all, approved, pending, spam or trash.
	 *
	 * @return string Corresponding value that exists in database.
	 */
	public function get_comment_db_status( $status ) {
		if ( 'approved' === $status ) {
			return '1';
		}
		if ( 'pending' === $status || 'unapproved' === $status ) {
			return '0';
		}
		return $status;
	}

	/**
	 * Determine if the passed comment status is valid or not.
	 *
	 * @param string $status - comment status.
	 *
	 * @return boolean
	 */
	public function validate_status_param( $status ) {
		return in_array( $status, array( 'all', 'approved', 'unapproved', 'pending', 'spam', 'trash' ), true );
	}

	/**
	 * Sanitize a given comment type.
	 *
	 * @param string $type Comment type: can be 'trackback', 'pingback', or 'comment'.
	 *
	 * @return string Sanitized comment type.
	 */
	public function get_sanitized_comment_type( $type = 'comment' ) {
		if ( in_array( $type, array( 'trackback', 'pingback', 'comment' ), true ) ) {
			return $type;
		}
		return 'comment';
	}

	/**
	 * Endpoint callback for /sites/%s/comments-tree
	 *
	 * @param string $path - the api path.
	 * @param int    $blog_id - the blog id.
	 *
	 * @return array Site tree results by status.
	 */
	public function callback( $path = '', $blog_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		$args           = $this->query_args();
		$comment_status = empty( $args['status'] ) ? 'all' : $args['status'];

		if ( ! $this->validate_status_param( $comment_status ) ) {
			return new WP_Error( 'invalid_status', "Invalid comment status value provided: '$comment_status'.", 400 );
		}

		return $this->get_site_tree( $comment_status );
	}
}
