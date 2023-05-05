<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

new WPCOM_JSON_API_Get_Comments_Tree_v1_2_Endpoint(
	array(
		'description'      => 'Get a comments tree for site.',
		'min_version'      => '1.2',
		'max_version'      => '1.2',
		'group'            => 'comments-tree',
		'stat'             => 'comments-tree:1',

		'method'           => 'GET',
		'path'             => '/sites/%s/comments-tree',
		'path_labels'      => array(
			'$site' => '(int|string) Site ID or domain',
		),
		'query_parameters' => array(
			'post_id' => '(int) Filter returned comments by a post.',
			'status'  => '(string) Filter returned comments based on this value (allowed values: all, approved, pending, trash, spam).',
		),
		'response_format'  => array(
			'comments_tree'   => '(array) Array of post IDs representing the comments tree for given site or post (max 50000)',
			'trackbacks_tree' => '(array) Array of post IDs representing the trackbacks tree for given site or post (max 50000)',
			'pingbacks_tree'  => '(array) Array of post IDs representing the pingbacks tree for given site or post (max 50000)',
		),

		'example_request'  => 'https://public-api.wordpress.com/rest/v1.2/sites/en.blog.wordpress.com/comments-tree?&status=approved&post_id=123',
	)
);

/**
 * Get comments tree v1_2 endpoint class.
 */
class WPCOM_JSON_API_Get_Comments_Tree_v1_2_Endpoint extends WPCOM_JSON_API_Get_Comments_Tree_v1_1_Endpoint { // phpcs:ignore
	/**
	 * Retrieves a list of comment data.
	 *
	 * @param array $args {
	 *     Optional. Arguments to control behavior. Default empty array.
	 *
	 *     @type int    $max_comment_count Maximum number of comments returned.
	 *     @type int    $post_id           Filter by post.
	 *     @type int    $start_at          First comment to search from going back in time.
	 *     @type string $status            Filter by status: all, approved, pending, spam or trash.
	 * }
	 *
	 * @return array
	 */
	public function get_site_tree_v1_2( $args = array() ) {
		global $wpdb;
		$defaults  = array(
			'max_comment_count' => 50000,
			'post_id'           => null,
			'start_at'          => PHP_INT_MAX,
			'status'            => 'all',
		);
		$args      = wp_parse_args( $args, $defaults );
		$db_status = $this->get_comment_db_status( $args['status'] );

		if ( ! empty( $args['post_id'] ) ) {
			$db_comment_rows = $wpdb->get_results(
				$wpdb->prepare(
					'SELECT comment_ID, comment_parent, comment_type ' .
					"FROM $wpdb->comments AS comments " .
					"WHERE comment_ID <= %d AND comment_post_ID = %d AND ( %s = 'all' OR comment_approved = %s ) " .
					'ORDER BY comment_ID DESC ' .
					'LIMIT %d',
					(int) $args['start_at'],
					(int) $args['post_id'],
					$db_status,
					$db_status,
					$args['max_comment_count']
				),
				ARRAY_N
			);
		} else {
			$db_comment_rows = $wpdb->get_results(
				$wpdb->prepare(
					'SELECT comment_ID, comment_parent, comment_type, comment_post_ID ' .
					"FROM $wpdb->comments AS comments " .
					"INNER JOIN $wpdb->posts AS posts ON comments.comment_post_ID = posts.ID " .
					"WHERE comment_ID <= %d AND ( %s = 'all' OR comment_approved = %s ) " .
					'ORDER BY comment_ID DESC ' .
					'LIMIT %d',
					(int) $args['start_at'],
					$db_status,
					$db_status,
					$args['max_comment_count']
				),
				ARRAY_N
			);
		}

		$comments   = array();
		$trackbacks = array();
		$pingbacks  = array();
		foreach ( $db_comment_rows as $row ) {
			$comment_id        = (int) $row[0];
			$comment_parent_id = (int) $row[1];
			$comment_post_id   = isset( $args['post_id'] ) ? (int) $args['post_id'] : (int) $row[3];

			if ( ! isset( $comments[ $comment_post_id ] ) ) {
				$comments[ $comment_post_id ] = array( array(), array() );
			}
			switch ( $row[2] ) {
				case 'trackback':
					$trackbacks[ $comment_post_id ][] = $comment_id;
					break;
				case 'pingback':
					$pingbacks[ $comment_post_id ][] = $comment_id;
					break;
				default:
					if ( 0 === $comment_parent_id ) {
						$comments[ $comment_post_id ][0][] = $comment_id;
					} else {
						$comments[ $comment_post_id ][1][] = array( $comment_id, $comment_parent_id );
					}
			}
		}

		return array(
			'comments_tree'   => $comments,
			'trackbacks_tree' => $trackbacks,
			'pingbacks_tree'  => $pingbacks,
		);
	}

	/**
	 * Endpoint callback for /sites/%s/comments-tree
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 *
	 * @return array Site or post tree results by status.
	 */
	public function callback( $path = '', $blog_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		$args    = $this->query_args();
		$filters = array();

		if ( ! empty( $args['status'] ) ) {
			if ( ! $this->validate_status_param( $args['status'] ) ) {
				return new WP_Error( 'invalid_status', 'Invalid comment status value provided: ' . $args['status'] . '.', 400 );
			}
			$filters['status'] = $args['status'];
		}

		if ( ! empty( $args['post_id'] ) ) {
			if ( get_post( absint( $args['post_id'] ) ) === null ) {
				return new WP_Error( 'invalid_post', 'Invalid post', 400 );
			}
			$filters['post_id'] = absint( $args['post_id'] );
		}

		return $this->get_site_tree_v1_2( $filters );
	}
}
