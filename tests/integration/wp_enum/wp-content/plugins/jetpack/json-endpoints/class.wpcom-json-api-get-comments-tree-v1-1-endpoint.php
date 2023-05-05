<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

new WPCOM_JSON_API_Get_Comments_Tree_v1_1_Endpoint(
	array(
		'description'      => 'Get a comments tree for site.',
		'min_version'      => '1.1',
		'max_version'      => '1.1',
		'group'            => 'comments-tree',
		'stat'             => 'comments-tree:1',

		'method'           => 'GET',
		'path'             => '/sites/%s/comments-tree',
		'path_labels'      => array(
			'$site' => '(int|string) Site ID or domain',
		),
		'query_parameters' => array(
			'status' => '(string) Filter returned comments based on this value (allowed values: all, approved, pending, trash, spam).',
		),
		'response_format'  => array(
			'comments_count'   => '(int) Total number of comments on the site',
			'comments_tree'    => '(array) Array of post IDs representing the comments tree for given site (max 50000)',
			'trackbacks_count' => '(int) Total number of trackbacks on the site',
			'trackbacks_tree'  => '(array) Array of post IDs representing the trackbacks tree for given site (max 50000)',
			'pingbacks_count'  => '(int) Total number of pingbacks on the site',
			'pingbacks_tree'   => '(array) Array of post IDs representing the pingbacks tree for given site (max 50000)',
		),

		'example_request'  => 'https://public-api.wordpress.com/rest/v1.1/sites/en.blog.wordpress.com/comments-tree?status=approved',
	)
);

/**
 * GET comments tree v1_1 endpoint.
 */
class WPCOM_JSON_API_Get_Comments_Tree_v1_1_Endpoint extends WPCOM_JSON_API_Get_Comments_Tree_Endpoint { // phpcs:ignore
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
			$comment_id        = (int) $row[0];
			$comment_post_id   = (int) $row[1];
			$comment_parent_id = (int) $row[2];
			if ( ! isset( $comments[ $comment_post_id ] ) ) {
				$comments[ $comment_post_id ] = array( array(), array() );
			}
			switch ( $row[3] ) {
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
			'comments_count'   => $this->get_site_tree_total_count( $status, 'comment' ),
			'comments_tree'    => $comments,
			'trackbacks_count' => $this->get_site_tree_total_count( $status, 'trackback' ),
			'trackbacks_tree'  => $trackbacks,
			'pingbacks_count'  => $this->get_site_tree_total_count( $status, 'pingback' ),
			'pingbacks_tree'   => $pingbacks,
		);
	}
}
