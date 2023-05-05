<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Comments Walker Class.
 */
class WPCOM_JSON_API_List_Comments_Walker extends Walker {

	/**
	 * Tree type.
	 *
	 * @var string
	 */
	public $tree_type = 'comment';

	/**
	 * Database fields.
	 *
	 * @var array
	 */
	public $db_fields = array(
		'parent' => 'comment_parent',
		'id'     => 'comment_ID',
	);

	/**
	 * Start the element output.
	 *
	 * @param array  $output - the output.
	 * @param object $object - the object.
	 * @param int    $depth - depth.
	 * @param array  $args - the arguments.
	 * @param int    $current_object_id - the object ID.
	 */
	public function start_el( &$output, $object, $depth = 0, $args = array(), $current_object_id = 0 ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		if ( ! is_array( $output ) ) {
			$output = array();
		}

		$output[] = $object->comment_ID;
	}

	/**
	 * Taken from WordPress's Walker_Comment::display_element()
	 *
	 * This function is designed to enhance Walker::display_element() to
	 * display children of higher nesting levels than selected inline on
	 * the highest depth level displayed. This prevents them being orphaned
	 * at the end of the comment list.
	 *
	 * Example: max_depth = 2, with 5 levels of nested content.
	 * 1
	 *  1.1
	 *    1.1.1
	 *    1.1.1.1
	 *    1.1.1.1.1
	 *    1.1.2
	 *    1.1.2.1
	 * 2
	 *  2.2
	 *
	 * @see Walker_Comment::display_element()
	 * @see Walker::display_element()
	 * @see wp_list_comments()
	 *
	 * @param object $element — Data object.
	 * @param array  $children_elements - List of elements to continue traversing (passed by reference).
	 * @param int    $max_depth — Max depth to traverse.
	 * @param int    $depth — Depth of current element.
	 * @param array  $args — An array of arguments.
	 * @param string $output — Used to append additional content (passed by reference).
	 */
	public function display_element( $element, &$children_elements, $max_depth, $depth, $args, &$output ) {

		if ( ! $element ) {
			return;
		}

		$id_field = $this->db_fields['id'];
		$id       = $element->$id_field;

		parent::display_element( $element, $children_elements, $max_depth, $depth, $args, $output );

		// If we're at the max depth, and the current element still has children, loop over those and display them at this level
		// This is to prevent them being orphaned to the end of the list.
		if ( $max_depth <= $depth + 1 && isset( $children_elements[ $id ] ) ) {
			foreach ( $children_elements[ $id ] as $child ) {
				$this->display_element( $child, $children_elements, $max_depth, $depth, $args, $output );
			}

			unset( $children_elements[ $id ] );
		}
	}
}

new WPCOM_JSON_API_List_Comments_Endpoint(
	array(
		'description'                          => 'Get a list of recent comments.',
		'group'                                => 'comments',
		'stat'                                 => 'comments',

		'method'                               => 'GET',
		'path'                                 => '/sites/%s/comments/',
		'path_labels'                          => array(
			'$site' => '(int|string) Site ID or domain',
		),

		'allow_fallback_to_jetpack_blog_token' => true,

		'example_request'                      => 'https://public-api.wordpress.com/rest/v1/sites/en.blog.wordpress.com/comments/?number=2',
	)
);

new WPCOM_JSON_API_List_Comments_Endpoint(
	array(
		'description'                          => 'Get a list of recent comments on a post.',
		'group'                                => 'comments',
		'stat'                                 => 'posts:1:replies',

		'method'                               => 'GET',
		'path'                                 => '/sites/%s/posts/%d/replies/',
		'path_labels'                          => array(
			'$site'    => '(int|string) Site ID or domain',
			'$post_ID' => '(int) The post ID',
		),

		'allow_fallback_to_jetpack_blog_token' => true,

		'example_request'                      => 'https://public-api.wordpress.com/rest/v1/sites/en.blog.wordpress.com/posts/7/replies/?number=2',
	)
);

/**
 * List comment endpoint.
 *
 * /sites/%s/comments/            -> $blog_id
 * /sites/%s/posts/%d/replies/    -> $blog_id, $post_id
 * /sites/%s/comments/%d/replies/ -> $blog_id, $comment_id
 *
 * @todo permissions
 */
class WPCOM_JSON_API_List_Comments_Endpoint extends WPCOM_JSON_API_Comment_Endpoint { // phpcs:ignore

	/**
	 * The response format.
	 *
	 * @var array
	 */
	public $response_format = array(
		'found'    => '(int) The total number of comments found that match the request (ignoring limits, offsets, and pagination).',
		'site_ID'  => '(int) The site ID',
		'comments' => '(array:comment) An array of comment objects.',
	);

	/**
	 * Constructor function.
	 *
	 * @param array $args - the arguments.
	 */
	public function __construct( $args ) {
		parent::__construct( $args );
		$this->query = array_merge(
			$this->query,
			array(
				'number'       => '(int=20) The number of comments to return.  Limit: 100. When using hierarchical=1, number refers to the number of top-level comments returned.',
				'offset'       => '(int=0) 0-indexed offset. Not available if using hierarchical=1.',
				'page'         => '(int) Return the Nth 1-indexed page of comments.  Takes precedence over the <code>offset</code> parameter. When using hierarchical=1, pagination is a bit different.  See the note on the number parameter.',
				'order'        => array(
					'DESC' => 'Return comments in descending order from newest to oldest.',
					'ASC'  => 'Return comments in ascending order from oldest to newest.',
				),
				'hierarchical' => array(
					'false' => '',
					'true'  => '(BETA) Order the comment list hierarchically.',
				),
				'after'        => '(ISO 8601 datetime) Return comments dated on or after the specified datetime. Not available if using hierarchical=1.',
				'before'       => '(ISO 8601 datetime) Return comments dated on or before the specified datetime. Not available if using hierarchical=1.',
				'type'         => array(
					'any'       => 'Return all comments regardless of type.',
					'comment'   => 'Return only regular comments.',
					'trackback' => 'Return only trackbacks.',
					'pingback'  => 'Return only pingbacks.',
					'pings'     => 'Return both trackbacks and pingbacks.',
				),
				'status'       => array(
					'approved'   => 'Return only approved comments.',
					'unapproved' => 'Return only comments in the moderation queue.',
					'spam'       => 'Return only comments marked as spam.',
					'trash'      => 'Return only comments in the trash.',
					'all'        => 'Return comments of all statuses.',
				),
			)
		);
	}

	/**
	 * The callback.
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 * @param int    $object_id - the object ID.
	 */
	public function callback( $path = '', $blog_id = 0, $object_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		$args = $this->query_args();

		if ( $args['number'] < 1 ) {
			$args['number'] = 20;
		} elseif ( 100 < $args['number'] ) {
			return new WP_Error( 'invalid_number', 'The NUMBER parameter must be less than or equal to 100.', 400 );
		}

		if ( false !== strpos( $path, '/posts/' ) ) {
			// We're looking for comments of a particular post.
			$post_id    = $object_id;
			$comment_id = 0;
		} else {
			// We're looking for comments for the whole blog, or replies to a single comment.
			$comment_id = $object_id;
			$post_id    = 0;
		}

		// We can't efficiently get the number of replies to a single comment.
		$count = false;
		$found = -1;

		if ( ! $comment_id ) {
			// We can get comment counts for the whole site or for a single post, but only for certain queries.
			if ( 'any' === $args['type'] && ! isset( $args['after'] ) && ! isset( $args['before'] ) ) {
				$count = $this->api->wp_count_comments( $post_id );
			}
		}

		switch ( $args['status'] ) {
			case 'approved':
				$status = 'approve';
				if ( $count ) {
					$found = $count->approved;
				}
				break;
			default:
				if ( ! current_user_can( 'edit_posts' ) ) {
					return new WP_Error( 'unauthorized', 'User cannot read non-approved comments', 403 );
				}
				if ( 'unapproved' === $args['status'] ) {
					$status       = 'hold';
					$count_status = 'moderated';
				} elseif ( 'all' === $args['status'] ) {
					$status       = 'all';
					$count_status = 'total_comments';
				} else {
					$status       = $args['status'];
					$count_status = $args['status'];
				}
				if ( $count ) {
					$found = $count->$count_status;
				}
		}

		/** This filter is documented in class.json-api.php */
		$exclude = apply_filters(
			'jetpack_api_exclude_comment_types',
			array( 'order_note', 'webhook_delivery', 'review', 'action_log' )
		);

		$query = array(
			'order'        => $args['order'],
			'type'         => 'any' === $args['type'] ? false : $args['type'],
			'status'       => $status,
			'type__not_in' => $exclude,
		);

		if ( isset( $args['page'] ) ) {
			if ( $args['page'] < 1 ) {
				$args['page'] = 1;
			}
		} elseif ( $args['offset'] < 0 ) {
			$args['offset'] = 0;
		}

		if ( ! $args['hierarchical'] ) {
			$query['number'] = $args['number'];

			if ( isset( $args['page'] ) ) {
				$query['offset'] = ( $args['page'] - 1 ) * $args['number'];
			} else {
				$query['offset'] = $args['offset'];
			}

			$is_before = isset( $args['before_gmt'] );
			$is_after  = isset( $args['after_gmt'] );

			if ( $is_before || $is_after ) {
				$query['date_query'] = array(
					'column'    => 'comment_date_gmt',
					'inclusive' => true,
				);

				if ( $is_before ) {
					$query['date_query']['before'] = $args['before_gmt'];
				}

				if ( $is_after ) {
					$query['date_query']['after'] = $args['after_gmt'];
				}
			}
		}

		if ( $post_id ) {
			$post = get_post( $post_id );
			if ( ! $post || is_wp_error( $post ) ) {
				return new WP_Error( 'unknown_post', 'Unknown post', 404 );
			}
			$query['post_id'] = $post->ID;
			if ( $this->api->ends_with( $this->path, '/replies' ) ) {
				$query['parent'] = 0;
			}
		} elseif ( $comment_id ) {
			$comment = get_comment( $comment_id );
			if ( ! $comment || is_wp_error( $comment ) ) {
				return new WP_Error( 'unknown_comment', 'Unknown comment', 404 );
			}
			$query['parent'] = $comment_id;
		}

		$comments = get_comments( $query );

		update_comment_cache( $comments );

		if ( $args['hierarchical'] ) {
			$walker      = new WPCOM_JSON_API_List_Comments_Walker();
			$comment_ids = $walker->paged_walk( $comments, get_option( 'thread_comments_depth', -1 ), isset( $args['page'] ) ? $args['page'] : 1, $args['number'] );
			if ( ! empty( $comment_ids ) ) {
				$comments = array_map( 'get_comment', $comment_ids );
			}
		}

		$return = array();

		foreach ( array_keys( $this->response_format ) as $key ) {
			switch ( $key ) {
				case 'found':
					$return[ $key ] = (int) $found;
					break;
				case 'site_ID':
					$return[ $key ] = (int) $blog_id;
					break;
				case 'comments':
					$return_comments = array();
					if ( ! empty( $comments ) ) {
						foreach ( $comments as $comment ) {
							$the_comment = $this->get_comment( $comment->comment_ID, $args['context'] );
							if ( $the_comment && ! is_wp_error( $the_comment ) ) {
								$return_comments[] = $the_comment;
							}
						}
					}

					if ( $return_comments ) {
						/** This action is documented in json-endpoints/class.wpcom-json-api-site-settings-endpoint.php */
						do_action( 'wpcom_json_api_objects', 'comments', count( $return_comments ) );
					}

					$return[ $key ] = $return_comments;
					break;
			}
		}

		return $return;
	}
}
