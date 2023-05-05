<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Manage comments via the WordPress.com REST API.
 *
 * Endpoints;
 * Create a comment on a post:                     /sites/%s/posts/%d/replies/new
 * Create a comment as a reply to another comment: /sites/%s/comments/%d/replies/new
 * Edit a comment:                                 /sites/%s/comments/%d
 * Delete a comment:                               /sites/%s/comments/%d/delete
 */

use Automattic\Jetpack\Status;

new WPCOM_JSON_API_Update_Comment_Endpoint(
	array(
		'description'                          => 'Create a comment on a post.',
		'group'                                => 'comments',
		'stat'                                 => 'posts:1:replies:new',

		'method'                               => 'POST',
		'path'                                 => '/sites/%s/posts/%d/replies/new',
		'path_labels'                          => array(
			'$site'    => '(int|string) Site ID or domain',
			'$post_ID' => '(int) The post ID',
		),

		'request_format'                       => array(
			// explicitly document all input.
			'content' => '(HTML) The comment text.',
		// @todo Should we open this up to unauthenticated requests too?
		// 'author'    => '(author object) The author of the comment.',
		),

		'pass_wpcom_user_details'              => true,

		'allow_fallback_to_jetpack_blog_token' => true,

		'example_request'                      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/posts/843/replies/new/',
		'example_request_data'                 => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'content' => 'Your reply is very interesting. This is a reply.',
			),
		),
	)
);

new WPCOM_JSON_API_Update_Comment_Endpoint(
	array(
		'description'                          => 'Create a comment as a reply to another comment.',
		'group'                                => 'comments',
		'stat'                                 => 'comments:1:replies:new',

		'method'                               => 'POST',
		'path'                                 => '/sites/%s/comments/%d/replies/new',
		'path_labels'                          => array(
			'$site'       => '(int|string) Site ID or domain',
			'$comment_ID' => '(int) The comment ID',
		),

		'request_format'                       => array(
			'content' => '(HTML) The comment text.',
		// @todo Should we open this up to unauthenticated requests too?
		// 'author'    => '(author object) The author of the comment.',
		),

		'pass_wpcom_user_details'              => true,

		'allow_fallback_to_jetpack_blog_token' => true,

		'example_request'                      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/comments/29/replies/new',
		'example_request_data'                 => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'content' => 'This reply is very interesting. This is editing a comment reply via the API.',
			),
		),
	)
);

new WPCOM_JSON_API_Update_Comment_Endpoint(
	array(
		'description'          => 'Edit a comment.',
		'group'                => 'comments',
		'stat'                 => 'comments:1:POST',

		'method'               => 'POST',
		'path'                 => '/sites/%s/comments/%d',
		'path_labels'          => array(
			'$site'       => '(int|string) Site ID or domain',
			'$comment_ID' => '(int) The comment ID',
		),

		'request_format'       => array(
			'author'       => "(string) The comment author's name.",
			'author_email' => "(string) The comment author's email.",
			'author_url'   => "(string) The comment author's URL.",
			'content'      => '(HTML) The comment text.',
			'date'         => "(ISO 8601 datetime) The comment's creation time.",
			'status'       => array(
				'approved'   => 'Approve the comment.',
				'unapproved' => 'Remove the comment from public view and send it to the moderation queue.',
				'spam'       => 'Mark the comment as spam.',
				'unspam'     => 'Unmark the comment as spam. Will attempt to set it to the previous status.',
				'trash'      => 'Send a comment to the trash if trashing is enabled (see constant: EMPTY_TRASH_DAYS).',
				'untrash'    => 'Untrash a comment. Only works when the comment is in the trash.',
			),
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/comments/29',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'content' => 'This reply is now edited via the API.',
				'status'  => 'approved',
			),
		),
	)
);

new WPCOM_JSON_API_Update_Comment_Endpoint(
	array(
		'description'          => 'Delete a comment.',
		'group'                => 'comments',
		'stat'                 => 'comments:1:delete',

		'method'               => 'POST',
		'path'                 => '/sites/%s/comments/%d/delete',
		'path_labels'          => array(
			'$site'       => '(int|string) Site ID or domain',
			'$comment_ID' => '(int) The comment ID',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/comments/$comment_ID/delete',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
	)
);

/**
 * Update comments endpoint class.
 */
class WPCOM_JSON_API_Update_Comment_Endpoint extends WPCOM_JSON_API_Comment_Endpoint {
	/**
	 * WPCOM_JSON_API_Update_Comment_Endpoint constructor.
	 *
	 * @param array $args - Args.
	 */
	public function __construct( $args ) {
		parent::__construct( $args );
		if ( $this->api->ends_with( $this->path, '/delete' ) ) {
			$this->comment_object_format['status']['deleted'] = 'The comment has been deleted permanently.';
		}
	}

	/**
	 * Update comment API callback.
	 *
	 * /sites/%s/posts/%d/replies/new    -> $blog_id, $post_id
	 * /sites/%s/comments/%d/replies/new -> $blog_id, $comment_id
	 * /sites/%s/comments/%d             -> $blog_id, $comment_id
	 * /sites/%s/comments/%d/delete      -> $blog_id, $comment_id
	 *
	 * @param string $path API path.
	 * @param int    $blog_id The blog ID.
	 * @param int    $object_id The object ID.
	 *
	 * @return bool|WP_Error|array
	 */
	public function callback( $path = '', $blog_id = 0, $object_id = 0 ) {
		if ( $this->api->ends_with( $path, '/new' ) ) {
			$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ), false );
		} else {
			$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		}
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		if ( $this->api->ends_with( $path, '/delete' ) ) {
			return $this->delete_comment( $path, $blog_id, $object_id );
		} elseif ( $this->api->ends_with( $path, '/new' ) ) {
			if ( false !== strpos( $path, '/posts/' ) ) {
				return $this->new_comment( $path, $blog_id, $object_id, 0 );
			} else {
				return $this->new_comment( $path, $blog_id, 0, $object_id );
			}
		}

		return $this->update_comment( $path, $blog_id, $object_id );
	}

	/**
	 * Add a new comment to a post or as a reply to another comment.
	 *
	 * /sites/%s/posts/%d/replies/new    -> $blog_id, $post_id
	 * /sites/%s/comments/%d/replies/new -> $blog_id, $comment_id
	 *
	 * @param string $path API path.
	 * @param int    $blog_id The blog ID.
	 * @param int    $post_id The post ID.
	 * @param int    $comment_parent_id The comment parent ID.
	 *
	 * @return bool|WP_Error|array
	 */
	public function new_comment( $path, $blog_id, $post_id, $comment_parent_id ) {
		if ( ! $post_id ) {
			$comment_parent = get_comment( $comment_parent_id );
			if ( ! $comment_parent_id || ! $comment_parent || is_wp_error( $comment_parent ) ) {
				return new WP_Error( 'unknown_comment', 'Unknown comment', 404 );
			}

			$post_id = $comment_parent->comment_post_ID;
		}

		$post = get_post( $post_id );
		if ( ! $post || is_wp_error( $post ) ) {
			return new WP_Error( 'unknown_post', 'Unknown post', 404 );
		}

		if (
			( new Status() )->is_private_site() &&
			/**
			 * Filter allowing non-registered users on the site to comment.
			 *
			 * @module json-api
			 *
			 * @since 3.4.0
			 *
			 * @param bool is_user_member_of_blog() Is the user member of the site.
			 */
			! apply_filters( 'wpcom_json_api_user_is_member_of_blog', is_user_member_of_blog() ) &&
			! is_super_admin()
		) {
			return new WP_Error( 'unauthorized', 'User cannot create comments', 403 );
		}

		if ( ! comments_open( $post->ID ) && ! current_user_can( 'edit_post', $post->ID ) ) {
			return new WP_Error( 'unauthorized', 'Comments on this post are closed', 403 );
		}

		$can_view = $this->user_can_view_post( $post->ID );
		if ( ! $can_view || is_wp_error( $can_view ) ) {
			return $can_view;
		}

		$post_status = get_post_status_object( get_post_status( $post ) );
		if ( ! $post_status->public && ! $post_status->private ) {
			return new WP_Error( 'unauthorized', 'Comments on drafts are not allowed', 403 );
		}

		$args  = $this->query_args();
		$input = $this->input();
		if ( ! is_array( $input ) || ! $input || ! strlen( $input['content'] ) ) {
			return new WP_Error( 'invalid_input', 'Invalid request input', 400 );
		}

		$user = wp_get_current_user();
		if ( ! $user || is_wp_error( $user ) || ! $user->ID ) {
			$auth_required = false;
			if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
				$auth_required = true;
			} elseif ( isset( $this->api->token_details['user'] ) ) {
				$user = (object) $this->api->token_details['user'];
				foreach ( array( 'display_name', 'user_email', 'user_url' ) as $user_datum ) {
					if ( ! isset( $user->$user_datum ) ) {
						$auth_required = true;
					}
				}
				if ( ! isset( $user->ID ) ) {
					$user->ID = 0;
				}

				$author = get_user_by( 'id', (int) $user->ID );
				// If we have a user with an external ID saved, we can use it.
				if (
					! $auth_required
					&& $user->ID
					&& $author
				) {
					$user = $author;
				}
			} else {
				$auth_required = true;
			}

			if ( $auth_required ) {
				return new WP_Error( 'authorization_required', 'An active access token must be used to comment.', 403 );
			}
		}

		$insert = array(
			'comment_post_ID'      => $post->ID,
			'user_ID'              => $user->ID,
			'comment_author'       => $user->display_name,
			'comment_author_email' => $user->user_email,
			'comment_author_url'   => $user->user_url,
			'comment_content'      => $input['content'],
			'comment_parent'       => $comment_parent_id,
			'comment_type'         => 'comment',
		);

		if ( $comment_parent_id ) {
			if ( '0' === $comment_parent->comment_approved && current_user_can( 'edit_comment', $comment_parent->comment_ID ) ) {
				wp_set_comment_status( $comment_parent->comment_ID, 'approve' );
			}
		}

		$this->api->trap_wp_die( 'comment_failure' );
		$comment_id = wp_new_comment( add_magic_quotes( $insert ) );
		$this->api->trap_wp_die( null );

		$return = $this->get_comment( $comment_id, $args['context'] );
		if ( ! $return ) {
			return new WP_Error( 400, __( 'Comment cache problem?', 'jetpack' ) );
		}
		if ( is_wp_error( $return ) ) {
			return $return;
		}

		/** This action is documented in json-endpoints/class.wpcom-json-api-site-settings-endpoint.php */
		do_action( 'wpcom_json_api_objects', 'comments' );
		return $return;
	}

	/**
	 * Update a comment.
	 *
	 * /sites/%s/comments/%d -> $blog_id, $comment_id
	 *
	 * @param string $path API path.
	 * @param int    $blog_id Blog ID.
	 * @param int    $comment_id Comment ID.
	 *
	 * @return bool|WP_Error|array
	 */
	public function update_comment( $path, $blog_id, $comment_id ) {
		$comment = get_comment( $comment_id );
		if ( ! $comment || is_wp_error( $comment ) ) {
			return new WP_Error( 'unknown_comment', 'Unknown comment', 404 );
		}

		if ( ! current_user_can( 'edit_comment', $comment->comment_ID ) ) {
			return new WP_Error( 'unauthorized', 'User cannot edit comment', 403 );
		}

		$args  = $this->query_args();
		$input = $this->input( false );
		if ( ! is_array( $input ) || ! $input ) {
			return new WP_Error( 'invalid_input', 'Invalid request input', 400 );
		}

		$update = array();
		foreach ( $input as $key => $value ) {
			$update[ "comment_$key" ] = $value;
		}

		$comment_status = wp_get_comment_status( $comment->comment_ID );
		if ( isset( $update['comment_status'] ) ) {
			switch ( $update['comment_status'] ) {
				case 'approved':
					if ( 'approve' !== $comment_status ) {
						wp_set_comment_status( $comment->comment_ID, 'approve' );
					}
					break;
				case 'unapproved':
					if ( 'hold' !== $comment_status ) {
						wp_set_comment_status( $comment->comment_ID, 'hold' );
					}
					break;
				case 'spam':
					if ( 'spam' !== $comment_status ) {
						wp_spam_comment( $comment->comment_ID );
					}
					break;
				case 'unspam':
					if ( 'spam' === $comment_status ) {
						wp_unspam_comment( $comment->comment_ID );
					}
					break;
				case 'trash':
					if ( ! EMPTY_TRASH_DAYS ) {
						return new WP_Error( 'trash_disabled', 'Cannot trash comment', 403 );
					}

					if ( 'trash' !== $comment_status ) {
						wp_trash_comment( $comment_id );
					}
					break;
				case 'untrash':
					if ( 'trash' === $comment_status ) {
						wp_untrash_comment( $comment->comment_ID );
					}
					break;
				default:
					$update['comment_approved'] = 1;
					break;
			}
			unset( $update['comment_status'] );
		}

		if ( ! empty( $update ) ) {
			$update['comment_ID'] = $comment->comment_ID;
			wp_update_comment( add_magic_quotes( $update ) );
		}

		$return = $this->get_comment( $comment->comment_ID, $args['context'] );
		if ( ! $return || is_wp_error( $return ) ) {
			return $return;
		}

		/** This action is documented in json-endpoints/class.wpcom-json-api-site-settings-endpoint.php */
		do_action( 'wpcom_json_api_objects', 'comments' );
		return $return;
	}

	/**
	 * Delete a comment.
	 *
	 * /sites/%s/comments/%d/delete -> $blog_id, $comment_id
	 *
	 * @param string $path API path.
	 * @param int    $blog_id Blog ID.
	 * @param int    $comment_id Comment ID.
	 *
	 * @return bool|WP_Error|array
	 */
	public function delete_comment( $path, $blog_id, $comment_id ) {
		$comment = get_comment( $comment_id );
		if ( ! $comment || is_wp_error( $comment ) ) {
			return new WP_Error( 'unknown_comment', 'Unknown comment', 404 );
		}

		if ( ! current_user_can( 'edit_comment', $comment->comment_ID ) ) { // [sic] There is no delete_comment cap
			return new WP_Error( 'unauthorized', 'User cannot delete comment', 403 );
		}

		$args   = $this->query_args();
		$return = $this->get_comment( $comment->comment_ID, $args['context'] );
		if ( ! $return || is_wp_error( $return ) ) {
			return $return;
		}

		/** This action is documented in json-endpoints/class.wpcom-json-api-site-settings-endpoint.php */
		do_action( 'wpcom_json_api_objects', 'comments' );

		wp_delete_comment( $comment->comment_ID );
		$status = wp_get_comment_status( $comment->comment_ID );
		if ( false === $status ) {
			$return['status'] = 'deleted';
			return $return;
		}

		return $this->get_comment( $comment->comment_ID, $args['context'] );
	}
}
