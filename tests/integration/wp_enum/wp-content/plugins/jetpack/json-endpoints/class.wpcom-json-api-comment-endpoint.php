<?php //phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Comment endpoint.
 *
 * @todo - can this file be written without overriding global variables?
 * @phpcs:disable WordPress.WP.GlobalVariablesOverride.Prohibited
 */
/**
 * Comment endpoint class.
 */
abstract class WPCOM_JSON_API_Comment_Endpoint extends WPCOM_JSON_API_Endpoint {
	/**
	 * Comment object array.
	 *
	 * @var $comment_object_format
	 */
	public $comment_object_format = array(
		// explicitly document and cast all output.
		'ID'           => '(int) The comment ID.',
		'post'         => "(object>post_reference) A reference to the comment's post.",
		'author'       => '(object>author) The author of the comment.',
		'date'         => "(ISO 8601 datetime) The comment's creation time.",
		'URL'          => '(URL) The full permalink URL to the comment.',
		'short_URL'    => '(URL) The wp.me short URL.',
		'content'      => '(HTML) <code>context</code> dependent.',
		'raw_content'  => '(string) Raw comment content.',
		'status'       => array(
			'approved'   => 'The comment has been approved.',
			'unapproved' => 'The comment has been held for review in the moderation queue.',
			'spam'       => 'The comment has been marked as spam.',
			'trash'      => 'The comment is in the trash.',
		),
		'parent'       => "(object>comment_reference|false) A reference to the comment's parent, if it has one.",
		'type'         => array(
			'comment'   => 'The comment is a regular comment.',
			'trackback' => 'The comment is a trackback.',
			'pingback'  => 'The comment is a pingback.',
			'review'    => 'The comment is a product review.',
		),
		'like_count'   => '(int) The number of likes for this comment.',
		'i_like'       => '(bool) Does the current user like this comment?',
		'meta'         => '(object) Meta data',
		'can_moderate' => '(bool) Whether current user can moderate the comment.',
		'i_replied'    => '(bool) Has the current user replied to this comment?',
	);

	/**
	 * Class constructor.
	 *
	 * @param object $args - arguments passed to constructor.
	 */
	public function __construct( $args ) {
		if ( ! $this->response_format ) {
			$this->response_format =& $this->comment_object_format;
		}
		parent::__construct( $args );
	}

	/**
	 * Get the comment.
	 *
	 * @param int    $comment_id - the ID of the comment.
	 * @param string $context - the context of the comment (displayed or edited).
	 */
	public function get_comment( $comment_id, $context ) {
		global $blog_id;

		$comment = get_comment( $comment_id );
		if ( ! $comment || is_wp_error( $comment ) ) {
			return new WP_Error( 'unknown_comment', 'Unknown comment', 404 );
		}

		$types = array( '', 'comment', 'pingback', 'trackback', 'review' );
		// @todo - can we make this comparison strict without breaking anything?
		// phpcs:ignore WordPress.PHP.StrictInArray.MissingTrueStrict
		if ( ! in_array( $comment->comment_type, $types ) ) {
			return new WP_Error( 'unknown_comment', 'Unknown comment', 404 );
		}

		$post = get_post( $comment->comment_post_ID );
		if ( ! $post || is_wp_error( $post ) ) {
			return new WP_Error( 'unknown_post', 'Unknown post', 404 );
		}

		$status = wp_get_comment_status( $comment->comment_ID );

		// Permissions.
		switch ( $context ) {
			case 'edit':
				if ( ! current_user_can( 'edit_comment', $comment->comment_ID ) ) {
					return new WP_Error( 'unauthorized', 'User cannot edit comment', 403 );
				}

				$GLOBALS['post'] = $post;
				$comment         = get_comment_to_edit( $comment->comment_ID );
				foreach ( array( 'comment_author', 'comment_author_email', 'comment_author_url' ) as $field ) {
					$comment->$field = htmlspecialchars_decode( $comment->$field, ENT_QUOTES );
				}
				break;
			case 'display':
				if ( 'approved' !== $status ) {
					$current_user_id       = get_current_user_id();
					$user_can_read_comment = false;
					// @todo - can we make this comparison strict without breaking anything?
					// phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
					if ( $current_user_id && $comment->user_id && $current_user_id == $comment->user_id ) {
						$user_can_read_comment = true;
					} elseif (
					$comment->comment_author_email && $comment->comment_author
					&&
					isset( $this->api->token_details['user'] )
					&&
					isset( $this->api->token_details['user']['user_email'] )
					&&
					$this->api->token_details['user']['user_email'] === $comment->comment_author_email
					&&
					$this->api->token_details['user']['display_name'] === $comment->comment_author
					) {
						$user_can_read_comment = true;
					} else {
						$user_can_read_comment = current_user_can( 'edit_posts' );
					}

					if ( ! $user_can_read_comment ) {
						return new WP_Error( 'unauthorized', 'User cannot read unapproved comment', 403 );
					}
				}

				$GLOBALS['post'] = $post;
				setup_postdata( $post );
				break;
			default:
				return new WP_Error( 'invalid_context', 'Invalid API CONTEXT', 400 );
		}

		$can_view = $this->user_can_view_post( $post->ID );
		if ( ! $can_view || is_wp_error( $can_view ) ) {
			return $can_view;
		}

		$GLOBALS['comment'] = $comment;
		$response           = array();

		foreach ( array_keys( $this->comment_object_format ) as $key ) {
			switch ( $key ) {
				case 'ID':
					// explicitly cast all output.
					$response[ $key ] = (int) $comment->comment_ID;
					break;
				case 'post':
					$response[ $key ] = (object) array(
						'ID'    => (int) $post->ID,
						'title' => (string) get_the_title( $post->ID ),
						'type'  => (string) $post->post_type,
						'link'  => (string) $this->links->get_post_link( $this->api->get_blog_id_for_output(), $post->ID ),
					);
					break;
				case 'author':
					$response[ $key ] = (object) $this->get_author( $comment, current_user_can( 'edit_comment', $comment->comment_ID ) );
					break;
				case 'date':
					$response[ $key ] = (string) $this->format_date( $comment->comment_date_gmt, $comment->comment_date );
					break;
				case 'URL':
					$response[ $key ] = (string) esc_url_raw( get_comment_link( $comment->comment_ID ) );
					break;
				case 'short_URL':
					// @todo - pagination
					$response[ $key ] = (string) esc_url_raw( wp_get_shortlink( $post->ID ) . "%23comment-{$comment->comment_ID}" );
					break;
				case 'content':
					if ( 'display' === $context ) {
						ob_start();
						comment_text();
						$response[ $key ] = (string) ob_get_clean();
					} else {
						$response[ $key ] = (string) $comment->comment_content;
					}
					break;
				case 'raw_content':
					$response[ $key ] = (string) $comment->comment_content;
					break;
				case 'status':
					$response[ $key ] = (string) $status;
					break;
				case 'parent': // May be object or false.
					if ( $comment->comment_parent ) {
						$parent           = get_comment( $comment->comment_parent );
						$response[ $key ] = (object) array(
							'ID'   => (int) $parent->comment_ID,
							'type' => (string) ( $parent->comment_type ? $parent->comment_type : 'comment' ),
							'link' => (string) $this->links->get_comment_link( $blog_id, $parent->comment_ID ),
						);
					} else {
						$response[ $key ] = false;
					}
					break;
				case 'type':
					$response[ $key ] = (string) ( $comment->comment_type ? $comment->comment_type : 'comment' );
					break;
				case 'like_count':
					if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
						$response[ $key ] = (int) $this->api->comment_like_count( $blog_id, $post->ID, $comment->comment_ID );
					}
					break;
				case 'i_like':
					if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
						$response[ $key ] = (bool) Likes::comment_like_current_user_likes( $blog_id, $comment->comment_ID );
					}
					break;
				case 'meta':
					$response[ $key ] = (object) array(
						'links' => (object) array(
							'self'    => (string) $this->links->get_comment_link( $this->api->get_blog_id_for_output(), $comment->comment_ID ),
							'help'    => (string) $this->links->get_comment_link( $this->api->get_blog_id_for_output(), $comment->comment_ID, 'help' ),
							'site'    => (string) $this->links->get_site_link( $this->api->get_blog_id_for_output() ),
							'post'    => (string) $this->links->get_post_link( $this->api->get_blog_id_for_output(), $comment->comment_post_ID ),
							'replies' => (string) $this->links->get_comment_link( $this->api->get_blog_id_for_output(), $comment->comment_ID, 'replies/' ),
							'likes'   => (string) $this->links->get_comment_link( $this->api->get_blog_id_for_output(), $comment->comment_ID, 'likes/' ),
						),
					);
					break;
				case 'can_moderate':
					$response[ $key ] = (bool) current_user_can( 'edit_comment', $comment_id );
					break;
				case 'i_replied':
					$response[ $key ] = (bool) 0 < get_comments(
						array(
							'user_id' => get_current_user_id(),
							'parent'  => $comment->comment_ID,
							'count'   => true,
						)
					);
					break;
			}
		}

		unset( $GLOBALS['comment'], $GLOBALS['post'] );
		return $response;
	}
}

