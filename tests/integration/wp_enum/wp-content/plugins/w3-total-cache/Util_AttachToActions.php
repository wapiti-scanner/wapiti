<?php
namespace W3TC;

/**
 * Attaches to wp actions related to content change, which should fire
 * flushes of html content
 */
class Util_AttachToActions {
	/**
	 * Flush actions.
	 *
	 * @return void
	 */
	public static function flush_posts_on_actions() {
		static $attached = false;
		if ( $attached ) {
			return;
		}

		$attached = true;

		$o = new Util_AttachToActions();

		// posts.
		add_action( 'pre_post_update', array( $o, 'on_pre_post_update' ), 0, 2 );
		add_action( 'save_post', array( $o, 'on_post_change' ), 0, 2 );
		add_action( 'wp_trash_post', array( $o, 'on_post_change' ), 0, 2 );

		// comments.
		add_action( 'comment_post', array( $o, 'on_comment_change' ), 0 );
		add_action( 'edit_comment', array( $o, 'on_comment_change' ), 0 );
		add_action( 'delete_comment', array( $o, 'on_comment_change' ), 0 );
		add_action( 'wp_set_comment_status', array( $o, 'on_comment_status' ), 0, 2 );
		add_action( 'trackback_post', array( $o, 'on_comment_change' ), 0 );
		add_action( 'pingback_post', array( $o, 'on_comment_change' ), 0 );

		// theme.
		add_action( 'switch_theme', array( $o, 'on_change' ), 0 );

		// navigation menu.
		add_action( 'wp_update_nav_menu', array( $o, 'on_change' ), 0 );

		// user profile.
		add_action( 'edit_user_profile_update', array( $o, 'on_change' ), 0 );

		// terms.
		add_action( 'edited_term', array( $o, 'on_change' ), 0 );
		add_action( 'delete_term', array( $o, 'on_change' ), 0 );

		// multisite.
		if ( Util_Environment::is_wpmu() ) {
			add_action( 'delete_blog', array( $o, 'on_change' ), 0 );
		}
	}

	/**
	 * Pre-Post changed action for published post changed to draft which invalidates the published URL.
	 *
	 * @link https://developer.wordpress.org/reference/hooks/pre_post_update/
	 *
	 * @param integer $post_id Post ID.
	 * @param array   $data    Array of unslashed post data.
	 *
	 * @return void
	 */
	public function on_pre_post_update( $post_id, $data = null ) {
		if ( is_null( $data ) ) {
			$data = get_post( $post_id, ARRAY_A );
		}

		// if attachment changed - parent post has to be flushed
		// since there are usually attachments content like title
		// on the page (gallery).
		if ( isset( $data['post_type'] ) && 'attachment' === $data['post_type'] ) {
			$post_id = $data['post_parent'];
			$data    = get_post( $post_id, ARRAY_A );
		}

		if ( ! isset( $data['post_status'] ) || 'draft' !== $data['post_status'] ) {
			return;
		}

		$cacheflush = Dispatcher::component( 'CacheFlush' );
		$cacheflush->flush_post( $post_id );
	}

	/**
	 * Post changed action
	 *
	 * @link https://developer.wordpress.org/reference/hooks/save_post/
	 *
	 * @param integer $post_id Post ID.
	 * @param WP_Post $post    Post.
	 *
	 * @return void
	 */
	public function on_post_change( $post_id, $post = null ) {
		if ( is_null( $post ) ) {
			$post = get_post( $post_id );
		}

		// if attachment changed - parent post has to be flushed
		// since there are usually attachments content like title
		// on the page (gallery).
		if ( isset( $post->post_type ) && 'attachment' === $post->post_type ) {
			$post_id = $post->post_parent;
			$post    = get_post( $post_id );
		}

		if ( ! Util_Environment::is_flushable_post( $post, 'posts', Dispatcher::config() ) ) {
			return;
		}

		$cacheflush = Dispatcher::component( 'CacheFlush' );
		$cacheflush->flush_post( $post_id );
	}

	/**
	 * Comment change action.
	 *
	 * @param integer $comment_id Comment ID.
	 */
	public function on_comment_change( $comment_id ) {
		$post_id = 0;

		if ( $comment_id ) {
			$comment = get_comment( $comment_id, ARRAY_A );
			$post_id = ( ! empty( $comment['comment_post_ID'] ) ? (int) $comment['comment_post_ID'] : 0 );
		}

		$this->on_post_change( $post_id );
	}

	/**
	 * Comment status action fired immediately after transitioning a comment’s status from one to another
	 * in the database and removing the comment, but prior to all status transition hooks.
	 *
	 * @link https://developer.wordpress.org/reference/functions/wp_set_comment_status/
	 *
	 * @param integer $comment_id Comment ID.
	 * @param string  $status Status.
	 */
	public function on_comment_status( $comment_id, $status ) {
		$this->on_comment_change( $comment_id );
	}

	/**
	 * Change action
	 */
	public function on_change() {
		$cacheflush = Dispatcher::component( 'CacheFlush' );
		$cacheflush->flush_posts();
	}
}
