<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Allows viewing posts on the frontend when the user is not logged in.
 *
 * @package automattic/jetpack
 */

// phpcs:disable WordPress.Security.NonceVerification.Recommended -- This is _implementing_ cross-site nonce handling, no need for WordPress's nonces.

/**
 * Allows viewing posts on the frontend when the user is not logged in.
 */
class Jetpack_Frame_Nonce_Preview {
	/**
	 * Static instance.
	 *
	 * @todo This should be private.
	 * @var self
	 */
	public static $instance = null;

	/**
	 * Returns the single instance of the Jetpack_Frame_Nonce_Preview object
	 *
	 * @since 4.3.0
	 *
	 * @return Jetpack_Frame_Nonce_Preview
	 **/
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new Jetpack_Frame_Nonce_Preview();
		}

		return self::$instance;
	}

	/**
	 * Constructor.
	 *
	 * @todo This should be private.
	 */
	public function __construct() {
		if ( isset( $_GET['frame-nonce'] ) && ! is_admin() ) {
			add_filter( 'pre_get_posts', array( $this, 'maybe_display_post' ) );
		}

		// autosave previews are validated differently.
		if ( isset( $_GET['frame-nonce'] ) && isset( $_GET['preview_id'] ) && isset( $_GET['preview_nonce'] ) ) {
			remove_action( 'init', '_show_post_preview' );
			add_action( 'init', array( $this, 'handle_autosave_nonce_validation' ) );
		}
	}

	/**
	 * Verify that frame nonce exists, and if so, validate the nonce by calling WP.com.
	 *
	 * @since 4.3.0
	 *
	 * @return bool
	 */
	public function is_frame_nonce_valid() {
		if ( empty( $_GET['frame-nonce'] ) ) {
			return false;
		}

		$xml = new Jetpack_IXR_Client();
		$xml->query( 'jetpack.verifyFrameNonce', sanitize_key( $_GET['frame-nonce'] ) );

		if ( $xml->isError() ) {
			return false;
		}

		return (bool) $xml->getResponse();
	}

	/**
	 * Conditionally add a hook on posts_results if this is the main query, a preview, and singular.
	 *
	 * @since 4.3.0
	 *
	 * @param WP_Query $query Query.
	 * @return WP_Query
	 */
	public function maybe_display_post( $query ) {
		if (
			$query->is_main_query() &&
			$query->is_preview() &&
			$query->is_singular()
		) {
			add_filter( 'posts_results', array( $this, 'set_post_to_publish' ), 10, 2 );
		}

		return $query;
	}

	/**
	 * Conditionally set the first post to 'publish' if the frame nonce is valid and there is a post.
	 *
	 * @since 4.3.0
	 *
	 * @param array $posts Posts.
	 * @return array
	 */
	public function set_post_to_publish( $posts ) {
		remove_filter( 'posts_results', array( $this, 'set_post_to_publish' ), 10, 2 );

		if ( empty( $posts ) || is_user_logged_in() || ! $this->is_frame_nonce_valid() ) {
			return $posts;
		}

		$posts[0]->post_status = 'publish';

		// Disable comments and pings for this post.
		add_filter( 'comments_open', '__return_false' );
		add_filter( 'pings_open', '__return_false' );

		return $posts;
	}

	/**
	 * Handle validation for autosave preview request
	 *
	 * @since 4.7.0
	 */
	public function handle_autosave_nonce_validation() {
		if ( ! $this->is_frame_nonce_valid() ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to preview drafts.', 'jetpack' ) );
		}
		add_filter( 'the_preview', '_set_preview' );
	}
}

Jetpack_Frame_Nonce_Preview::get_instance();
