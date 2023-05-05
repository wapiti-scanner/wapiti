<?php
/**
 * This is Calypso skin of the wp-admin interface that is conditionally triggered via the ?calypsoify=1 param.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Status;

/**
 * Class Jetpack_Calypsoify
 */
class Jetpack_Calypsoify {

	/**
	 * Singleton instance of `Jetpack_Calypsoify`.
	 *
	 * @var object
	 */
	public static $instance = false;

	/**
	 * Is Calypsoify enabled, based on any value of `calypsoify` user meta.
	 *
	 * @var bool
	 */
	public $is_calypsoify_enabled = false;

	/**
	 * Jetpack_Calypsoify constructor.
	 */
	private function __construct() {
		add_action( 'admin_init', array( $this, 'setup' ), 4 );
	}

	/**
	 * Singleton.
	 *
	 * @return Jetpack_Calypsoify
	 */
	public static function get_instance() {
		if ( ! self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Setup function that is loaded on the `wp_loaded` hook via the constructor.
	 */
	public function setup() {
		$this->is_calypsoify_enabled = isset( $_GET['calypsoify'] ) && 1 === (int) $_GET['calypsoify'] && $this->is_page_gutenberg(); // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		$this->check_meta();

		if ( $this->is_calypsoify_enabled ) {
			add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_for_gutenberg' ), 100 );
		}
	}

	/**
	 * Enqueues scripts, data, and styles for Gutenberg.
	 */
	public function enqueue_for_gutenberg() {
		$site_suffix = ( new Status() )->get_site_suffix();
		wp_enqueue_style( 'calypsoify_wpadminmods_css', plugin_dir_url( __FILE__ ) . 'style-gutenberg.min.css', false, JETPACK__VERSION );
		wp_style_add_data( 'calypsoify_wpadminmods_css', 'rtl', 'replace' );
		wp_style_add_data( 'calypsoify_wpadminmods_css', 'suffix', '.min' );

		wp_enqueue_script( 'calypsoify_wpadminmods_js', plugin_dir_url( __FILE__ ) . 'mods-gutenberg.js', array( 'jquery' ), JETPACK__VERSION, false );
		wp_localize_script(
			'calypsoify_wpadminmods_js',
			'calypsoifyGutenberg',
			array(
				'closeUrl'                => $this->get_close_gutenberg_url(),
				'manageReusableBlocksUrl' => $this->get_calypso_origin() . '/types/wp_block/' . $site_suffix,
				'createNewPostUrl'        => $this->get_calypso_origin() . '/post/' . $site_suffix,
			)
		);
	}

	/**
	 * Returns the Calypso domain that originated the current request.
	 *
	 * @return string
	 */
	private function get_calypso_origin() {
		$origin  = ! empty( $_GET['origin'] ) ? wp_unslash( $_GET['origin'] ) : 'https://wordpress.com'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$allowed = array(
			'http://calypso.localhost:3000',
			'http://127.0.0.1:41050', // Desktop App.
			'https://wpcalypso.wordpress.com',
			'https://horizon.wordpress.com',
			'https://wordpress.com',
		);
		return in_array( $origin, $allowed, true ) ? $origin : 'https://wordpress.com';
	}

	/**
	 * Returns the Calypso URL that displays either the current post type list (if no args
	 * are supplied) or the classic editor for the current post (if a post ID is supplied).
	 *
	 * @param int|null $post_id Post ID.
	 *
	 * @return string
	 */
	public function get_calypso_url( $post_id = null ) {
		$screen      = get_current_screen();
		$post_type   = $screen->post_type;
		$site_suffix = ( new Status() )->get_site_suffix();

		if ( $post_id === null ) {
			// E.g. posts or pages have no special suffix. CPTs are in the `types/{cpt}` format.
			$post_type_suffix = ( 'post' === $post_type || 'page' === $post_type )
				? "/{$post_type}s/"
				: "/types/{$post_type}/";
			$post_suffix      = '';
		} else {
			$post_type_suffix = ( 'post' === $post_type || 'page' === $post_type )
				? "/{$post_type}/"
				: "/edit/{$post_type}/";
			$post_suffix      = "/{$post_id}";
		}

		return $this->get_calypso_origin() . $post_type_suffix . $site_suffix . $post_suffix;
	}

	/**
	 * Returns the URL to be used on the block editor close button for going back to the
	 * Calypso post list.
	 *
	 * @return string
	 */
	public function get_close_gutenberg_url() {
		return $this->get_calypso_url();
	}

	/**
	 * Returns the URL for switching the user's editor to the Calypso (WordPress.com Classic) editor.
	 *
	 * @return string
	 */
	public function get_switch_to_classic_editor_url() {
		return add_query_arg(
			'set-editor',
			'classic',
			$this->is_calypsoify_enabled ? $this->get_calypso_url( get_the_ID() ) : false
		);
	}

	/**
	 * Checks if the calypsoify user meta value is set, and deletes it if it is.
	 * This is to ensure that Calypsoify is not activated without the URL parameter.
	 */
	public function check_meta() {
		if ( ! empty( get_user_meta( get_current_user_id(), 'calypsoify', true ) ) ) {
			delete_user_meta( get_current_user_id(), 'calypsoify' );
		}
	}

	/**
	 * Return whether a post type should display the Gutenberg/block editor.
	 *
	 * @since 6.7.0
	 *
	 * @param string $post_type Post type.
	 */
	public function is_post_type_gutenberg( $post_type ) {
		return use_block_editor_for_post_type( $post_type );
	}

	/**
	 * Determines if the page is an instance of the Gutenberg block editor.
	 *
	 * @return bool
	 */
	public function is_page_gutenberg() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		// Disabling WordPress.Security.NonceVerification.Recommended because this function fires within admin_init and this is only changing display.
		$page = isset( $_SERVER['REQUEST_URI'] ) ? wp_basename( esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) ) : '';

		if ( false !== strpos( $page, 'post-new.php' ) && empty( $_GET['post_type'] ) ) {
			return true;
		}

		if ( false !== strpos( $page, 'post-new.php' ) && isset( $_GET['post_type'] ) && $this->is_post_type_gutenberg( sanitize_key( $_GET['post_type'] ) ) ) {
			return true;
		}

		if ( false !== strpos( $page, 'post.php' ) ) {
			$post = get_post( isset( $_GET['post'] ) ? intval( $_GET['post'] ) : null );
			if ( isset( $post ) && isset( $post->post_type ) && $this->is_post_type_gutenberg( $post->post_type ) ) {
				return true;
			}
		}

		if ( false !== strpos( $page, 'revision.php' ) ) {
			$post   = get_post( isset( $_GET['revision'] ) ? intval( $_GET['revision'] ) : null );
			$parent = get_post( $post->post_parent );
			if ( isset( $parent ) && isset( $parent->post_type ) && $this->is_post_type_gutenberg( $parent->post_type ) ) {
				return true;
			}
		}

		return false;
		// phpcs:enable
	}

}

Jetpack_Calypsoify::get_instance();
