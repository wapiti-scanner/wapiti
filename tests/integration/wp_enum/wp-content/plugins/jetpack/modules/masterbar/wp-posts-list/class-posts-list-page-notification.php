<?php
/**
 * Posts_List_Page_Notification file.
 * Disable edit_post and delete_post capabilities for Posts Pages in WP-Admin and display a notification icon.
 *
 * @package Jetpack
 */

namespace Automattic\Jetpack\Dashboard_Customizations;

/**
 * Class Posts_List_Page_Notification
 *
 * @package Automattic\Jetpack\Dashboard_Customizations
 */
class Posts_List_Page_Notification {

	/**
	 * Site's Posts page id
	 *
	 * @var int|null
	 */
	private $posts_page_id;

	/**
	 * If the Post_list contains the site's Posts Page
	 *
	 * @var bool
	 */
	private $is_page_in_list = false;

	/**
	 * Class instance.
	 *
	 * @var Posts_List_Page_Notification|null
	 */
	private static $instance = null;

	/**
	 * Posts_List_Page_Notification constructor.
	 *
	 * @param string $posts_page_id The Posts page configured in WordPress.
	 * @param string $show_on_front The show_on_front site option.
	 * @param string $page_on_front The page_on_front site_option.
	 */
	public function __construct( $posts_page_id, $show_on_front, $page_on_front ) {
		if ( 'page' === $show_on_front && $posts_page_id !== $page_on_front ) {
			add_action( 'init', array( $this, 'init_actions' ) );
		}

		$this->posts_page_id = '' === $posts_page_id ? null : (int) $posts_page_id;
	}

	/**
	 * Add in all hooks.
	 */
	public function init_actions() {
		\add_filter( 'map_meta_cap', array( $this, 'disable_posts_page' ), 10, 4 );
		\add_filter( 'post_class', array( $this, 'add_posts_page_css_class' ), 10, 3 );
		\add_action( 'admin_print_footer_scripts-edit.php', array( $this, 'add_notification_icon' ) );
		\add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_css' ) );
	}

	/**
	 * Creates instance.
	 *
	 * @return Posts_List_Page_Notification
	 */
	public static function init() {
		if ( self::$instance === null ) {
			self::$instance = new self( \get_option( 'page_for_posts' ), \get_option( 'show_on_front' ), \get_option( 'page_on_front' ) );
		}

		return self::$instance;
	}

	/**
	 * Disable editing and deleting for the page that is configured as a Posts Page.
	 *
	 * @param array  $caps Array of capabilities.
	 * @param string $cap The current capability.
	 * @param string $user_id The user id.
	 * @param array  $args Argument array.
	 * @return array
	 */
	public function disable_posts_page( $caps, $cap, $user_id, $args ) {
		if ( 'edit_post' !== $cap && 'delete_post' !== $cap ) {
			return $caps;
		}

		if ( isset( $args[0] ) && $this->posts_page_id === $args[0] ) {
			$caps[] = 'do_not_allow';
		}

		return $caps;
	}

	/**
	 * Load the CSS for the WP Posts List
	 *
	 * We would probably need to move this elsewhere when new features are introduced to wp-posts-list.
	 */
	public function enqueue_css() {
		\wp_enqueue_style( 'wp-posts-list', plugins_url( 'wp-posts-list.css', __FILE__ ), array(), JETPACK__VERSION );
	}

	/**
	 * Adds a CSS class on the page configured as a Posts Page.
	 *
	 * @param array  $classes A list of CSS classes.
	 * @param string $class A CSS class.
	 * @param string $post_id The current post id.
	 * @return array
	 */
	public function add_posts_page_css_class( $classes, $class, $post_id ) {
		if ( $this->posts_page_id !== $post_id ) {
			return $classes;
		}

		$this->is_page_in_list = true;

		$classes[] = 'posts-page';

		return $classes;
	}

	/**
	 * Add a info icon on the Posts Page letting the user know why they cannot delete and remove the page.
	 */
	public function add_notification_icon() {
		// No need to add the JS since the site is not configured with a Posts Page or the current listview doesn't contain the page.
		if ( null === $this->posts_page_id || ! $this->is_page_in_list ) {
			return;
		}

		$text_notice = __( 'The content of your latest posts page is automatically generated and cannot be edited.', 'jetpack' );
		?>
		<script>
			document.querySelector(".posts-page .check-column").innerHTML = '' +
					'<div class="info"><span class="icon dashicons dashicons-info-outline"></span><span class="message"><?php echo esc_html( $text_notice ); ?></span></div>';
		</script>
		<?php
	}
}
