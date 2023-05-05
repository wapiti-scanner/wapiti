<?php //phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Module Name: Related posts
 * Module Description: Keep visitors engaged on your blog by highlighting relevant and new content at the bottom of each published post.
 * First Introduced: 2.9
 * Sort Order: 29
 * Recommendation Order: 9
 * Requires Connection: Yes
 * Auto Activate: No
 * Module Tags: Recommended
 * Feature: Engagement
 * // phpcs:ignore WordPress.WP.CapitalPDangit.Misspelled
 * Additional Search Queries: related, jetpack related posts, related posts for wordpress, related posts, popular posts, popular, related content, related post, contextual, context, contextual related posts, related articles, similar posts, easy related posts, related page, simple related posts, free related posts, related thumbnails, similar, engagement, yet another related posts plugin
 */
class Jetpack_RelatedPosts_Module {
	/**
	 * Class variables
	 *
	 * @var Jetpack_RelatedPosts_Module
	 */
	private static $instance = null;

	/**
	 * Singleton implementation
	 *
	 * @return object
	 */
	public static function instance() {
		if ( ! is_a( self::$instance, 'Jetpack_RelatedPosts_Module' ) ) {
			self::$instance = new Jetpack_RelatedPosts_Module();
		}

		return self::$instance;
	}

	/**
	 * Register actions and filters
	 *
	 * @uses add_action, add_filter
	 */
	private function __construct() {
		add_action( 'jetpack_module_loaded_related-posts', array( $this, 'action_on_load' ) );
	}

	/**
	 * This action triggers if the module is in an active state, load related posts and options.
	 *
	 * @uses Jetpack_RelatedPosts::init, is_admin, Jetpack::enable_module_configurable, Jetpack_Sync::sync_posts
	 */
	public function action_on_load() {
		require_once __DIR__ . '/related-posts/jetpack-related-posts.php';
		Jetpack_RelatedPosts::init();

		if ( is_admin() ) {
			Jetpack::enable_module_configurable( __FILE__ );
		}

		// Load Customizer controls.
		if ( class_exists( WP_Customize_Manager::class ) && class_exists( WP_Customize_Control::class ) ) {
			require_once __DIR__ . '/related-posts/class.related-posts-customize.php';
		}
	}
}

// Do it.
Jetpack_RelatedPosts_Module::instance();
