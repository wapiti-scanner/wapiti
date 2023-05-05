<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Module Name: Infinite Scroll
 * Module Description: Automatically load new content when a visitor scrolls
 * Sort Order: 26
 * First Introduced: 2.0
 * Requires Connection: No
 * Auto Activate: No
 * Module Tags: Appearance
 * Feature: Appearance
 * Additional Search Queries: scroll, infinite, infinite scroll
 */

use Automattic\Jetpack\Stats\Options as Stats_Options;

/**
 * Jetpack-specific elements of Infinite Scroll
 */
class Jetpack_Infinite_Scroll_Extras {
	/**
	 * Class variable singleton.
	 *
	 * @var Jetpack_Infinite_Scroll_Extras
	 */
	private static $instance = null;

	/**
	 * Option names.
	 *
	 * @var string
	 */
	private $option_name_google_analytics = 'infinite_scroll_google_analytics';

	/**
	 * Singleton implementation
	 *
	 * @return object
	 */
	public static function instance() {
		if ( ! self::$instance instanceof Jetpack_Infinite_Scroll_Extras ) {
			self::$instance = new Jetpack_Infinite_Scroll_Extras();
		}

		return self::$instance;
	}

	/**
	 * Register actions and filters
	 *
	 * @uses add_action, add_filter
	 */
	private function __construct() {
		add_action( 'jetpack_modules_loaded', array( $this, 'action_jetpack_modules_loaded' ) );

		add_action( 'admin_init', array( $this, 'action_admin_init' ), 11 );

		add_action( 'after_setup_theme', array( $this, 'action_after_setup_theme' ), 5 );

		add_filter( 'infinite_scroll_js_settings', array( $this, 'filter_infinite_scroll_js_settings' ) );

		add_action( 'wp_enqueue_scripts', array( $this, 'action_wp_enqueue_scripts' ) );
	}

	/**
	 * Enable "Configure" button on module card
	 *
	 * @uses Jetpack::enable_module_configurable
	 * @action jetpack_modules_loaded
	 */
	public function action_jetpack_modules_loaded() {
		Jetpack::enable_module_configurable( __FILE__ );
	}

	/**
	 * Register Google Analytics setting
	 *
	 * @uses add_settings_field, __, register_setting
	 * @action admin_init
	 */
	public function action_admin_init() {
		if ( ! Jetpack_Plan::supports( 'google-analytics' ) ) {
			return;
		}

		add_settings_field( $this->option_name_google_analytics, '<span id="infinite-scroll-google-analytics">' . __( 'Use Google Analytics with Infinite Scroll', 'jetpack' ) . '</span>', array( $this, 'setting_google_analytics' ), 'reading' );
		register_setting( 'reading', $this->option_name_google_analytics, array( $this, 'sanitize_boolean_value' ) );
	}

	/**
	 * Render Google Analytics option
	 *
	 * @uses checked, get_option, __
	 */
	public function setting_google_analytics() {
		echo '<label><input name="infinite_scroll_google_analytics" type="checkbox" value="1" ' . checked( true, (bool) get_option( $this->option_name_google_analytics, false ), false ) . ' /> ' . esc_html__( 'Track each scroll load (7 posts by default) as a page view in Google Analytics', 'jetpack' ) . '</label>';
		echo '<p class="description">' . esc_html__( 'Check the box above to record each new set of posts loaded via Infinite Scroll as a page view in Google Analytics.', 'jetpack' ) . '</p>';
	}

	/**
	 * Sanitize value as a boolean
	 *
	 * @param mixed $value - the value we're sanitizing.
	 * @return bool
	 */
	public function sanitize_boolean_value( $value ) {
		return (bool) $value;
	}

	/**
	 * Load theme's infinite scroll annotation file, if present in the IS plugin.
	 * The `setup_theme` action is used because the annotation files should be using `after_setup_theme` to register support for IS.
	 *
	 * As released in Jetpack 2.0, a child theme's parent wasn't checked for in the plugin's bundled support, hence the convoluted way the parent is checked for now.
	 *
	 * @uses is_admin, wp_get_theme, apply_filters
	 * @action setup_theme
	 * @return null
	 */
	public function action_after_setup_theme() {
		$theme = wp_get_theme();

		if ( ! $theme instanceof WP_Theme && ! is_array( $theme ) ) {
			return;
		}

		/** This filter is already documented in modules/infinite-scroll/infinity.php */
		$customization_file = apply_filters( 'infinite_scroll_customization_file', __DIR__ . "/infinite-scroll/themes/{$theme['Stylesheet']}.php", $theme['Stylesheet'] );

		if ( is_readable( $customization_file ) ) {
			require_once $customization_file;
		} elseif ( ! empty( $theme['Template'] ) ) {
			$customization_file = __DIR__ . "/infinite-scroll/themes/{$theme['Template']}.php";

			if ( is_readable( $customization_file ) ) {
				require_once $customization_file;
			}
		}
	}

	/**
	 * Modify Infinite Scroll configuration information
	 *
	 * @uses Jetpack::get_active_modules, is_user_logged_in, stats_get_options, Jetpack_Options::get_option, get_option, JETPACK__API_VERSION, JETPACK__VERSION
	 * @filter infinite_scroll_js_settings
	 *
	 * @param array $settings - the settings.
	 * @return array
	 */
	public function filter_infinite_scroll_js_settings( $settings ) {
		// Provide WP Stats info for tracking Infinite Scroll loads
		// Abort if Stats module isn't active
		if ( in_array( 'stats', Jetpack::get_active_modules(), true ) ) {
			// Abort if user is logged in but logged-in users shouldn't be tracked.
			if ( is_user_logged_in() ) {
				$stats_options        = Stats_Options::get_options();
				$track_loggedin_users = isset( $stats_options['count_roles'] ) ? (bool) $stats_options['count_roles'] : false;

				if ( ! $track_loggedin_users ) {
					return $settings;
				}
			}

			// We made it this far, so gather the data needed to track IS views
			$settings['stats'] = 'blog=' . Jetpack_Options::get_option( 'id' ) . '&host=' . wp_parse_url( get_option( 'home' ), PHP_URL_HOST ) . '&v=ext&j=' . JETPACK__API_VERSION . ':' . JETPACK__VERSION;

			// Pagetype parameter
			$settings['stats'] .= '&x_pagetype=infinite';
			if ( 'click' === $settings['type'] ) {
				$settings['stats'] .= '-click';
			}

			$settings['stats'] .= '-jetpack';
		}

		// Check if Google Analytics tracking is requested.
		$settings['google_analytics'] = Jetpack_Plan::supports( 'google-analytics' ) && Jetpack_Options::get_option_and_ensure_autoload( $this->option_name_google_analytics, 0 );

		return $settings;
	}

	/**
	 * Always load certain scripts when IS is enabled, as they can't be loaded after `document.ready` fires, meaning they can't leverage IS's script loader.
	 *
	 * @global $videopress
	 * @uses do_action()
	 * @uses apply_filters()
	 * @uses wp_enqueue_style()
	 * @uses wp_enqueue_script()
	 * @action wp_enqueue_scripts
	 * @return null
	 */
	public function action_wp_enqueue_scripts() {
		// Do not load scripts and styles on singular pages and static pages
		$load_scripts_and_styles = ! ( is_singular() || is_page() );
		if (
			/**
			 * Allow plugins to enqueue all Infinite Scroll scripts and styles on singular pages as well.
			 *
			 *  @module infinite-scroll
			 *
			 * @since 3.1.0
			 *
			 * @param bool $load_scripts_and_styles Should scripts and styles be loaded on singular pahes and static pages. Default to false.
			 */
			! apply_filters( 'jetpack_infinite_scroll_load_scripts_and_styles', $load_scripts_and_styles )
		) {
			return;
		}

		// VideoPress stand-alone plugin
		global $videopress;
		if ( ! empty( $videopress ) && The_Neverending_Home_Page::archive_supports_infinity() && is_a( $videopress, 'VideoPress' ) && method_exists( $videopress, 'enqueue_scripts' ) ) {
			$videopress->enqueue_scripts();
		}

		// VideoPress Jetpack module
		if ( Jetpack::is_module_active( 'videopress' ) ) {
			wp_enqueue_script( 'videopress' );
		}

		// Fire the post_gallery action early so Carousel scripts are present.
		if ( Jetpack::is_module_active( 'carousel' ) ) {
			/** This filter is already documented in core/wp-includes/media.php */
			do_action( 'post_gallery', '', '', 0 );
		}

		// Always enqueue Tiled Gallery scripts when both IS and Tiled Galleries are enabled
		if ( Jetpack::is_module_active( 'tiled-gallery' ) ) {
			Jetpack_Tiled_Gallery::default_scripts_and_styles();
		}
	}
}
Jetpack_Infinite_Scroll_Extras::instance();

/**
 * Load main IS file
 */
require_once __DIR__ . '/infinite-scroll/infinity.php';

/**
 * Remove the IS annotation loading function bundled with the IS plugin in favor of the Jetpack-specific version in Jetpack_Infinite_Scroll_Extras::action_after_setup_theme();
 */
remove_action( 'after_setup_theme', 'the_neverending_home_page_theme_support', 5 );
