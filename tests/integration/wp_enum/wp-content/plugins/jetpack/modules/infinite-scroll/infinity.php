<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Redirect;

/*
Plugin Name: The Neverending Home Page.
Plugin URI: https://automattic.com/
Description: Adds infinite scrolling support to the front-end blog post view for themes, pulling the next set of posts automatically into view when the reader approaches the bottom of the page.
Version: 1.1
Author: Automattic
Author URI: https://automattic.com/
License: GNU General Public License v2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Text Domain: jetpack
*/

/**
 * Class: The_Neverending_Home_Page relies on add_theme_support, expects specific
 * styling from each theme; including fixed footer.
 */
class The_Neverending_Home_Page {
	/**
	* Maximum allowed number of posts per page in $_REQUEST.
	*/
	const MAX_ALLOWED_POSTS_PER_PAGE_ΙΝ_REQUEST = 5000;

	/**
	 * Register actions and filters, plus parse IS settings
	 *
	 * @uses add_action, add_filter, self::get_settings
	 */
	public function __construct() {
		add_action( 'pre_get_posts', array( $this, 'posts_per_page_query' ) );
		add_action( 'admin_init', array( $this, 'settings_api_init' ) );
		add_action( 'template_redirect', array( $this, 'action_template_redirect' ) );
		add_action( 'customize_preview_init', array( $this, 'init_customizer_assets' ) );
		add_action( 'template_redirect', array( $this, 'ajax_response' ) );
		add_action( 'custom_ajax_infinite_scroll', array( $this, 'query' ) );
		add_filter( 'infinite_scroll_query_args', array( $this, 'inject_query_args' ) );
		add_filter( 'infinite_scroll_allowed_vars', array( $this, 'allowed_query_vars' ) );
		add_action( 'the_post', array( $this, 'preserve_more_tag' ) );
		add_action( 'wp_footer', array( $this, 'footer' ) );
		add_filter( 'infinite_scroll_additional_scripts', array( $this, 'add_mejs_config' ) );

		// Plugin compatibility
		add_filter( 'grunion_contact_form_redirect_url', array( $this, 'filter_grunion_redirect_url' ) );

		// AMP compatibility
		// needs to happen after parse_query so that Jetpack_AMP_Support::is_amp_request() is ready.
		add_action( 'wp', array( $this, 'amp_load_hooks' ) );

		// Parse IS settings from theme
		self::get_settings();
	}

	/**
	 * Initialize our static variables
	 */

	/**
	 * The time.
	 *
	 * @var null - I don't think this is used?
	 */
	public static $the_time = null;

	/**
	 * Settings.
	 *
	 * Don't access directly, instead use self::get_settings().
	 *
	 * @var array
	 */
	public static $settings = null;

	/**
	 * The enabled option name.
	 *
	 * @var string
	 */
	public static $option_name_enabled = 'infinite_scroll';

	/**
	 * Parse IS settings provided by theme
	 *
	 * @uses get_theme_support, infinite_scroll_has_footer_widgets, sanitize_title, add_action, get_option, wp_parse_args, is_active_sidebar
	 * @return object
	 */
	public static function get_settings() {
		if ( self::$settings === null ) {
			$css_pattern = '#[^A-Z\d\-_]#i';

			$defaults = array(
				'type'            => 'scroll', // scroll | click
				'requested_type'  => 'scroll', // store the original type for use when logic overrides it
				'footer_widgets'  => false, // true | false | sidebar_id | array of sidebar_ids -- last two are checked with is_active_sidebar
				'container'       => 'content', // container html id
				'wrapper'         => true, // true | false | html class -- the html class.
				'render'          => false, // optional function, otherwise the `content` template part will be used
				'footer'          => true, // boolean to enable or disable the infinite footer | string to provide an html id to derive footer width from
				'footer_callback' => false, // function to be called to render the IS footer, in place of the default
				'posts_per_page'  => false, // phpcs:ignore WordPress.WP.PostsPerPage.posts_per_page_posts_per_page -- int | false to set based on IS type
				'click_handle'    => true, // boolean to enable or disable rendering the click handler div. If type is click and this is false, page must include its own trigger with the HTML ID `infinite-handle`.
			);
			$settings = $defaults;
			// Validate settings passed through add_theme_support()
			$_settings = get_theme_support( 'infinite-scroll' );

			if ( is_array( $_settings ) ) {
				// Preferred implementation, where theme provides an array of options
				if ( isset( $_settings[0] ) && is_array( $_settings[0] ) ) {
					foreach ( $_settings[0] as $key => $value ) {
						switch ( $key ) {
							case 'type':
								if ( in_array( $value, array( 'scroll', 'click' ), true ) ) {
									$settings['requested_type'] = $value;
									$settings[ $key ]           = $settings['requested_type'];
								}

								break;

							case 'footer_widgets':
								if ( is_string( $value ) ) {
									$settings[ $key ] = sanitize_title( $value );
								} elseif ( is_array( $value ) ) {
									$settings[ $key ] = array_map( 'sanitize_title', $value );
								} elseif ( is_bool( $value ) ) {
									$settings[ $key ] = $value;
								}

								break;

							case 'container':
							case 'wrapper':
								if ( 'wrapper' === $key && is_bool( $value ) ) {
									$settings[ $key ] = $value;
								} else {
									$value = preg_replace( $css_pattern, '', $value );

									if ( ! empty( $value ) ) {
										$settings[ $key ] = $value;
									}
								}

								break;

							case 'render':
								if ( false !== $value && is_callable( $value ) ) {
									$settings[ $key ] = $value;
								}

								break;

							case 'footer':
								if ( is_bool( $value ) ) {
									$settings[ $key ] = $value;
								} elseif ( is_string( $value ) ) {
									$value = preg_replace( $css_pattern, '', $value );

									if ( ! empty( $value ) ) {
										$settings[ $key ] = $value;
									}
								}

								break;

							case 'footer_callback':
								if ( is_callable( $value ) ) {
									$settings[ $key ] = $value;
								} else {
									$settings[ $key ] = false;
								}

								break;

							case 'posts_per_page':
								if ( is_numeric( $value ) ) {
									$settings[ $key ] = (int) $value;
								}

								break;

							case 'click_handle':
								if ( is_bool( $value ) ) {
									$settings[ $key ] = $value;
								}

								break;

							default:
								break;
						}
					}
				} elseif ( is_string( $_settings[0] ) ) {
					// Checks below are for backwards compatibility

					// Container to append new posts to
					$settings['container'] = preg_replace( $css_pattern, '', $_settings[0] );

					// Wrap IS elements?
					if ( isset( $_settings[1] ) ) {
						$settings['wrapper'] = (bool) $_settings[1];
					}
				}
			}

			// Always ensure all values are present in the final array
			$settings = wp_parse_args( $settings, $defaults );

			// Check if a legacy `infinite_scroll_has_footer_widgets()` function is defined and override the footer_widgets parameter's value.
			// Otherwise, if a widget area ID or array of IDs was provided in the footer_widgets parameter, check if any contains any widgets.
			// It is safe to use `is_active_sidebar()` before the sidebar is registered as this function doesn't check for a sidebar's existence when determining if it contains any widgets.
			if ( function_exists( 'infinite_scroll_has_footer_widgets' ) ) {
				$settings['footer_widgets'] = (bool) infinite_scroll_has_footer_widgets();
			} elseif ( is_array( $settings['footer_widgets'] ) ) {
				$sidebar_ids                = $settings['footer_widgets'];
				$settings['footer_widgets'] = false;

				foreach ( $sidebar_ids as $sidebar_id ) {
					if ( is_active_sidebar( $sidebar_id ) ) {
						$settings['footer_widgets'] = true;
						break;
					}
				}

				unset( $sidebar_ids );
				unset( $sidebar_id );
			} elseif ( is_string( $settings['footer_widgets'] ) ) {
				$settings['footer_widgets'] = (bool) is_active_sidebar( $settings['footer_widgets'] );
			}

			/**
			 * Filter Infinite Scroll's `footer_widgets` parameter.
			 *
			 * @module infinite-scroll
			 *
			 * @since 2.0.0
			 *
			 * @param bool $settings['footer_widgets'] Does the current theme have Footer Widgets.
			 */
			$settings['footer_widgets'] = apply_filters( 'infinite_scroll_has_footer_widgets', $settings['footer_widgets'] );

			// Finally, after all of the sidebar checks and filtering, ensure that a boolean value is present, otherwise set to default of `false`.
			if ( ! is_bool( $settings['footer_widgets'] ) ) {
				$settings['footer_widgets'] = false;
			}

			// Ensure that IS is enabled and no footer widgets exist if the IS type isn't already "click".
			if ( 'click' !== $settings['type'] ) {
				// Check the setting status
				$disabled = '' === get_option( self::$option_name_enabled ) ? true : false;

				// Footer content or Reading option check
				if ( $settings['footer_widgets'] || $disabled ) {
					$settings['type'] = 'click';
				}
			}

			// Force display of the click handler and attendant bits when the type isn't `click`
			if ( 'click' !== $settings['type'] ) {
				$settings['click_handle'] = true;
			}

			// Store final settings in a class static to avoid reparsing
			/**
			 * Filter the array of Infinite Scroll settings.
			 *
			 * @module infinite-scroll
			 *
			 * @since 2.0.0
			 *
			 * @param array $settings Array of Infinite Scroll settings.
			 */
			self::$settings = apply_filters( 'infinite_scroll_settings', $settings );
		}

		/** This filter is already documented in modules/infinite-scroll/infinity.php */
		return (object) apply_filters( 'infinite_scroll_settings', self::$settings );
	}

	/**
	 * Number of posts per page.
	 *
	 * @uses self::wp_query, self::get_settings, apply_filters
	 * @return int
	 */
	public static function posts_per_page() {
		$posts_per_page             = self::get_settings()->posts_per_page ? self::get_settings()->posts_per_page : self::wp_query()->get( 'posts_per_page' );
		$posts_per_page_core_option = get_option( 'posts_per_page' );

		// If Infinite Scroll is set to click, and if the site owner changed posts_per_page, let's use that.
		if (
			'click' === self::get_settings()->type
				&& ( '10' !== $posts_per_page_core_option )
		) {
			$posts_per_page = $posts_per_page_core_option;
		}

		// Take JS query into consideration here.
		$posts_per_page_in_request = isset( $_REQUEST['query_args']['posts_per_page'] ) ? (int) $_REQUEST['query_args']['posts_per_page'] : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( $posts_per_page_in_request > 0 &&
			self::MAX_ALLOWED_POSTS_PER_PAGE_ΙΝ_REQUEST >= $posts_per_page_in_request
		) {
			$posts_per_page = $posts_per_page_in_request;
		}

		/**
		 * Filter the number of posts per page.
		 *
		 * @module infinite-scroll
		 *
		 * @since 6.0.0
		 *
		 * @param int $posts_per_page The number of posts to display per page.
		 */
		return (int) apply_filters( 'infinite_scroll_posts_per_page', $posts_per_page );
	}

	/**
	 * Retrieve the query used with Infinite Scroll
	 *
	 * @global $wp_the_query
	 * @uses apply_filters
	 * @return object
	 */
	public static function wp_query() {
		global $wp_the_query;
		/**
		 * Filter the Infinite Scroll query object.
		 *
		 * @module infinite-scroll
		 *
		 * @since 2.2.1
		 *
		 * @param WP_Query $wp_the_query WP Query.
		 */
		return apply_filters( 'infinite_scroll_query_object', $wp_the_query );
	}

	/**
	 * Has infinite scroll been triggered?
	 */
	public static function got_infinity() {
		/**
		 * Filter the parameter used to check if Infinite Scroll has been triggered.
		 *
		 * @module infinite-scroll
		 *
		 * @since 3.9.0
		 *
		 * @param bool isset( $_GET[ 'infinity' ] ) Return true if the "infinity" parameter is set.
		 */
		return apply_filters( 'infinite_scroll_got_infinity', isset( $_GET['infinity'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no changes made to the site.
	}

	/**
	 * Is this guaranteed to be the last batch of posts?
	 */
	public static function is_last_batch() {
		/**
		 * Override whether or not this is the last batch for a request
		 *
		 * @module infinite-scroll
		 *
		 * @since 4.8.0
		 *
		 * @param bool|null null                 Bool if value should be overridden, null to determine from query
		 * @param object    self::wp_query()     WP_Query object for current request
		 * @param object    self::get_settings() Infinite Scroll settings
		 */
		$override = apply_filters( 'infinite_scroll_is_last_batch', null, self::wp_query(), self::get_settings() ); // phpcs:ignore WordPress.WP.ClassNameCase.Incorrect -- False positive.
		if ( is_bool( $override ) ) {
			return $override;
		}

		$entries        = (int) self::wp_query()->found_posts;
		$posts_per_page = self::posts_per_page();

		// This is to cope with an issue in certain themes or setups where posts are returned but found_posts is 0.
		if ( 0 === $entries ) {
			return (bool) ( count( self::wp_query()->posts ) < $posts_per_page );
		}
		$paged = max( 1, self::wp_query()->get( 'paged' ) );

		// Are there enough posts for more than the first page?
		if ( $entries <= $posts_per_page ) {
			return true;
		}

		// Calculate entries left after a certain number of pages
		if ( $paged && $paged > 1 ) {
			$entries -= $posts_per_page * $paged;
		}

		// Are there some entries left to display?
		return $entries <= 0;
	}

	/**
	 * The more tag will be ignored by default if the blog page isn't our homepage.
	 * Let's force the $more global to false.
	 *
	 * @param array $array - the_post array.
	 * @return array
	 */
	public function preserve_more_tag( $array ) {
		global $more;

		if ( self::got_infinity() ) {
			$more = 0; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- 0 = show content up to the more tag. Add more link.
		}

		return $array;
	}

	/**
	 * Add a checkbox field to Settings > Reading
	 * for enabling infinite scroll.
	 *
	 * Only show if the current theme supports infinity.
	 *
	 * @uses current_theme_supports, add_settings_field, __, register_setting
	 * @action admin_init
	 * @return null
	 */
	public function settings_api_init() {
		if ( ! current_theme_supports( 'infinite-scroll' ) ) {
			return;
		}

		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			// This setting is no longer configurable in wp-admin on WordPress.com -- leave a pointer
			add_settings_field(
				self::$option_name_enabled,
				'<span id="infinite-scroll-options">' . esc_html__( 'Infinite Scroll Behavior', 'jetpack' ) . '</span>',
				array( $this, 'infinite_setting_html_calypso_placeholder' ),
				'reading'
			);
			return;
		}

		// Add the setting field [infinite_scroll] and place it in Settings > Reading
		add_settings_field( self::$option_name_enabled, '<span id="infinite-scroll-options">' . esc_html__( 'Infinite Scroll Behavior', 'jetpack' ) . '</span>', array( $this, 'infinite_setting_html' ), 'reading' );
		register_setting( 'reading', self::$option_name_enabled, 'esc_attr' );
	}

	/**
	 * Render the redirect link to the infinite scroll settings in Calypso.
	 */
	public function infinite_setting_html_calypso_placeholder() {
		$details     = get_blog_details();
		$writing_url = Redirect::get_url( 'calypso-settings-writing', array( 'site' => $details->domain ) );
		echo '<span>' . sprintf(
			/* translators: Variables are the enclosing link to the settings page */
			esc_html__( 'This option has moved. You can now manage it %1$shere%2$s.', 'jetpack' ),
			'<a href="' . esc_url( $writing_url ) . '">',
			'</a>'
		) . '</span>';
	}

	/**
	 * HTML code to display a checkbox true/false option
	 * for the infinite_scroll setting.
	 */
	public function infinite_setting_html() {

		// If the blog has footer widgets, show a notice instead of the checkbox
		if ( self::get_settings()->footer_widgets || 'click' === self::get_settings()->requested_type ) {
			echo '<label><em>' . esc_html__( 'We&rsquo;ve changed this option to a click-to-scroll version for you since you have footer widgets in Appearance &rarr; Widgets, or your theme uses click-to-scroll as the default behavior.', 'jetpack' ) . '</em></label>';
		} else {
			echo '<label><input name="infinite_scroll" type="checkbox" value="1" ' . checked( 1, '' !== get_option( self::$option_name_enabled ), false ) . ' /> ' . esc_html__( 'Check to load posts as you scroll. Uncheck to show clickable button to load posts', 'jetpack' ) . '</label>';
			// translators: the number of posts to show on each page load.
			echo '<p class="description">' . esc_html( sprintf( _n( 'Shows %s post on each load.', 'Shows %s posts on each load.', self::posts_per_page(), 'jetpack' ), number_format_i18n( self::posts_per_page() ) ) ) . '</p>';
		}
	}

	/**
	 * Does the legwork to determine whether the feature is enabled.
	 *
	 * @uses current_theme_supports, self::archive_supports_infinity, self::get_settings, add_filter, wp_enqueue_script, plugins_url, wp_enqueue_style, add_action
	 * @action template_redirect
	 * @return null
	 */
	public function action_template_redirect() {
		// Check that we support infinite scroll, and are on the home page.
		if ( ! current_theme_supports( 'infinite-scroll' ) || ! self::archive_supports_infinity() ) {
			return;
		}

		$id = self::get_settings()->container;

		// Check that we have an id.
		if ( empty( $id ) ) {
			return;
		}

		// AMP infinite scroll functionality will start on amp_load_hooks().
		if ( class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() ) {
			return;
		}

		// Add our scripts.
		wp_register_script(
			'the-neverending-homepage',
			Assets::get_file_url_for_environment(
				'_inc/build/infinite-scroll/infinity.min.js',
				'modules/infinite-scroll/infinity.js'
			),
			array(),
			JETPACK__VERSION . '-is5.0.1', // Added for ability to cachebust on WP.com.
			true
		);

		// Add our default styles.
		wp_register_style( 'the-neverending-homepage', plugins_url( 'infinity.css', __FILE__ ), array(), '20140422' );

		// Make sure there are enough posts for IS
		if ( self::is_last_batch() ) {
			return;
		}

		// Add our scripts.
		wp_enqueue_script( 'the-neverending-homepage' );

		// Add our default styles.
		wp_enqueue_style( 'the-neverending-homepage' );

		add_action( 'wp_footer', array( $this, 'action_wp_footer_settings' ), 2 );

		add_action( 'wp_footer', array( $this, 'action_wp_footer' ), 21 ); // Core prints footer scripts at priority 20, so we just need to be one later than that

		add_filter( 'infinite_scroll_results', array( $this, 'filter_infinite_scroll_results' ), 10, 3 );
	}

	/**
	 * Initialize the Customizer logic separately from the main JS.
	 *
	 * @since 8.4.0
	 */
	public function init_customizer_assets() {
		// Add our scripts.
		wp_register_script(
			'the-neverending-homepage-customizer',
			Assets::get_file_url_for_environment(
				'_inc/build/infinite-scroll/infinity-customizer.min.js',
				'modules/infinite-scroll/infinity-customizer.js'
			),
			array( 'jquery', 'customize-base' ),
			JETPACK__VERSION . '-is5.0.0', // Added for ability to cachebust on WP.com.
			true
		);

		wp_enqueue_script( 'the-neverending-homepage-customizer' );
	}

	/**
	 * Returns classes to be added to <body>. If it's enabled, 'infinite-scroll'. If set to continuous scroll, adds 'neverending' too.
	 *
	 * @since 4.7.0 No longer added as a 'body_class' filter but passed to JS environment and added using JS.
	 *
	 * @return string
	 */
	public function body_class() {
		$classes = '';
		// Do not add infinity-scroll class if disabled through the Reading page
		$disabled = '' === get_option( self::$option_name_enabled ) ? true : false;
		if ( ! $disabled || 'click' === self::get_settings()->type ) {
			$classes = 'infinite-scroll';

			if ( 'scroll' === self::get_settings()->type ) {
				$classes .= ' neverending';
			}
		}

		return $classes;
	}

	/**
	 * In case IS is activated on search page, we have to exclude initially loaded posts which match the keyword by title, not the content as they are displayed before content-matching ones
	 *
	 * @uses self::wp_query
	 * @uses self::get_last_post_date
	 * @uses self::has_only_title_matching_posts
	 * @return array
	 */
	public function get_excluded_posts() {

		$excluded_posts = array();
		// loop through posts returned by wp_query call
		foreach ( self::wp_query()->get_posts() as $post ) {

			$orderby   = isset( self::wp_query()->query_vars['orderby'] ) ? self::wp_query()->query_vars['orderby'] : '';
			$post_date = ( ! empty( $post->post_date ) ? $post->post_date : false );
			if ( 'modified' === $orderby || false === $post_date ) {
				$post_date = $post->post_modified;
			}

			// in case all posts initially displayed match the keyword by title we add em all to excluded posts array
			// else, we add only posts which are older than last_post_date param as newer are natually excluded by last_post_date condition in the SQL query
			if ( self::has_only_title_matching_posts() || $post_date <= self::get_last_post_date() ) {
				array_push( $excluded_posts, $post->ID );
			}
		}
		return $excluded_posts;
	}

	/**
	 * In case IS is active on search, we have to exclude posts matched by title rather than by post_content in order to prevent dupes on next pages
	 *
	 * @uses self::wp_query
	 * @uses self::get_excluded_posts
	 * @return array
	 */
	public function get_query_vars() {

		$query_vars = self::wp_query()->query_vars;
		// applies to search page only
		if ( true === self::wp_query()->is_search() ) {
			// set post__not_in array in query_vars in case it does not exists
			if ( false === isset( $query_vars['post__not_in'] ) ) {
				$query_vars['post__not_in'] = array();
			}
			// get excluded posts
			$excluded = self::get_excluded_posts();
			// merge them with other post__not_in posts (eg.: sticky posts)
			$query_vars['post__not_in'] = array_merge( $query_vars['post__not_in'], $excluded );
		}
		return $query_vars;
	}

	/**
	 * This function checks whether all posts returned by initial wp_query match the keyword by title
	 * The code used in this function is borrowed from WP_Query class where it is used to construct like conditions for keywords
	 *
	 * @uses self::wp_query
	 * @return bool
	 */
	public function has_only_title_matching_posts() {

		// apply following logic for search page results only
		if ( false === self::wp_query()->is_search() ) {
			return false;
		}

		// grab the last posts in the stack as if the last one is title-matching the rest is title-matching as well
		$post = end( self::wp_query()->posts );

		// code inspired by WP_Query class
		if ( preg_match_all( '/".*?("|$)|((?<=[\t ",+])|^)[^\t ",+]+/', self::wp_query()->get( 's' ), $matches ) ) {
			$search_terms = self::wp_query()->query_vars['search_terms'];
			// if the search string has only short terms or stopwords, or is 10+ terms long, match it as sentence
			if ( empty( $search_terms ) || count( $search_terms ) > 9 ) {
				$search_terms = array( self::wp_query()->get( 's' ) );
			}
		} else {
			$search_terms = array( self::wp_query()->get( 's' ) );
		}

		// actual testing. As search query combines multiple keywords with AND, it's enough to check if any of the keywords is present in the title
		$term = current( $search_terms );
		if ( ! empty( $term ) && false !== strpos( $post->post_title, $term ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Grab the timestamp for the initial query's last post.
	 *
	 * This takes into account the query's 'orderby' parameter and returns
	 * false if the posts are not ordered by date.
	 *
	 * @uses self::got_infinity
	 * @uses self::has_only_title_matching_posts
	 * @uses self::wp_query
	 * @return string 'Y-m-d H:i:s' or false
	 */
	public function get_last_post_date() {
		if ( self::got_infinity() ) {
			return;
		}

		if ( ! self::wp_query()->have_posts() ) {
			return null;
		}

		// In case there are only title-matching posts in the initial WP_Query result, we don't want to use the last_post_date param yet
		if ( true === self::has_only_title_matching_posts() ) {
			return false;
		}

		$post      = end( self::wp_query()->posts );
		$orderby   = isset( self::wp_query()->query_vars['orderby'] ) ?
			self::wp_query()->query_vars['orderby'] : '';
		$post_date = ( ! empty( $post->post_date ) ? $post->post_date : false );
		switch ( $orderby ) {
			case 'modified':
				return $post->post_modified;
			case 'date':
			case '':
				return $post_date;
			default:
				return false;
		}
	}

	/**
	 * Returns the appropriate `wp_posts` table field for a given query's
	 * 'orderby' parameter, if applicable.
	 *
	 * @param object $query - an optional query object.
	 * @uses self::wp_query
	 * @return string or false
	 */
	public function get_query_sort_field( $query = null ) {
		if ( empty( $query ) ) {
			$query = self::wp_query();
		}

		$orderby = isset( $query->query_vars['orderby'] ) ? $query->query_vars['orderby'] : '';

		switch ( $orderby ) {
			case 'modified':
				return 'post_modified';
			case 'date':
			case '':
				return 'post_date';
			default:
				return false;
		}
	}

	/**
	 * Create a where clause that will make sure post queries return posts
	 * in the correct order, without duplicates, if a new post is added
	 * and we're sorting by post date.
	 *
	 * @global $wpdb
	 * @param string $where - the where clause.
	 * @param object $query - the query.
	 * @uses apply_filters
	 * @filter posts_where
	 * @return string
	 */
	public function query_time_filter( $where, $query ) {
		if ( self::got_infinity() ) {
			global $wpdb;

			$sort_field = self::get_query_sort_field( $query );

			if ( 'post_date' !== $sort_field || 'DESC' !== $_REQUEST['query_args']['order'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- no changes made to the site.
				return $where;
			}

			$query_before = sanitize_text_field( wp_unslash( $_REQUEST['query_before'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- no changes made to the site.

			if ( empty( $query_before ) ) {
				return $where;
			}

			// Construct the date query using our timestamp
			$clause = $wpdb->prepare( " AND {$wpdb->posts}.post_date <= %s", $query_before );

			/**
			 * Filter Infinite Scroll's SQL date query making sure post queries
			 * will always return results prior to (descending sort)
			 * or before (ascending sort) the last post date.
			 *
			 * @module infinite-scroll
			 *
			 * @param string $clause SQL Date query.
			 * @param object $query Query.
			 * @param string $operator @deprecated Query operator.
			 * @param string $last_post_date @deprecated Last Post Date timestamp.
			 */
			$operator       = 'ASC' === $_REQUEST['query_args']['order'] ? '>' : '<'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- no changes to the site.
			$last_post_date = sanitize_text_field( wp_unslash( $_REQUEST['last_post_date'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- no changes to the site.
			$where         .= apply_filters( 'infinite_scroll_posts_where', $clause, $query, $operator, $last_post_date );
		}

		return $where;
	}

	/**
	 * Let's overwrite the default post_per_page setting to always display a fixed amount.
	 *
	 * @param object $query - the query.
	 * @uses is_admin, self::archive_supports_infinity, self::get_settings
	 */
	public function posts_per_page_query( $query ) {
		if ( ! is_admin() && self::archive_supports_infinity() && $query->is_main_query() ) {
			$query->set( 'posts_per_page', self::posts_per_page() );
		}
	}

	/**
	 * Check if the IS output should be wrapped in a div.
	 * Setting value can be a boolean or a string specifying the class applied to the div.
	 *
	 * @uses self::get_settings
	 * @return bool
	 */
	public function has_wrapper() {
		return (bool) self::get_settings()->wrapper;
	}

	/**
	 * Returns the Ajax url
	 *
	 * @global $wp
	 * @uses home_url, add_query_arg, apply_filters
	 * @return string
	 */
	public function ajax_url() {
		$base_url = set_url_scheme( home_url( '/' ) );

		$ajaxurl = add_query_arg( array( 'infinity' => 'scrolling' ), $base_url );

		/**
		 * Filter the Infinite Scroll Ajax URL.
		 *
		 * @module infinite-scroll
		 *
		 * @since 2.0.0
		 *
		 * @param string $ajaxurl Infinite Scroll Ajax URL.
		 */
		return apply_filters( 'infinite_scroll_ajax_url', $ajaxurl );
	}

	/**
	 * Our own Ajax response, avoiding calling admin-ajax
	 */
	public function ajax_response() {
		// Only proceed if the url query has a key of "Infinity"
		if ( ! self::got_infinity() ) {
			return false;
		}

		// This should already be defined below, but make sure.
		if ( ! defined( 'DOING_AJAX' ) ) {
			define( 'DOING_AJAX', true );
		}

		@header( 'Content-Type: text/html; charset=' . get_option( 'blog_charset' ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		send_nosniff_header();

		/**
		 * Fires at the end of the Infinite Scroll Ajax response.
		 *
		 * @module infinite-scroll
		 *
		 * @since 2.0.0
		 */
		do_action( 'custom_ajax_infinite_scroll' );
		die( '0' );
	}

	/**
	 * Alias for renamed class method.
	 *
	 * Previously, JS settings object was unnecessarily output in the document head.
	 * When the hook was changed, the method name no longer made sense.
	 */
	public function action_wp_head() {
		$this->action_wp_footer_settings();
	}

	/**
	 * Prints the relevant infinite scroll settings in JS.
	 *
	 * @global $wp_rewrite
	 * @uses self::get_settings, esc_js, esc_url_raw, self::has_wrapper, __, apply_filters, do_action, self::get_query_vars
	 * @action wp_footer
	 */
	public function action_wp_footer_settings() {
		global $wp_rewrite;
		global $currentday;

		// Default click handle text
		$click_handle_text = __( 'Older posts', 'jetpack' );

		// If a single CPT is displayed, use its plural name instead of "posts"
		// Could be empty (posts) or an array of multiple post types.
		// In the latter two cases cases, the default text is used, leaving the `infinite_scroll_js_settings` filter for further customization.
		$post_type = self::wp_query()->get( 'post_type' );

		// If it's a taxonomy, try to change the button text.
		if ( is_tax() ) {
			// Get current taxonomy slug.
			$taxonomy_slug = self::wp_query()->get( 'taxonomy' );

			// Get taxonomy settings.
			$taxonomy = get_taxonomy( $taxonomy_slug );

			// Check if the taxonomy is attached to one post type only and use its plural name.
			// If not, use "Posts" without confusing the users.
			if (
				is_a( $taxonomy, 'WP_Taxonomy' )
				&& is_countable( $taxonomy->object_type )
				&& count( $taxonomy->object_type ) < 2
			) {
				$post_type = $taxonomy->object_type[0];
			}
		}

		if ( is_string( $post_type ) && ! empty( $post_type ) ) {
			$post_type = get_post_type_object( $post_type );

			if ( is_object( $post_type ) && ! is_wp_error( $post_type ) ) {
				if ( isset( $post_type->labels->name ) ) {
					$cpt_text = $post_type->labels->name;
				} elseif ( isset( $post_type->label ) ) {
					$cpt_text = $post_type->label;
				}

				if ( isset( $cpt_text ) ) {
					/* translators: %s is the name of a custom post type */
					$click_handle_text = sprintf( __( 'More %s', 'jetpack' ), $cpt_text );
					unset( $cpt_text );
				}
			}
		}

		unset( $post_type );

		// Base JS settings
		$js_settings = array(
			'id'               => self::get_settings()->container,
			'ajaxurl'          => esc_url_raw( self::ajax_url() ),
			'type'             => esc_js( self::get_settings()->type ),
			'wrapper'          => self::has_wrapper(),
			'wrapper_class'    => is_string( self::get_settings()->wrapper ) ? esc_js( self::get_settings()->wrapper ) : 'infinite-wrap',
			'footer'           => is_string( self::get_settings()->footer ) ? esc_js( self::get_settings()->footer ) : self::get_settings()->footer,
			'click_handle'     => esc_js( self::get_settings()->click_handle ),
			'text'             => esc_js( $click_handle_text ),
			'totop'            => esc_js( __( 'Scroll back to top', 'jetpack' ) ),
			'currentday'       => $currentday,
			'order'            => 'DESC',
			'scripts'          => array(),
			'styles'           => array(),
			'google_analytics' => false,
			'offset'           => max( 1, self::wp_query()->get( 'paged' ) ), // Pass through the current page so we can use that to offset the first load.
			'history'          => array(
				'host'                 => preg_replace( '#^http(s)?://#i', '', untrailingslashit( esc_url( get_home_url() ) ) ),
				'path'                 => self::get_request_path(),
				'use_trailing_slashes' => $wp_rewrite->use_trailing_slashes,
				'parameters'           => self::get_request_parameters(),
			),
			'query_args'       => self::get_query_vars(),
			'query_before'     => current_time( 'mysql' ),
			'last_post_date'   => self::get_last_post_date(),
			'body_class'       => self::body_class(),
			'loading_text'     => esc_js( __( 'Loading new page', 'jetpack' ) ),
		);

		// Optional order param
		if ( isset( $_REQUEST['order'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no changes made to the site.
			$order = strtoupper( sanitize_text_field( wp_unslash( $_REQUEST['order'] ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no changes made to the site.

			if ( in_array( $order, array( 'ASC', 'DESC' ), true ) ) {
				$js_settings['order'] = $order;
			}
		}

		/**
		 * Filter the Infinite Scroll JS settings outputted in the head.
		 *
		 * @module infinite-scroll
		 *
		 * @since 2.0.0
		 *
		 * @param array $js_settings Infinite Scroll JS settings.
		 */
		$js_settings = apply_filters( 'infinite_scroll_js_settings', $js_settings );

		/**
		 * Fires before Infinite Scroll outputs inline JavaScript in the head.
		 *
		 * @module infinite-scroll
		 *
		 * @since 2.0.0
		 */
		do_action( 'infinite_scroll_wp_head' );

		?>
		<script type="text/javascript">
		var infiniteScroll = <?php echo wp_json_encode( array( 'settings' => $js_settings ), JSON_HEX_TAG ); ?>;
		</script>
		<?php
	}

	// phpcs:disable WordPress.WP.GlobalVariablesOverride.Prohibited

	/**
	 * Build path data for current request.
	 * Used for Google Analytics and pushState history tracking.
	 *
	 * @global $wp_rewrite
	 * @global $wp
	 * @uses user_trailingslashit, sanitize_text_field, add_query_arg
	 * @return string|bool
	 */
	private function get_request_path() {
		global $wp_rewrite;

		if ( $wp_rewrite->using_permalinks() ) {
			global $wp;

			// If called too early, bail
			if ( ! isset( $wp->request ) ) {
				return false;
			}

			// Determine path for paginated version of current request
			if ( preg_match( '#' . preg_quote( $wp_rewrite->pagination_base, '#' ) . '/\d+/?$#i', $wp->request ) ) {
				$path = preg_replace( '#' . preg_quote( $wp_rewrite->pagination_base, '#' ) . '/\d+$#i', $wp_rewrite->pagination_base . '/%d', $wp->request );
			} else {
				$path = $wp->request . '/' . $wp_rewrite->pagination_base . '/%d';
			}

			// Slashes everywhere we need them
			if ( 0 !== strpos( $path, '/' ) ) {
				$path = '/' . $path;
			}

			$path = user_trailingslashit( $path );
		} else {
			// Clean up raw $_REQUEST input
			$path = array_map( 'sanitize_text_field', wp_unslash( $_REQUEST ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- seems this is used for Google Analytics and browser history tracking.
			$path = array_filter( $path );

			$path['paged'] = '%d';

			$path = add_query_arg( $path, '/' );
		}

		return empty( $path ) ? false : $path;
	}

	/**
	 * Return query string for current request, prefixed with '?'.
	 *
	 * @return string
	 */
	private function get_request_parameters() {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$uri = preg_replace( '/^[^?]*(\?.*$)/', '$1', $uri, 1, $count );
		if ( $count !== 1 ) {
			return '';
		}
		return $uri;
	}

	/**
	 * Provide IS with a list of the scripts and stylesheets already present on the page.
	 * Since posts may contain require additional assets that haven't been loaded, this data will be used to track the additional assets.
	 *
	 * @global $wp_scripts, $wp_styles
	 * @action wp_footer
	 */
	public function action_wp_footer() {
		global $wp_scripts, $wp_styles;

		$scripts = is_a( $wp_scripts, 'WP_Scripts' ) ? $wp_scripts->done : array();
		/**
		 * Filter the list of scripts already present on the page.
		 *
		 * @module infinite-scroll
		 *
		 * @since 2.1.2
		 *
		 * @param array $scripts Array of scripts present on the page.
		 */
		$scripts = apply_filters( 'infinite_scroll_existing_scripts', $scripts );

		$styles = is_a( $wp_styles, 'WP_Styles' ) ? $wp_styles->done : array();
		/**
		 * Filter the list of styles already present on the page.
		 *
		 * @module infinite-scroll
		 *
		 * @since 2.1.2
		 *
		 * @param array $styles Array of styles present on the page.
		 */
		$styles = apply_filters( 'infinite_scroll_existing_stylesheets', $styles );

		?>
		<script type="text/javascript">
			(function() {
				var extend = function(out) {
					out = out || {};

					for (var i = 1; i < arguments.length; i++) {
						if (!arguments[i])
						continue;

						for (var key in arguments[i]) {
						if (arguments[i].hasOwnProperty(key))
							out[key] = arguments[i][key];
						}
					}

					return out;
				};
				extend( window.infiniteScroll.settings.scripts, <?php echo wp_json_encode( $scripts ); ?> );
				extend( window.infiniteScroll.settings.styles, <?php echo wp_json_encode( $styles ); ?> );
			})();
		</script>
		<?php
		$aria_live = 'assertive';
		if ( 'scroll' === self::get_settings()->type ) {
			$aria_live = 'polite';
		}
		?>
		<span id="infinite-aria" aria-live="<?php echo esc_attr( $aria_live ); ?>"></span>
		<?php
	}

	/**
	 * Identify additional scripts required by the latest set of IS posts and provide the necessary data to the IS response handler.
	 *
	 * @param array $results - the results.
	 * @param array $query_args - Array of Query arguments.
	 * @param array $wp_query - the WP query.
	 * @global $wp_scripts
	 * @uses sanitize_text_field, add_query_arg
	 * @filter infinite_scroll_results
	 * @return array
	 */
	public function filter_infinite_scroll_results( $results, $query_args, $wp_query ) {
		// Don't bother unless there are posts to display
		if ( 'success' !== $results['type'] ) {
			return $results;
		}

		// Parse and sanitize the script handles already output
		$initial_scripts = isset( $_REQUEST['scripts'] ) && is_array( $_REQUEST['scripts'] ) ? array_map( 'sanitize_text_field', wp_unslash( $_REQUEST['scripts'] ) ) : false; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no site changes made.

		if ( is_array( $initial_scripts ) ) {
			global $wp_scripts;

			// Identify new scripts needed by the latest set of IS posts
			$new_scripts = array_filter(
				$wp_scripts->done,
				function ( $script_name ) use ( $initial_scripts ) {
					// Jetpack block scripts should always be sent, even if they've been
					// sent before. These scripts only run once on when loaded, they don't
					// watch for new blocks being added.
					if ( 0 === strpos( $script_name, 'jetpack-block-' ) ) {
						return true;
					}

					return ! in_array( $script_name, $initial_scripts, true );
				}
			);

			// If new scripts are needed, extract relevant data from $wp_scripts
			if ( ! empty( $new_scripts ) ) {
				$results['scripts'] = array();

				foreach ( $new_scripts as $handle ) {
					// Abort if somehow the handle doesn't correspond to a registered script
					// or if the script doesn't have `src` set.
					$script_not_registered = ! isset( $wp_scripts->registered[ $handle ] );
					$empty_src             = empty( $wp_scripts->registered[ $handle ]->src );
					if ( $script_not_registered || $empty_src ) {
						continue;
					}

					// Provide basic script data
					$script_data = array(
						'handle'        => $handle,
						'footer'        => ( is_array( $wp_scripts->in_footer ) && in_array( $handle, $wp_scripts->in_footer, true ) ),
						'extra_data'    => $wp_scripts->print_extra_script( $handle, false ),
						'before_handle' => $wp_scripts->print_inline_script( $handle, 'before', false ),
						'after_handle'  => $wp_scripts->print_inline_script( $handle, 'after', false ),
					);

					// Base source
					$src = $wp_scripts->registered[ $handle ]->src;

					// Take base_url into account
					if ( strpos( $src, 'http' ) !== 0 ) {
						$src = $wp_scripts->base_url . $src;
					}

					// Version and additional arguments
					if ( null === $wp_scripts->registered[ $handle ]->ver ) {
						$ver = '';
					} else {
						$ver = $wp_scripts->registered[ $handle ]->ver ? $wp_scripts->registered[ $handle ]->ver : $wp_scripts->default_version;
					}

					if ( isset( $wp_scripts->args[ $handle ] ) ) {
						$ver = $ver ? $ver . '&amp;' . $wp_scripts->args[ $handle ] : $wp_scripts->args[ $handle ];
					}

					// Full script source with version info
					$script_data['src'] = add_query_arg( 'ver', $ver, $src );

					// Add script to data that will be returned to IS JS
					array_push( $results['scripts'], $script_data );
				}
			}
		}

		// Expose additional script data to filters, but only include in final `$results` array if needed.
		if ( ! isset( $results['scripts'] ) ) {
			$results['scripts'] = array();
		}

		/**
		 * Filter the additional scripts required by the latest set of IS posts.
		 *
		 * @module infinite-scroll
		 *
		 * @since 2.1.2
		 *
		 * @param array $results['scripts'] Additional scripts required by the latest set of IS posts.
		 * @param array|bool $initial_scripts Set of scripts loaded on each page.
		 * @param array $results Array of Infinite Scroll results.
		 * @param array $query_args Array of Query arguments.
		 * @param WP_Query $wp_query WP Query.
		 */
		$results['scripts'] = apply_filters(
			'infinite_scroll_additional_scripts',
			$results['scripts'],
			$initial_scripts,
			$results,
			$query_args,
			$wp_query
		);

		if ( empty( $results['scripts'] ) ) {
			unset( $results['scripts'] );
		}

		// Parse and sanitize the style handles already output
		$initial_styles = isset( $_REQUEST['styles'] ) && is_array( $_REQUEST['styles'] ) ? array_map( 'sanitize_text_field', wp_unslash( $_REQUEST['styles'] ) ) : false; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		if ( is_array( $initial_styles ) ) {
			global $wp_styles;

			// Identify new styles needed by the latest set of IS posts
			$new_styles = array_diff( $wp_styles->done, $initial_styles );

			// If new styles are needed, extract relevant data from $wp_styles
			if ( ! empty( $new_styles ) ) {
				$results['styles'] = array();

				foreach ( $new_styles as $handle ) {
					// Abort if somehow the handle doesn't correspond to a registered stylesheet
					if ( ! isset( $wp_styles->registered[ $handle ] ) ) {
						continue;
					}

					// Provide basic style data
					$style_data = array(
						'handle' => $handle,
						'media'  => 'all',
					);

					// Base source
					$src = $wp_styles->registered[ $handle ]->src;

					// Take base_url into account
					if ( strpos( $src, 'http' ) !== 0 ) {
						$src = $wp_styles->base_url . $src;
					}

					// Version and additional arguments
					if ( null === $wp_styles->registered[ $handle ]->ver ) {
						$ver = '';
					} else {
						$ver = $wp_styles->registered[ $handle ]->ver ? $wp_styles->registered[ $handle ]->ver : $wp_styles->default_version;
					}

					if ( isset( $wp_styles->args[ $handle ] ) ) {
						$ver = $ver ? $ver . '&amp;' . $wp_styles->args[ $handle ] : $wp_styles->args[ $handle ];
					}

					// Full stylesheet source with version info
					$style_data['src'] = add_query_arg( 'ver', $ver, $src );

					// Parse stylesheet's conditional comments if present, converting to logic executable in JS
					if ( isset( $wp_styles->registered[ $handle ]->extra['conditional'] ) && $wp_styles->registered[ $handle ]->extra['conditional'] ) {
						// First, convert conditional comment operators to standard logical operators. %ver is replaced in JS with the IE version
						$style_data['conditional'] = str_replace(
							array(
								'lte',
								'lt',
								'gte',
								'gt',
							),
							array(
								'%ver <=',
								'%ver <',
								'%ver >=',
								'%ver >',
							),
							$wp_styles->registered[ $handle ]->extra['conditional']
						);

						// Next, replace any !IE checks. These shouldn't be present since WP's conditional stylesheet implementation doesn't support them, but someone could be _doing_it_wrong().
						$style_data['conditional'] = preg_replace( '#!\s*IE(\s*\d+){0}#i', '1==2', $style_data['conditional'] );

						// Lastly, remove the IE strings
						$style_data['conditional'] = str_replace( 'IE', '', $style_data['conditional'] );
					}

					// Parse requested media context for stylesheet
					if ( isset( $wp_styles->registered[ $handle ]->args ) ) {
						$style_data['media'] = esc_attr( $wp_styles->registered[ $handle ]->args );
					}

					// Add stylesheet to data that will be returned to IS JS
					array_push( $results['styles'], $style_data );
				}
			}
		}

		// Expose additional stylesheet data to filters, but only include in final `$results` array if needed.
		if ( ! isset( $results['styles'] ) ) {
			$results['styles'] = array();
		}

		/**
		 * Filter the additional styles required by the latest set of IS posts.
		 *
		 * @module infinite-scroll
		 *
		 * @since 2.1.2
		 *
		 * @param array $results['styles'] Additional styles required by the latest set of IS posts.
		 * @param array|bool $initial_styles Set of styles loaded on each page.
		 * @param array $results Array of Infinite Scroll results.
		 * @param array $query_args Array of Query arguments.
		 * @param WP_Query $wp_query WP Query.
		 */
		$results['styles'] = apply_filters(
			'infinite_scroll_additional_stylesheets',
			$results['styles'],
			$initial_styles,
			$results,
			$query_args,
			$wp_query
		);

		if ( empty( $results['styles'] ) ) {
			unset( $results['styles'] );
		}

		// Lastly, return the IS results array
		return $results;
	}

	/**
	 * Runs the query and returns the results via JSON.
	 * Triggered by an AJAX request.
	 *
	 * @global $wp_query
	 * @global $wp_the_query
	 * @uses current_theme_supports, get_option, self::wp_query, current_user_can, apply_filters, self::get_settings, add_filter, WP_Query, remove_filter, have_posts, wp_head, do_action, add_action, this::render, this::has_wrapper, esc_attr, wp_footer, sharing_register_post_for_share_counts, get_the_id
	 */
	public function query() {
		if ( ! isset( $_REQUEST['page'] ) || ! current_theme_supports( 'infinite-scroll' ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no changes to the site.
			die;
		}

		// @todo see if we should validate this nonce since we use it to form a query.
		$page = (int) $_REQUEST['page']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- we're casting this to an int and not making changes to the site.

		// Sanitize and set $previousday. Expected format: dd.mm.yy
		if ( isset( $_REQUEST['currentday'] ) && preg_match( '/^\d{2}\.\d{2}\.\d{2}$/', $_REQUEST['currentday'] ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification.Recommended -- manually validating, no changes to site
			global $previousday;
			$previousday = $_REQUEST['currentday']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput
		}

		$post_status = array( 'publish' );
		if ( current_user_can( 'read_private_posts' ) ) {
			array_push( $post_status, 'private' );
		}

		$order = isset( $_REQUEST['order'] ) && in_array( $_REQUEST['order'], array( 'ASC', 'DESC' ), true ) ? sanitize_text_field( wp_unslash( $_REQUEST['order'] ) ) : 'DESC'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no changes made to the site.

		$query_args = array_merge(
			self::wp_query()->query_vars,
			array(
				'paged'          => $page,
				'post_status'    => $post_status,
				'posts_per_page' => self::posts_per_page(), // phpcs:ignore WordPress.WP.PostsPerPage.posts_per_page_posts_per_page
				'order'          => $order,
			)
		);

		// 4.0 ?s= compatibility, see https://core.trac.wordpress.org/ticket/11330#comment:50
		if ( empty( $query_args['s'] ) && ! isset( self::wp_query()->query['s'] ) ) {
			unset( $query_args['s'] );
		}

		// By default, don't query for a specific page of a paged post object.
		// This argument can come from merging self::wp_query() into $query_args above.
		// Since IS is only used on archives, we should always display the first page of any paged content.
		unset( $query_args['page'] );

		/**
		 * Filter the array of main query arguments.
		 *
		 * @module infinite-scroll
		 *
		 * @since 2.0.1
		 *
		 * @param array $query_args Array of Query arguments.
		 */
		$query_args = apply_filters( 'infinite_scroll_query_args', $query_args );

		add_filter( 'posts_where', array( $this, 'query_time_filter' ), 10, 2 );

		$infinite_scroll_query   = new WP_Query();
		$GLOBALS['wp_the_query'] = $infinite_scroll_query;
		$GLOBALS['wp_query']     = $infinite_scroll_query;

		$infinite_scroll_query->query( $query_args );

		remove_filter( 'posts_where', array( $this, 'query_time_filter' ), 10, 2 );

		$results = array();

		if ( have_posts() ) {
			// Fire wp_head to ensure that all necessary scripts are enqueued. Output isn't used, but scripts are extracted in self::action_wp_footer.
			ob_start();
			wp_head();
			while ( ob_get_length() ) {
				ob_end_clean();
			}

			$results['type'] = 'success';

			/**
			 * Fires when rendering Infinite Scroll posts.
			 *
			 * @module infinite-scroll
			 *
			 * @since 2.0.0
			 */
			do_action( 'infinite_scroll_render' );
			$results['html'] = ob_get_clean();
			if ( empty( $results['html'] ) ) {
				/**
				 * Gather renderer callbacks. These will be called in order and allow multiple callbacks to be queued. Once content is found, no futher callbacks will run.
				 *
				 * @module infinite-scroll
				 *
				 * @since 6.0.0
				 */
				$callbacks = apply_filters(
					'infinite_scroll_render_callbacks',
					array( self::get_settings()->render ) // This is the setting callback e.g. from add theme support.
				);

				// Append fallback callback. That rhymes.
				$callbacks[] = array( $this, 'render' );

				foreach ( $callbacks as $callback ) {
					if ( false !== $callback && is_callable( $callback ) ) {
						rewind_posts();
						ob_start();
						add_action( 'infinite_scroll_render', $callback );

						/**
						 * This action is already documented above.
						 * See https://github.com/Automattic/jetpack/pull/16317/
						 * for more details as to why it was introduced.
						 */
						do_action( 'infinite_scroll_render' );

						$results['html'] = ob_get_clean();
						remove_action( 'infinite_scroll_render', $callback );
					}
					if ( ! empty( $results['html'] ) ) {
						break;
					}
				}
			}

			// If primary and fallback rendering methods fail, prevent further IS rendering attempts. Otherwise, wrap the output if requested.
			if ( empty( $results['html'] ) ) {
				unset( $results['html'] );
				/**
				 * Fires when Infinite Scoll doesn't render any posts.
				 *
				 * @module infinite-scroll
				 *
				 * @since 2.0.0
				 */
				do_action( 'infinite_scroll_empty' );
				$results['type'] = 'empty';
			} elseif ( $this->has_wrapper() ) {
				$wrapper_classes  = is_string( self::get_settings()->wrapper ) ? self::get_settings()->wrapper : 'infinite-wrap';
				$wrapper_classes .= ' infinite-view-' . $page;
				$wrapper_classes  = trim( $wrapper_classes );
				$aria_label       = sprintf(
					/* translators: %1$s is the page count */
					__( 'Page: %1$d.', 'jetpack' ),
					$page
				);

				$results['html'] = '<div class="' . esc_attr( $wrapper_classes ) . '" id="infinite-view-' . $page . '" data-page-num="' . $page . '" role="region" aria-label="' . esc_attr( $aria_label ) . '">' . $results['html'] . '</div>';
			}

			// Fire wp_footer to ensure that all necessary scripts are enqueued. Output isn't used, but scripts are extracted in self::action_wp_footer.
			ob_start();
			wp_footer();
			while ( ob_get_length() ) {
				ob_end_clean();
			}

			if ( 'success' === $results['type'] ) {
				global $currentday;
				$results['lastbatch']  = self::is_last_batch();
				$results['currentday'] = $currentday;
			}

			// Loop through posts to capture sharing data for new posts loaded via Infinite Scroll
			if ( 'success' === $results['type'] && function_exists( 'sharing_register_post_for_share_counts' ) ) {
				global $jetpack_sharing_counts;

				while ( have_posts() ) {
					the_post();

					sharing_register_post_for_share_counts( get_the_ID() );
				}

				$results['postflair'] = array_flip( $jetpack_sharing_counts );
			}
		} else {
			/** This action is already documented in modules/infinite-scroll/infinity.php */
			do_action( 'infinite_scroll_empty' );
			$results['type'] = 'empty';
		}

		wp_send_json(
			/**
			 * Filter the Infinite Scroll results.
			 *
			 * @module infinite-scroll
			 *
			 * @since 2.0.0
			 *
			 * @param array $results Array of Infinite Scroll results.
			 * @param array $query_args Array of main query arguments.
			 * @param WP_Query $wp_query WP Query.
			 */
			apply_filters( 'infinite_scroll_results', $results, $query_args, self::wp_query() )
		);
	}

	/**
	 * Update the $allowed_vars array with the standard WP public and private
	 * query vars, as well as taxonomy vars
	 *
	 * @global $wp
	 * @param array $allowed_vars - the allowed variables array.
	 * @filter infinite_scroll_allowed_vars
	 * @return array
	 */
	public function allowed_query_vars( $allowed_vars ) {
		global $wp;

		$allowed_vars += $wp->public_query_vars;
		$allowed_vars += $wp->private_query_vars;
		$allowed_vars += $this->get_taxonomy_vars();

		foreach ( array_keys( $allowed_vars, 'paged', true ) as $key ) {
			unset( $allowed_vars[ $key ] );
		}

		return array_unique( $allowed_vars );
	}

	/**
	 * Returns an array of stock and custom taxonomy query vars
	 *
	 * @global $wp_taxonomies
	 * @return array
	 */
	public function get_taxonomy_vars() {
		global $wp_taxonomies;

		$taxonomy_vars = array();
		foreach ( $wp_taxonomies as $t ) {
			if ( $t->query_var ) {
				$taxonomy_vars[] = $t->query_var;
			}
		}

		// still needed?
		$taxonomy_vars[] = 'tag_id';

		return $taxonomy_vars;
	}

	/**
	 * Update the $query_args array with the parameters provided via AJAX/GET.
	 *
	 * @param array $query_args - the query args.
	 * @filter infinite_scroll_query_args
	 * @return array
	 */
	public function inject_query_args( $query_args ) {
		/**
		 * Filter the array of allowed Infinite Scroll query arguments.
		 *
		 * @module infinite-scroll
		 *
		 * @since 2.6.0
		 *
		 * @param array $args Array of allowed Infinite Scroll query arguments.
		 * @param array $query_args Array of query arguments.
		 */
		$allowed_vars = apply_filters( 'infinite_scroll_allowed_vars', array(), $query_args );

		$query_args = array_merge(
			$query_args,
			array(
				'suppress_filters' => false,
			)
		);

		if ( isset( $_REQUEST['query_args'] ) && is_array( $_REQUEST['query_args'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no site changes.
			foreach ( wp_unslash( $_REQUEST['query_args'] ) as $var => $value ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- no site changes, sanitized below.
				if ( in_array( $var, $allowed_vars, true ) && ! empty( $value ) ) {
					$query_args[ $var ] = filter_var( $value );
				}
			}
		}

		return $query_args;
	}

	/**
	 * Rendering fallback used when themes don't specify their own handler.
	 *
	 * @uses have_posts, the_post, get_template_part, get_post_format
	 * @action infinite_scroll_render
	 */
	public function render() {
		while ( have_posts() ) {
			the_post();

			get_template_part( 'content', get_post_format() );
		}
	}

	/**
	 * Allow plugins to filter what archives Infinite Scroll supports
	 *
	 * @uses current_theme_supports, is_home, is_archive, apply_filters, self::get_settings
	 * @return bool
	 */
	public static function archive_supports_infinity() {
		$supported = current_theme_supports( 'infinite-scroll' ) && ( is_home() || is_archive() || is_search() );

		// Disable when previewing a non-active theme in the customizer
		if ( is_customize_preview() && ! $GLOBALS['wp_customize']->is_theme_active() ) {
			return false;
		}

		/**
		 * Allow plugins to filter what archives Infinite Scroll supports.
		 *
		 * @module infinite-scroll
		 *
		 * @since 2.0.0
		 *
		 * @param bool $supported Does the Archive page support Infinite Scroll.
		 * @param object self::get_settings() IS settings provided by theme.
		 */
		return (bool) apply_filters( 'infinite_scroll_archive_supported', $supported, self::get_settings() );
	}

	/**
	 * The Infinite Blog Footer
	 *
	 * @uses self::get_settings, self::archive_supports_infinity, self::default_footer
	 * @return string or null
	 */
	public function footer() {
		if ( class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() ) {
			return;
		}

		// Bail if theme requested footer not show
		if ( false === self::get_settings()->footer ) {
			return;
		}

		// We only need the new footer for the 'scroll' type
		if ( 'scroll' !== self::get_settings()->type || ! self::archive_supports_infinity() ) {
			return;
		}

		if ( self::is_last_batch() ) {
			return;
		}

		// Display a footer, either user-specified or a default
		if ( false !== self::get_settings()->footer_callback && is_callable( self::get_settings()->footer_callback ) ) {
			call_user_func( self::get_settings()->footer_callback, self::get_settings() );
		} else {
			self::default_footer();
		}
	}

	/**
	 * Render default IS footer
	 *
	 * @uses __, wp_get_theme, apply_filters, home_url, esc_attr, get_bloginfo, bloginfo
	 */
	private function default_footer() {
		if ( '' !== get_privacy_policy_url() ) {
			$credits = get_the_privacy_policy_link() . '<span role="separator" aria-hidden="true"> / </span>';
		} else {
			$credits = '';
		}
		$credits .= sprintf(
			'<a href="https://wordpress.org/" rel="noopener noreferrer" target="_blank" rel="generator">%1$s</a> ',
			__( 'Proudly powered by WordPress', 'jetpack' )
		);
		$credits .= sprintf(
			/* translators: %1$s is the name of a theme */
			__( 'Theme: %1$s.', 'jetpack' ),
			wp_get_theme()->Name
		);
		/**
		 * Filter Infinite Scroll's credit text.
		 *
		 * @module infinite-scroll
		 *
		 * @since 2.0.0
		 *
		 * @param string $credits Infinite Scroll credits.
		 */
		$credits = apply_filters( 'infinite_scroll_credit', $credits );

		?>
		<div id="infinite-footer">
			<div class="container">
				<div class="blog-info">
					<a id="infinity-blog-title" href="<?php echo esc_url( home_url( '/' ) ); ?>" rel="home">
						<?php bloginfo( 'name' ); ?>
					</a>
				</div>
				<div class="blog-credits">
					<?php echo $credits; //phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
				</div>
			</div>
		</div><!-- #infinite-footer -->
		<?php
	}

	/**
	 * Ensure that IS doesn't interfere with Grunion by stripping IS query arguments from the Grunion redirect URL.
	 * When arguments are present, Grunion redirects to the IS AJAX endpoint.
	 *
	 * @param string $url - the Grunion redirect URL.
	 * @uses remove_query_arg
	 * @filter grunion_contact_form_redirect_url
	 * @return string
	 */
	public function filter_grunion_redirect_url( $url ) {
		// Remove IS query args, if present
		if ( false !== strpos( $url, 'infinity=scrolling' ) ) {
			$url = remove_query_arg(
				array(
					'infinity',
					'action',
					'page',
					'order',
					'scripts',
					'styles',
				),
				$url
			);
		}

		return $url;
	}

	/**
	 * When the MediaElement is loaded in dynamically, we need to enforce that
	 * its settings are added to the page as well.
	 *
	 * @param array $scripts_data New scripts exposed to the infinite scroll.
	 *
	 * @since 8.4.0
	 */
	public function add_mejs_config( $scripts_data ) {
		foreach ( $scripts_data as $key => $data ) {
			if ( 'mediaelement-core' === $data['handle'] ) {
				$mejs_settings = array(
					'pluginPath'  => includes_url( 'js/mediaelement/', 'relative' ),
					'classPrefix' => 'mejs-',
					'stretching'  => 'responsive',
				);

				$scripts_data[ $key ]['extra_data'] = sprintf(
					'window.%s = %s',
					'_wpmejsSettings',
					wp_json_encode( apply_filters( 'mejs_settings', $mejs_settings ) )
				);
			}
		}
		return $scripts_data;
	}

	/**
	 * Determines whether the legacy AMP Reader post templates are being used.
	 *
	 * @return bool
	 */
	private function is_exempted_amp_page() {
		if ( is_singular( 'web-story' ) ) {
			// Ensure that <amp-next-page> is not injected after <amp-story> as generated by the Web Stories plugin.
			return true;
		}
		if ( function_exists( 'amp_is_legacy' ) ) {
			// Available since AMP v2.0, this will return false if a theme like Twenty Twenty is selected as the Reader theme.
			return amp_is_legacy();
		}
		if ( method_exists( 'AMP_Options_Manager', 'get_option' ) ) {
			// In versions prior to v2.0, checking the template mode as being 'reader' is sufficient.
			return 'reader' === AMP_Options_Manager::get_option( 'theme_support' );
		}
		return false;
	}

	/**
	 * Load AMP specific hooks.
	 *
	 * @return void
	 */
	public function amp_load_hooks() {
		if ( $this->is_exempted_amp_page() ) {
			return;
		}

		if ( class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() ) {
			$template = self::get_settings()->render;

			add_filter( 'jetpack_infinite_scroll_load_scripts_and_styles', '__return_false' );

			add_action( 'template_redirect', array( $this, 'amp_start_output_buffering' ), 0 );
			add_action( 'shutdown', array( $this, 'amp_output_buffer' ), 1 );

			if ( is_string( $template ) && strpos( $template, '::' ) === false && is_callable( "amp_{$template}_hooks" ) ) {
				call_user_func( "amp_{$template}_hooks" );
			}

			// Warms up the amp next page markup.
			// This should be done outside the output buffering callback started in the template_redirect.
			$this->amp_get_footer_template();
		}
	}

	/**
	 * Start the AMP output buffering.
	 *
	 * @return void
	 */
	public function amp_start_output_buffering() {
		ob_start( array( $this, 'amp_finish_output_buffering' ) );
	}

	/**
	 * Flush the AMP output buffer.
	 *
	 * @return void
	 */
	public function amp_output_buffer() {
		if ( ob_get_contents() ) {
			ob_end_flush();
		}
	}

	/**
	 * Filter the AMP output buffer contents.
	 *
	 * @param string $buffer Contents of the output buffer.
	 *
	 * @return string|false
	 */
	public function amp_finish_output_buffering( $buffer ) {
		// Hide WordPress admin bar on next page load.
		$buffer = preg_replace(
			'/id="wpadminbar"/',
			'$0 next-page-hide',
			$buffer
		);

		/**
		 * Get the theme footers.
		 *
		 * @module infinite-scroll
		 *
		 * @since 9.0.0
		 *
		 * @param array  array() An array to store multiple markup entries to be added to the footer.
		 * @param string $buffer The contents of the output buffer.
		 */
		$footers = apply_filters( 'jetpack_amp_infinite_footers', array(), $buffer );

		/**
		 * Filter the output buffer.
		 * Themes can leverage this hook to add custom markup on next page load.
		 *
		 * @module infinite-scroll
		 *
		 * @since 9.0.0
		 *
		 * @param string $buffer The contents of the output buffer.
		 */
		$buffer = apply_filters( 'jetpack_amp_infinite_output', $buffer );

		// Add the amp next page markup.
		$buffer = preg_replace(
			'~</body>~',
			$this->amp_get_footer_template( $footers ) . '$0',
			$buffer
		);

		return $buffer;
	}

	/**
	 * Get AMP next page markup with the custom footers.
	 *
	 * @param string[] $footers The theme footers.
	 *
	 * @return string
	 */
	protected function amp_get_footer_template( $footers = array() ) {
		static $template = null;

		if ( null === $template ) {
			$template = $this->amp_footer_template();
		}

		if ( empty( $footers ) ) {
			return $template;
		}

		return preg_replace(
			'/%%footer%%/',
			implode( '', $footers ),
			$template
		);
	}

	/**
	 * AMP Next Page markup.
	 *
	 * @return string
	 */
	protected function amp_footer_template() {
		ob_start();
		?>
<amp-next-page max-pages="<?php echo esc_attr( $this->amp_get_max_pages() ); ?>">
	<script type="application/json">
		[
			<?php echo wp_json_encode( $this->amp_next_page() ); ?>
		]
	</script>
	<div separator>
		<?php
		echo wp_kses_post(
			/**
			 * AMP infinite scroll separator.
			 *
			 * @module infinite-scroll
			 *
			 * @since 9.0.0
			 *
			 * @param string '' The markup for the next page separator.
			 */
			apply_filters( 'jetpack_amp_infinite_separator', '' )
		);
		?>
	</div>
	<div recommendation-box class="recommendation-box">
		<template type="amp-mustache">
			{{#pages}}
			<?php
			echo wp_kses_post(
				/**
				 * AMP infinite scroll older posts markup.
				 *
				 * @module infinite-scroll
				 *
				 * @since 9.0.0
				 *
				 * @param string '' The markup for the older posts/next page.
				 */
				apply_filters( 'jetpack_amp_infinite_older_posts', '' )
			);
			?>
			{{/pages}}
		</template>
	</div>
	<div footer>
		%%footer%%
	</div>
</amp-next-page>
		<?php
		return ob_get_clean();
	}

	/**
	 * Get the AMP next page information.
	 *
	 * @return array
	 */
	protected function amp_next_page() {
		$title = '';
		$url   = '';
		$image = '';

		if ( ! static::amp_is_last_page() ) {
			$title = sprintf(
				'%s - %s %d - %s',
				wp_title( '', false ),
				__( 'Page', 'jetpack' ),
				max( get_query_var( 'paged', 1 ), 1 ) + 1,
				get_bloginfo( 'name' )
			);
			$url   = get_next_posts_page_link();
		}

		$next_page = array(
			'title' => $title,
			'url'   => $url,
			'image' => $image,
		);

		/**
		 * The next page settings.
		 * An array containing:
		 *  - title => The title to be featured on the browser tab.
		 *  - url   => The URL of next page.
		 *  - image => The image URL. A required AMP setting, not in use currently. Themes are welcome to leverage.
		 *
		 * @module infinite-scroll
		 *
		 * @since 9.0.0
		 *
		 * @param array $next_page The contents of the output buffer.
		 */
		return apply_filters( 'jetpack_amp_infinite_next_page_data', $next_page );
	}

	/**
	 * Get the number of pages left.
	 *
	 * @return int
	 */
	protected static function amp_get_max_pages() {
		global $wp_query;

		return (int) $wp_query->max_num_pages - $wp_query->query_vars['paged'];
	}

	/**
	 * Is the last page.
	 *
	 * @return bool
	 */
	protected static function amp_is_last_page() {
		return 0 === static::amp_get_max_pages();
	}
}

/**
 * Initialize The_Neverending_Home_Page
 */
function the_neverending_home_page_init() {
	if ( ! current_theme_supports( 'infinite-scroll' ) ) {
		return;
	}

	new The_Neverending_Home_Page();
}
add_action( 'init', 'the_neverending_home_page_init', 20 );

/**
 * Check whether the current theme is infinite-scroll aware.
 * If so, include the files which add theme support.
 */
function the_neverending_home_page_theme_support() {
	if (
			defined( 'IS_WPCOM' ) && IS_WPCOM &&
			defined( 'REST_API_REQUEST' ) && REST_API_REQUEST &&
			! doing_action( 'restapi_theme_after_setup_theme' )
	) {
		// Don't source theme compat files until we're in the site's context
		return;
	}
	$theme_name = get_stylesheet();

	/**
	 * Filter the path to the Infinite Scroll compatibility file.
	 *
	 * @module infinite-scroll
	 *
	 * @since 2.0.0
	 *
	 * @param string $str IS compatibility file path.
	 * @param string $theme_name Theme name.
	 */
	$customization_file = apply_filters( 'infinite_scroll_customization_file', __DIR__ . "/themes/{$theme_name}.php", $theme_name );

	if ( is_readable( $customization_file ) ) {
		require_once $customization_file;
	}
}
add_action( 'after_setup_theme', 'the_neverending_home_page_theme_support', 5 );

/**
 * Early accommodation of the Infinite Scroll AJAX request
 */
if ( The_Neverending_Home_Page::got_infinity() ) {
	/**
	 * If we're sure this is an AJAX request (i.e. the HTTP_X_REQUESTED_WITH header says so),
	 * indicate it as early as possible for actions like init
	 */
	if ( ! defined( 'DOING_AJAX' ) &&
		isset( $_SERVER['HTTP_X_REQUESTED_WITH'] ) &&
		strtoupper( sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REQUESTED_WITH'] ) ) ) === 'XMLHTTPREQUEST'
	) {
		define( 'DOING_AJAX', true );
	}

	// Don't load the admin bar when doing the AJAX response.
	show_admin_bar( false );
}
