<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Theme Tools: functions for Featured Content enhancements.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Constants;

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

if ( ! class_exists( 'Featured_Content' ) && isset( $GLOBALS['pagenow'] ) && 'plugins.php' !== $GLOBALS['pagenow'] ) {

	/**
	 * Featured Content.
	 *
	 * This module will allow users to define a subset of posts to be displayed in a
	 * theme-designated featured content area.
	 *
	 * This feature will only be activated for themes that declare that they support
	 * it. This can be done by adding code similar to the following during the
	 * "after_setup_theme" action:
	 *
	 * add_theme_support( 'featured-content', array(
	 *     'filter'     => 'mytheme_get_featured_content',
	 *     'max_posts'  => 20,
	 *     'post_types' => array( 'post', 'page' ),
	 * ) );
	 *
	 * For maximum compatibility with different methods of posting users will
	 * designate a featured post tag to associate posts with. Since this tag now has
	 * special meaning beyond that of a normal tags, users will have the ability to
	 * hide it from the front-end of their site.
	 */
	class Featured_Content {

		/**
		 * The maximum number of posts that a Featured Content area can contain. We
		 * define a default value here but themes can override this by defining a
		 * "max_posts" entry in the second parameter passed in the call to
		 * add_theme_support( 'featured-content' ).
		 *
		 * @see Featured_Content::init()
		 * @var int
		 */
		public static $max_posts = 15;

		/**
		 * The registered post types supported by Featured Content. Themes can add
		 * Featured Content support for registered post types by defining a
		 * 'post_types' argument (string|array) in the call to
		 * add_theme_support( 'featured-content' ).
		 *
		 * @see Featured_Content::init()
		 * @var array
		 */
		public static $post_types = array( 'post' );

		/**
		 * The tag that is used to mark featured content. Users can define
		 * a custom tag name that will be stored in this variable.
		 *
		 * @see Featured_Content::hide_featured_term
		 * @var string
		 */
		public static $tag;

		/**
		 * Instantiate.
		 *
		 * All custom functionality will be hooked into the "init" action.
		 */
		public static function setup() {
			add_action( 'init', array( __CLASS__, 'init' ), 30 );
		}

		/**
		 * Conditionally hook into WordPress.
		 *
		 * Themes must declare that they support this module by adding
		 * add_theme_support( 'featured-content' ); during after_setup_theme.
		 *
		 * If no theme support is found there is no need to hook into WordPress. We'll
		 * just return early instead.
		 *
		 * @uses Featured_Content::$max_posts
		 */
		public static function init() {
			$theme_support = get_theme_support( 'featured-content' );

			// Return early if theme does not support featured content.
			if ( ! $theme_support ) {
				return;
			}

			/*
			 * An array of named arguments must be passed as the second parameter
			 * of add_theme_support().
			 */
			if ( ! isset( $theme_support[0] ) ) {
				return;
			}

			if ( isset( $theme_support[0]['featured_content_filter'] ) ) {
				$theme_support[0]['filter'] = $theme_support[0]['featured_content_filter'];
				unset( $theme_support[0]['featured_content_filter'] );
			}

			// Return early if "filter" has not been defined.
			if ( ! isset( $theme_support[0]['filter'] ) ) {
				return;
			}

			// Theme can override the number of max posts.
			if ( isset( $theme_support[0]['max_posts'] ) ) {
				self::$max_posts = absint( $theme_support[0]['max_posts'] );
			}

			add_filter( $theme_support[0]['filter'], array( __CLASS__, 'get_featured_posts' ) );
			add_action( 'customize_register', array( __CLASS__, 'customize_register' ), 9 );
			add_action( 'admin_init', array( __CLASS__, 'register_setting' ) );
			add_action( 'save_post', array( __CLASS__, 'delete_transient' ) );
			add_action( 'delete_post_tag', array( __CLASS__, 'delete_post_tag' ) );
			add_action( 'customize_controls_enqueue_scripts', array( __CLASS__, 'enqueue_scripts' ) );
			add_action( 'pre_get_posts', array( __CLASS__, 'pre_get_posts' ) );
			add_action( 'switch_theme', array( __CLASS__, 'switch_theme' ) );
			add_action( 'switch_theme', array( __CLASS__, 'delete_transient' ) );
			add_action( 'wp_loaded', array( __CLASS__, 'wp_loaded' ) );
			add_action( 'update_option_featured-content', array( __CLASS__, 'flush_post_tag_cache' ), 10, 2 );
			add_action( 'delete_option_featured-content', array( __CLASS__, 'flush_post_tag_cache' ), 10, 2 );
			add_action( 'split_shared_term', array( __CLASS__, 'jetpack_update_featured_content_for_split_terms', 10, 4 ) );

			if ( isset( $theme_support[0]['additional_post_types'] ) ) {
				$theme_support[0]['post_types'] = array_merge( array( 'post' ), (array) $theme_support[0]['additional_post_types'] );
				unset( $theme_support[0]['additional_post_types'] );
			}

			// Themes can allow Featured Content pages.
			if ( isset( $theme_support[0]['post_types'] ) ) {
				self::$post_types = array_merge( self::$post_types, (array) $theme_support[0]['post_types'] );
				self::$post_types = array_unique( self::$post_types );

				// register post_tag support for each post type.
				foreach ( self::$post_types as $post_type ) {
					register_taxonomy_for_object_type( 'post_tag', $post_type );
				}
			}
		}

		/**
		 * Hide "featured" tag from the front-end.
		 *
		 * Has to run on wp_loaded so that the preview filters of the customizer
		 * have a chance to alter the value.
		 */
		public static function wp_loaded() {
			if ( self::get_setting( 'hide-tag' ) ) {
				$settings = self::get_setting();

				// This is done before setting filters for get_terms in order to avoid an infinite filter loop.
				self::$tag = get_term_by( 'name', $settings['tag-name'], 'post_tag' );

				add_filter( 'get_terms', array( __CLASS__, 'hide_featured_term' ), 10, 3 );
				add_filter( 'get_the_terms', array( __CLASS__, 'hide_the_featured_term' ), 10, 3 );
			}
		}

		/**
		 * Get featured posts
		 *
		 * This method is not intended to be called directly. Theme developers should
		 * place a filter directly in their theme and then pass its name as a value of
		 * the "filter" key in the array passed as the $args parameter during the call
		 * to: add_theme_support( 'featured-content', $args ).
		 *
		 * @uses Featured_Content::get_featured_post_ids()
		 *
		 * @return array
		 */
		public static function get_featured_posts() {
			$post_ids = self::get_featured_post_ids();

			// No need to query if there is are no featured posts.
			if ( empty( $post_ids ) ) {
				return array();
			}

			$featured_posts = get_posts(
				array(
					'include'          => $post_ids,
					'posts_per_page'   => count( $post_ids ), // phpcs:ignore WordPress.WP.PostsPerPage.posts_per_page_posts_per_page
					'post_type'        => self::$post_types,
					'suppress_filters' => false,
				)
			);

			return $featured_posts;
		}

		/**
		 * Get featured post IDs
		 *
		 * This function will return the an array containing the post IDs of all
		 * featured posts.
		 *
		 * Sets the "featured_content_ids" transient.
		 *
		 * @return array Array of post IDs.
		 */
		public static function get_featured_post_ids() {
			// Return array of cached results if they exist.
			$featured_ids = get_transient( 'featured_content_ids' );
			if ( ! empty( $featured_ids ) ) {
				return array_map(
					'absint',
					/**
					* Filter the list of Featured Posts IDs.
					*
					* @module theme-tools
					*
					* @since 2.7.0
					*
					* @param array $featured_ids Array of post IDs.
					*/
					apply_filters( 'featured_content_post_ids', (array) $featured_ids )
				);
			}

			$settings = self::get_setting();

			// Return empty array if no tag name is set.
			$term = get_term_by( 'name', $settings['tag-name'], 'post_tag' );
			if ( ! $term ) {
				$term = get_term_by( 'id', $settings['tag-id'], 'post_tag' );
			}
			if ( $term ) {
				$tag = $term->term_id;
			} else {
				/** This action is documented in modules/theme-tools/featured-content.php */
				return apply_filters( 'featured_content_post_ids', array() );
			}

			// Back compat for installs that have the quantity option still set.
			$quantity = isset( $settings['quantity'] ) ? $settings['quantity'] : self::$max_posts;

			// Query for featured posts.
			$featured = get_posts(
				array(
					'numberposts'      => $quantity,
					'post_type'        => self::$post_types,
					'suppress_filters' => false,
					'tax_query'        => array(
						array(
							'field'    => 'term_id',
							'taxonomy' => 'post_tag',
							'terms'    => $tag,
						),
					),
				)
			);

			// Return empty array if no featured content exists.
			if ( ! $featured ) {
				/** This action is documented in modules/theme-tools/featured-content.php */
				return apply_filters( 'featured_content_post_ids', array() );
			}

			// Ensure correct format before save/return.
			$featured_ids = wp_list_pluck( (array) $featured, 'ID' );
			$featured_ids = array_map( 'absint', $featured_ids );

			set_transient( 'featured_content_ids', $featured_ids );

			/** This action is documented in modules/theme-tools/featured-content.php */
			return apply_filters( 'featured_content_post_ids', $featured_ids );
		}

		/**
		 * Delete Transient.
		 *
		 * Hooks in the "save_post" action.
		 *
		 * @see Featured_Content::validate_settings().
		 */
		public static function delete_transient() {
			delete_transient( 'featured_content_ids' );
		}

		/**
		 * Flush the Post Tag relationships cache.
		 *
		 * Hooks in the "update_option_featured-content" action.
		 *
		 * @param array $prev Previous option data.
		 * @param array $opts New option data.
		 */
		public static function flush_post_tag_cache( $prev, $opts ) {
			if ( ! empty( $opts ) && ! empty( $opts['tag-id'] ) ) {
				$query = new WP_Query(
					array(
						'tag_id'         => (int) $opts['tag-id'],
						'posts_per_page' => -1,
					)
				);
				foreach ( $query->posts as $post ) {
					wp_cache_delete( $post->ID, 'post_tag_relationships' );
				}
			}
		}

		/**
		 * Exclude featured posts from the blog query when the blog is the front-page,
		 * and user has not checked the "Also display tagged posts outside the Featured Content area" checkbox.
		 *
		 * Filter the home page posts, and remove any featured post ID's from it.
		 * Hooked onto the 'pre_get_posts' action, this changes the parameters of the
		 * query before it gets any posts.
		 *
		 * @uses Featured_Content::get_featured_post_ids();
		 * @uses Featured_Content::get_setting();
		 * @param WP_Query $query WP_Query object.
		 * @return WP_Query Possibly modified WP_Query
		 */
		public static function pre_get_posts( $query ) {

			// Bail if not home or not main query.
			if ( ! $query->is_home() || ! $query->is_main_query() ) {
				return;
			}

			// Bail if the blog page is not the front page.
			if ( 'posts' !== get_option( 'show_on_front' ) ) {
				return;
			}

			$featured = self::get_featured_post_ids();

			// Bail if no featured posts.
			if ( ! $featured ) {
				return;
			}

			$settings = self::get_setting();

			// Bail if the user wants featured posts always displayed.
			if ( $settings['show-all'] ) {
				return;
			}

			// We need to respect post ids already in the blocklist.
			$post__not_in = $query->get( 'post__not_in' );

			if ( ! empty( $post__not_in ) ) {
				$featured = array_merge( (array) $post__not_in, $featured );
				$featured = array_unique( $featured );
			}

			$query->set( 'post__not_in', $featured );
		}

		/**
		 * Reset tag option when the saved tag is deleted.
		 *
		 * It's important to mention that the transient needs to be deleted, too.
		 * While it may not be obvious by looking at the function alone, the transient
		 * is deleted by Featured_Content::validate_settings().
		 *
		 * Hooks in the "delete_post_tag" action.
		 *
		 * @see Featured_Content::validate_settings().
		 *
		 * @param int $tag_id The term_id of the tag that has been deleted.
		 * @return void
		 */
		public static function delete_post_tag( $tag_id ) {
			$settings = self::get_setting();

			if ( empty( $settings['tag-id'] ) || $tag_id != $settings['tag-id'] ) { // phpcs:ignore Universal.Operators.StrictComparisons.LooseNotEqual
				return;
			}

			$settings['tag-id'] = 0;
			$settings           = self::validate_settings( $settings );
			update_option( 'featured-content', $settings );
		}

		/**
		 * Hide featured tag from displaying when global terms are queried from
		 * the front-end.
		 *
		 * Hooks into the "get_terms" filter.
		 *
		 * @uses Featured_Content::get_setting()
		 *
		 * @param array $terms A list of term objects. This is the return value of get_terms().
		 * @param array $taxonomies An array of taxonomy slugs.
		 * @param array $args Array of get_terms() arguments.
		 * @return array $terms
		 */
		public static function hide_featured_term( $terms, $taxonomies, $args ) {

			// This filter is only appropriate on the front-end.
			if ( is_admin() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) ) {
				return $terms;
			}

			// WordPress defines the parameter as `array`, but it passes null if `get_terms( $args )` was called
			// without a 'taxonomy' in $args.
			if ( ! is_array( $taxonomies ) ) {
				return $terms;
			}

			// We only want to hide the featured tag.
			if ( ! in_array( 'post_tag', $taxonomies, true ) ) {
				return $terms;
			}

			// Bail if no terms were returned.
			if ( empty( $terms ) ) {
				return $terms;
			}

			// Bail if term objects are unavailable.
			if ( 'all' !== $args['fields'] ) {
				return $terms;
			}

			$settings = self::get_setting();

			if ( false !== self::$tag ) {
				foreach ( $terms as $order => $term ) {
					if (
					is_object( $term )
					&& (
						$settings['tag-id'] === $term->term_id
						|| $settings['tag-name'] === $term->name
					)
					) {
						unset( $terms[ $order ] );
					}
				}
			}

			return $terms;
		}

		/**
		 * Hide featured tag from displaying when terms associated with a post object
		 * are queried from the front-end.
		 *
		 * Hooks into the "get_the_terms" filter.
		 *
		 * @uses Featured_Content::get_setting()
		 *
		 * @param array $terms A list of term objects. This is the return value of get_the_terms().
		 * @param int   $id The ID field for the post object that terms are associated with.
		 * @param array $taxonomy An array of taxonomy slugs.
		 * @return array $terms
		 */
		public static function hide_the_featured_term( $terms, $id, $taxonomy ) {

			// This filter is only appropriate on the front-end.
			if ( is_admin() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) ) {
				return $terms;
			}

			// Make sure we are in the correct taxonomy.
			if ( 'post_tag' !== $taxonomy ) {
				return $terms;
			}

			// No terms? Return early!
			if ( empty( $terms ) ) {
				return $terms;
			}

			$settings = self::get_setting();
			$tag      = get_term_by( 'name', $settings['tag-name'], 'post_tag' );

			if ( false !== $tag ) {
				foreach ( $terms as $order => $term ) {
					if ( $settings['tag-id'] === $term->term_id || $settings['tag-name'] === $term->name ) {
						unset( $terms[ $order ] );
					}
				}
			}

			return $terms;
		}

		/**
		 * Register custom setting on the Settings -> Reading screen.
		 *
		 * @uses Featured_Content::render_form()
		 * @uses Featured_Content::validate_settings()
		 *
		 * @return void
		 */
		public static function register_setting() {
			add_settings_field( 'featured-content', __( 'Featured Content', 'jetpack' ), array( __CLASS__, 'render_form' ), 'reading' );

			// Register sanitization callback for the Customizer.
			register_setting( 'featured-content', 'featured-content', array( __CLASS__, 'validate_settings' ) );
		}

		/**
		 * Add settings to the Customizer.
		 *
		 * @param WP_Customize_Manager $wp_customize Theme Customizer object.
		 */
		public static function customize_register( $wp_customize ) {
			$wp_customize->add_section(
				'featured_content',
				array(
					'title'          => esc_html__( 'Featured Content', 'jetpack' ),
					'description'    => sprintf(
						/* translators: %1$s: Link to 'featured' admin tag view. %2$s: Max number of posts shown by theme in featured content area. */
						__( 'Easily feature all posts with the <a href="%1$s">"featured" tag</a> or a tag of your choice. Your theme supports up to %2$s posts in its featured content area.', 'jetpack' ),
						admin_url( '/edit.php?tag=featured' ),
						absint( self::$max_posts )
					),
					'priority'       => 130,
					'theme_supports' => 'featured-content',
				)
			);

			/*
			Add Featured Content settings.
			 *
			 * Sanitization callback registered in Featured_Content::validate_settings().
			 * See https://themeshaper.com/2013/04/29/validation-sanitization-in-customizer/comment-page-1/#comment-12374
			 */
			$wp_customize->add_setting(
				'featured-content[tag-name]',
				array(
					'type'                 => 'option',
					'sanitize_js_callback' => array( __CLASS__, 'delete_transient' ),
				)
			);
			$wp_customize->add_setting(
				'featured-content[hide-tag]',
				array(
					'default'              => true,
					'type'                 => 'option',
					'sanitize_js_callback' => array( __CLASS__, 'delete_transient' ),
				)
			);
			$wp_customize->add_setting(
				'featured-content[show-all]',
				array(
					'default'              => false,
					'type'                 => 'option',
					'sanitize_js_callback' => array( __CLASS__, 'delete_transient' ),
				)
			);

			// Add Featured Content controls.
			$wp_customize->add_control(
				'featured-content[tag-name]',
				array(
					'label'          => esc_html__( 'Tag name', 'jetpack' ),
					'section'        => 'featured_content',
					'theme_supports' => 'featured-content',
					'priority'       => 20,
				)
			);
			$wp_customize->add_control(
				'featured-content[hide-tag]',
				array(
					'label'          => esc_html__( 'Do not display tag in post details and tag clouds.', 'jetpack' ),
					'section'        => 'featured_content',
					'theme_supports' => 'featured-content',
					'type'           => 'checkbox',
					'priority'       => 30,
				)
			);
			$wp_customize->add_control(
				'featured-content[show-all]',
				array(
					'label'          => esc_html__( 'Also display tagged posts outside the Featured Content area.', 'jetpack' ),
					'section'        => 'featured_content',
					'theme_supports' => 'featured-content',
					'type'           => 'checkbox',
					'priority'       => 40,
				)
			);
		}

		/**
		 * Enqueue the tag suggestion script.
		 */
		public static function enqueue_scripts() {
			wp_enqueue_script( 'featured-content-suggest', plugins_url( 'js/suggest.js', __FILE__ ), array( 'jquery', 'suggest' ), '20131022', true );
		}

		/**
		 * Renders all form fields on the Settings -> Reading screen.
		 */
		public static function render_form() {
			printf(
				wp_kses(
					/* translators: %s: Link to the Featured Content settings in the Customizer. */
					__( 'The settings for Featured Content have <a href="%s">moved to Appearance &rarr; Customize</a>.', 'jetpack' ),
					array(
						'a' => array( 'href' => array() ),
					)
				),
				esc_url( admin_url( 'customize.php?#accordion-section-featured_content' ) )
			);
		}

		/**
		 * Get settings
		 *
		 * Get all settings recognized by this module. This function will return all
		 * settings whether or not they have been stored in the database yet. This
		 * ensures that all keys are available at all times.
		 *
		 * In the event that you only require one setting, you may pass its name as the
		 * first parameter to the function and only that value will be returned.
		 *
		 * @param string $key The key of a recognized setting.
		 * @return mixed Array of all settings by default. A single value if passed as first parameter.
		 */
		public static function get_setting( $key = 'all' ) {
			$saved = (array) get_option( 'featured-content' );

			/**
			 * Filter Featured Content's default settings.
			 *
			 * @module theme-tools
			 *
			 * @since 2.7.0
			 *
			 * @param array $args {
			 * Array of Featured Content Settings
			 *
			 *  @type int hide-tag Default is 1.
			 *  @type int tag-id Default is 0.
			 *  @type string tag-name Default is empty.
			 *  @type int show-all Default is 0.
			 * }
			 */
			$defaults = apply_filters(
				'featured_content_default_settings',
				array(
					'hide-tag' => 1,
					'tag-id'   => 0,
					'tag-name' => '',
					'show-all' => 0,
				)
			);

			$options = wp_parse_args( $saved, $defaults );
			$options = array_intersect_key( $options, $defaults );

			if ( 'all' !== $key ) {
				return isset( $options[ $key ] ) ? $options[ $key ] : false;
			}

			return $options;
		}

		/**
		 * Validate settings
		 *
		 * Make sure that all user supplied content is in an expected format before
		 * saving to the database. This function will also delete the transient set in
		 * Featured_Content::get_featured_content().
		 *
		 * @uses Featured_Content::delete_transient()
		 *
		 * @param array $input Array of settings input.
		 * @return array $output
		 */
		public static function validate_settings( $input ) {
			$output = array();

			if ( empty( $input['tag-name'] ) ) {
				$output['tag-id'] = 0;
			} else {
				$term = get_term_by( 'name', $input['tag-name'], 'post_tag' );

				if ( $term ) {
					$output['tag-id'] = $term->term_id;
				} else {
					$new_tag = wp_create_tag( $input['tag-name'] );

					if ( ! is_wp_error( $new_tag ) && isset( $new_tag['term_id'] ) ) {
						$output['tag-id'] = $new_tag['term_id'];
					}
				}

				$output['tag-name'] = $input['tag-name'];
			}

			$output['hide-tag'] = isset( $input['hide-tag'] ) && $input['hide-tag'] ? 1 : 0;

			$output['show-all'] = isset( $input['show-all'] ) && $input['show-all'] ? 1 : 0;

			self::delete_transient();

			return $output;
		}

		/**
		 * Removes the quantity setting from the options array.
		 *
		 * @return void
		 */
		public static function switch_theme() {
			$option = (array) get_option( 'featured-content' );

			if ( isset( $option['quantity'] ) ) {
				unset( $option['quantity'] );
				update_option( 'featured-content', $option );
			}
		}

		/**
		 * Update Featured Content term data as necessary when a shared term is split.
		 *
		 * @param int    $old_term_id ID of the formerly shared term.
		 * @param int    $new_term_id ID of the new term created for the $term_taxonomy_id.
		 * @param int    $term_taxonomy_id ID for the term_taxonomy row affected by the split.
		 * @param string $taxonomy Taxonomy for the split term.
		 */
		public static function jetpack_update_featured_content_for_split_terms( $old_term_id, $new_term_id, $term_taxonomy_id, $taxonomy ) {
			$featured_content_settings = get_option( 'featured-content', array() );

			// Check to see whether the stored tag ID is the one that's just been split.
			if ( isset( $featured_content_settings['tag-id'] ) && $old_term_id == $featured_content_settings['tag-id'] && 'post_tag' === $taxonomy ) { // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
				// We have a match, so we swap out the old tag ID for the new one and resave the option.
				$featured_content_settings['tag-id'] = $new_term_id;
				update_option( 'featured-content', $featured_content_settings );
			}
		}
	}

	/**
	 * Adds the featured content plugin to the set of files for which action
	 * handlers should be copied when the theme context is loaded by the REST API.
	 *
	 * @param array $copy_dirs Copy paths with actions to be copied.
	 * @return array Copy paths with featured content plugin
	 */
	function wpcom_rest_api_featured_content_copy_plugin_actions( $copy_dirs ) {
		$copy_dirs[] = __FILE__;
		return $copy_dirs;
	}
	add_action( 'restapi_theme_action_copy_dirs', 'wpcom_rest_api_featured_content_copy_plugin_actions' );

	/**
	 * Delayed initialization for API Requests.
	 *
	 * @param object $request REST request object.
	 */
	function wpcom_rest_request_before_callbacks( $request ) {
		Featured_Content::init();
		return $request;
	}

	if ( Constants::is_true( 'IS_WPCOM' ) && Constants::is_true( 'REST_API_REQUEST' ) ) {
		add_filter( 'rest_request_before_callbacks', 'wpcom_rest_request_before_callbacks' );
	}

	Featured_Content::setup();
}
