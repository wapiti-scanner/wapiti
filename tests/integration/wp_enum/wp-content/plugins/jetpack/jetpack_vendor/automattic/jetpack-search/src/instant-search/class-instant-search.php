<?php
/**
 * Instant Search: Our modern and customizable search experience.
 *
 * @package automattic/jetpack-search
 */

namespace Automattic\Jetpack\Search;

use Automattic\Jetpack\Assets;
use WP_Block_Parser;
use WP_Block_Patterns_Registry;
use WP_Error;
use WP_REST_Templates_Controller;

/**
 * Class responsible for enabling the Instant Search experience on the site.
 */
class Instant_Search extends Classic_Search {
	/**
	 * The name of instant search sidebar.
	 *
	 * 'sidebar' is broken to 'side-bar' on purpose to walk around the mechanism that WP automatically adds widgets to it.
	 *
	 * @since 9.8.0
	 * @var string
	 */
	const INSTANT_SEARCH_SIDEBAR     = 'jetpack-instant-search-side-bar';
	const OLD_INSTANT_SEARCH_SIDEBAR = 'jetpack-instant-search-sidebar';

	const AUTO_CONFIG_SIDEBAR = 'sidebar-1';

	/**
	 * The singleton instance of this class.
	 * Instant_Search shouldn't share the variable with its parent.
	 *
	 * @var Instant_Search
	 */
	private static $instance;

	/**
	 * Variable to save old sidebars_widgets value.
	 *
	 * The value is set when action `after_switch_theme` is applied and cleared on filter `pre_update_option_sidebars_widgets`.
	 * The filters mentioned above run on /wp-admin/themes.php?activated=true, a request closely following switching theme.
	 *
	 * @since 9.8.0
	 *
	 * @var array
	 */
	protected $old_sidebars_widgets;

	/**
	 * Returns a class singleton. Initializes with first-time setup if given a blog ID parameter.
	 *
	 * @param string $blog_id Blog id.
	 * @return static The class singleton.
	 */
	public static function instance( $blog_id = null ) {
		if ( ! isset( self::$instance ) ) {
			if ( null === $blog_id ) {
				$blog_id = Helper::get_wpcom_site_id();
			}
			self::$instance = new static();
			self::$instance->setup( $blog_id );
		}
		return self::$instance;
	}

	/**
	 * Setup the various hooks needed for the plugin to take over search duties.
	 *
	 * @since 5.0.0
	 */
	public function init_hooks() {
		if ( ! is_admin() ) {
			add_filter( 'posts_pre_query', array( $this, 'filter__posts_pre_query' ), 10, 2 );

			add_action( 'init', array( $this, 'set_filters_from_widgets' ) );

			add_action( 'wp_enqueue_scripts', array( $this, 'load_assets' ) );
			add_action( 'wp_footer', array( 'Automattic\Jetpack\Search\Helper', 'print_instant_search_sidebar' ) );
			add_filter( 'body_class', array( $this, 'add_body_class' ), 10 );
		} else {
			add_action( 'update_option', array( $this, 'track_widget_updates' ), 10, 3 );
		}

		add_action( 'widgets_init', array( $this, 'register_jetpack_instant_sidebar' ) );
		add_action( 'jetpack_deactivate_module_search', array( $this, 'move_search_widgets_to_inactive' ) );
	}

	/**
	 * Loads assets for Jetpack Instant Search Prototype featuring Search As You Type experience.
	 */
	public function load_assets() {
		$this->load_assets_with_parameters( Package::get_installed_path() );
	}

	/**
	 * Loads assets according to parameters provided.
	 *
	 * @param string $package_base_path - Base path for the search package.
	 */
	public function load_assets_with_parameters( $package_base_path ) {
		Assets::register_script(
			'jetpack-instant-search',
			'build/instant-search/jp-search.js',
			$package_base_path . '/src', // A full path to a file or a directory inside a plugin.
			array(
				'dependencies' => array( 'wp-i18n' ),
				'in_footer'    => true,
				'textdomain'   => 'jetpack-search-pkg',
			)
		);
		Assets::enqueue_script( 'jetpack-instant-search' );
		$this->load_and_initialize_tracks();
		$this->inject_javascript_options();
	}

	/**
	 * Passes all options to the JS app.
	 */
	protected function inject_javascript_options() {
		$options = Helper::generate_initial_javascript_state();
		// Use wp_add_inline_script instead of wp_localize_script, see https://core.trac.wordpress.org/ticket/25280.
		wp_add_inline_script( 'jetpack-instant-search', 'var JetpackInstantSearchOptions=JSON.parse(decodeURIComponent("' . rawurlencode( wp_json_encode( $options ) ) . '"));', 'before' );
	}

	/**
	 * Registers a widget sidebar for Instant Search.
	 */
	public function register_jetpack_instant_sidebar() {
		$args = array(
			'name'          => __( 'Jetpack Search Sidebar', 'jetpack-search-pkg' ),
			'id'            => self::INSTANT_SEARCH_SIDEBAR,
			'description'   => __( 'Customize the sidebar inside the Jetpack Search overlay', 'jetpack-search-pkg' ),
			'class'         => '',
			'before_widget' => '<div id="%1$s" class="widget %2$s">',
			'after_widget'  => '</div>',
			'before_title'  => '<h2 class="widgettitle">',
			'after_title'   => '</h2>',
		);
		register_sidebar( $args );
	}

	/**
	 * Loads scripts for Tracks analytics library
	 */
	public function load_and_initialize_tracks() {
		wp_enqueue_script( 'jp-tracks', '//stats.wp.com/w.js', array(), gmdate( 'YW' ), true );
	}

	/**
	 * Bypass the normal Search query since we will run it with instant search.
	 *
	 * @since 8.3.0
	 *
	 * @param array    $posts Current array of posts (still pre-query).
	 * @param WP_Query $query The WP_Query being filtered.
	 *
	 * @return array Array of matching posts.
	 */
	public function filter__posts_pre_query( $posts, $query ) {
		if ( ! $this->should_handle_query( $query ) ) {
			// Intentionally not adding the 'jetpack_search_abort' action since this should fire for every request except for search.
			return $posts;
		}

		/**
		 * Bypass the main query and return dummy data
		 *  WP Core doesn't call the set_found_posts and its filters when filtering
		 *  posts_pre_query like we do, so need to do these manually.
		 */
		$query->found_posts   = 1;
		$query->max_num_pages = 1;

		return array();
	}

	/**
	 * Run the aggregations API query for any filtering
	 *
	 * @since 8.3.0
	 */
	public function fetch_search_result_if_empty() {
		if ( ! empty( $this->search_result ) ) {
			return;
		}

		if ( is_admin() ) {
			return;
		}

		if ( empty( $this->aggregations ) ) {
			return;
		}

		$builder = new WPES\Query_Builder();
		$this->add_aggregations_to_es_query_builder( $this->aggregations, $builder );
		$this->search_result = $this->instant_api(
			array(
				'aggregations' => $builder->build_aggregation(),
				'size'         => 0,
				'from'         => 0,
			)
		);
	}

	/**
	 * Run an instant search on the WordPress.com public API.
	 *
	 * @since 8.3.0
	 *
	 * @param array $args Args conforming to the WP.com v1.3/sites/<blog_id>/search endpoint.
	 *
	 * @return object|WP_Error The response from the public API, or a WP_Error.
	 */
	public function instant_api( array $args ) {
		global $wp_version;
		$start_time = microtime( true );

		// Cache locally to avoid remote request slowing the page.
		$transient_name = 'jetpack_instant_search_cache_' . md5( wp_json_encode( $args ) );
		$cache          = get_transient( $transient_name );
		if ( false !== $cache ) {
			return $cache;
		}

		$service_url = add_query_arg(
			$args,
			sprintf(
				'https://public-api.wordpress.com/rest/v1.3/sites/%d/search',
				$this->jetpack_blog_id
			)
		);

		$request_args = array(
			'timeout'    => 10,
			'user-agent' => "WordPress/{$wp_version} | Jetpack-Search/" . Package::VERSION,
		);

		$request  = wp_remote_get( esc_url_raw( $service_url ), $request_args );
		$end_time = microtime( true );

		if ( is_wp_error( $request ) ) {
			return $request;
		}

		$response_code = wp_remote_retrieve_response_code( $request );
		$response      = json_decode( wp_remote_retrieve_body( $request ), true );

		if ( ! $response_code || $response_code < 200 || $response_code >= 300 ) {
			/**
			 * Fires after a search query request has failed
			 *
			 * @module search
			 *
			 * @since  5.6.0
			 *
			 * @param array Array containing the response code and response from the failed search query
			 */
			do_action(
				'failed_jetpack_search_query',
				array(
					'response_code' => $response_code,
					'json'          => $response,
				)
			);

			return new WP_Error( 'invalid_search_api_response', 'Invalid response from API - ' . $response_code );
		}

		$took = is_array( $response ) && ! empty( $response['took'] )
		? $response['took']
		: null;

		$query = array(
			'args'          => $args,
			'response'      => $response,
			'response_code' => $response_code,
			'elapsed_time'  => ( $end_time - $start_time ) * 1000, // Convert from float seconds to ms.
			'es_time'       => $took,
			'url'           => $service_url,
		);

		/**
		 * Fires after a search request has been performed.
		 *
		 * Includes the following info in the $query parameter:
		 *
		 * array args Array of Elasticsearch arguments for the search
		 * array response Raw API response, JSON decoded
		 * int response_code HTTP response code of the request
		 * float elapsed_time Roundtrip time of the search request, in milliseconds
		 * float es_time Amount of time Elasticsearch spent running the request, in milliseconds
		 * string url API url that was queried
		 *
		 * @module search
		 *
		 * @since  5.0.0
		 * @since  5.8.0 This action now fires on all queries instead of just successful queries.
		 *
		 * @param array $query Array of information about the query performed
		 */
		do_action( 'did_jetpack_search_query', $query );

		// Update local cache.
		set_transient( $transient_name, $response, 4 * HOUR_IN_SECONDS );

		return $response;
	}

	/**
	 * Get the raw Aggregation results from the Elasticsearch response.
	 *
	 * @since  8.4.0
	 *
	 * @return array Array of Aggregations performed on the search.
	 */
	public function get_search_aggregations_results() {
		$this->fetch_search_result_if_empty();
		if ( empty( $this->search_result ) || is_wp_error( $this->search_result ) || ! isset( $this->search_result['aggregations'] ) ) {
			return array();
		}

		return $this->search_result['aggregations'];
	}

	/**
	 * Automatically configure necessary settings for instant search
	 *
	 * @since  8.3.0
	 */
	public function auto_config_search() {
		$this->auto_config_excluded_post_types();
		$this->auto_config_overlay_sidebar_widgets();
		$this->auto_config_theme_sidebar_search_widget();
		$this->auto_config_result_format();
	}

	/**
	 * Auto config search widget or block for current theme.
	 */
	public function auto_config_theme_sidebar_search_widget() {
		if ( \current_theme_supports( 'block-templates' ) ) {
			$this->auto_config_fse_theme_footer_search_block();
		} else {
			$this->auto_config_non_fse_theme_sidebar_search_widget();
		}
	}

	/**
	 * Automatically copy configured search widgets from theme sidebar to the overlay sidebar.
	 * If there's nothing to copy, we create one.
	 *
	 * @since  8.8.0
	 */
	public function auto_config_overlay_sidebar_widgets() {
		$sidebars                              = get_option( 'sidebars_widgets', array() );
		list(,$sidebar_jp_searchbox_wiget_id ) = $this->get_search_widget_indices( $sidebars, self::INSTANT_SEARCH_SIDEBAR );
		// If there's JP search widget in overly sidebar, abort.
		if ( false !== $sidebar_jp_searchbox_wiget_id ) {
			return;
		}

		// Init overlay sidebar if it doesn't exists.
		if ( ! isset( $sidebars[ self::INSTANT_SEARCH_SIDEBAR ] ) ) {
			$sidebars[ self::INSTANT_SEARCH_SIDEBAR ] = array();
		}

		$widget_opt_name = Helper::get_widget_option_name();
		$widget_options  = get_option( $widget_opt_name, array() );

		$next_id = $this->get_next_jp_search_widget_id( $widget_options );

		list(,$sidebar_jp_searchbox_wiget_id ) = $this->get_search_widget_indices( $sidebars, self::AUTO_CONFIG_SIDEBAR );
		if ( false !== $sidebar_jp_searchbox_wiget_id && isset( $widget_options[ $sidebar_jp_searchbox_wiget_id ] ) ) {
			// If there is a JP search widget in the theme sidebar, copy it over to the search overlay sidebar.
			$widget_options[ $next_id ] = $widget_options[ $sidebar_jp_searchbox_wiget_id ];
		} else {
			// If JP Search widget doesn't exist in the theme sidebar, we have nothing to copy from, so we create a new one within the overlay sidebar.
			$widget_options[ $next_id ] = $this->get_preconfig_widget_options();
		}
		array_unshift( $sidebars[ self::INSTANT_SEARCH_SIDEBAR ], Helper::build_widget_id( $next_id ) );
		update_option( $widget_opt_name, $widget_options );
		update_option( 'sidebars_widgets', $sidebars );
		return true;
	}

	/**
	 * Add JP Search widget on top of theme sidebar.
	 * Or Replace core search widget in theme sidebar if exists.
	 */
	public function auto_config_non_fse_theme_sidebar_search_widget() {
		$sidebars = get_option( 'sidebars_widgets', array() );
		if ( ! isset( $sidebars[ self::AUTO_CONFIG_SIDEBAR ] ) ) {
			return;
		}

		list( $sidebar_searchbox_idx,$sidebar_jp_searchbox_wiget_id ) = $this->get_search_widget_indices( $sidebars );
		// If there's JP search widget in theme sidebar, abort.
		if ( false !== $sidebar_jp_searchbox_wiget_id ) {
			return;
		}

		$widget_opt_name = Helper::get_widget_option_name();
		$widget_options  = get_option( $widget_opt_name, array() );

		list($sidebar_searchbox_idx, ) = $this->get_search_widget_indices( $sidebars );
		$next_id                       = $this->get_next_jp_search_widget_id( $widget_options );
		$preconfig_opts                = $this->get_preconfig_widget_options();

		$widget_options[ $next_id ] = $preconfig_opts;
		if ( false !== $sidebar_searchbox_idx ) {
			// Replace core search widget with JP search widget.
			$sidebars[ self::AUTO_CONFIG_SIDEBAR ][ $sidebar_searchbox_idx ] = Helper::build_widget_id( $next_id );
		} else {
			// Add JP Search widget to top.
			array_unshift( $sidebars[ self::AUTO_CONFIG_SIDEBAR ], Helper::build_widget_id( $next_id ) );
		}

		update_option( $widget_opt_name, $widget_options );
		update_option( 'sidebars_widgets', $sidebars );
		return true;
	}

	/**
	 * Get the next ID for the Jetpack Search widget, which is equivalent to the last JP Search widget ID + 1.
	 *
	 * @param array $widget_options - jetpack widget option value.
	 *
	 * @return int
	 */
	public function get_next_jp_search_widget_id( $widget_options ) {
		return ! empty( $widget_options ) ? max(
			array_map(
				function ( $val ) {
					return intval( $val );
				},
				array_keys( $widget_options )
			)
		) + 1 : 1;
	}

	/**
	 * Get search and JP Search widget indices in theme sidebar.
	 *
	 * @param array  $sidebars - theme `sidebars_widgets` option value.
	 * @param string $sidebar_id - the sidebar id to search on.
	 *
	 * @return array - core search widget index and JP search widget id.
	 */
	protected function get_search_widget_indices( $sidebars, $sidebar_id = 'sidebar-1' ) {
		$sidebar_searchbox_idx   = false;
		$sidebar_jp_searchbox_id = false;
		if ( isset( $sidebars[ $sidebar_id ] ) ) {
			foreach ( (array) $sidebars[ $sidebar_id ] as $idx => $widget_id ) {
				if ( $this->widget_has_search_block( $widget_id ) ) {
					// The array index of wp search widget.
					$sidebar_searchbox_idx = $idx;
				}
				if ( 0 === strpos( $widget_id, Helper::FILTER_WIDGET_BASE ) ) {
					// The id of Jetpack Search widget.
					$sidebar_jp_searchbox_id = str_replace( Helper::FILTER_WIDGET_BASE . '-', '', $widget_id );
				}
			}
		}
		return array( $sidebar_searchbox_idx, $sidebar_jp_searchbox_id );
	}

	/**
	 * Returns true if search widget or block exists in widgets
	 *
	 * @param string $widget_id - widget ID.
	 */
	protected function widget_has_search_block( $widget_id ) {
		// test search widget.
		if ( 0 === strpos( $widget_id, 'search-' ) ) {
			return true;
		}
		// test search block widget.
		if ( 0 === strpos( $widget_id, 'block-' ) ) {
			$widget_blocks = get_option( 'widget_block', array() );
			$widget_index  = str_replace( 'block-', '', $widget_id );
			// A single block could be of type string or array.
			if ( isset( $widget_blocks[ $widget_index ]['content'] ) && false !== strpos( (string) $widget_blocks[ $widget_index ]['content'], 'wp:search' ) ) {
				return true;
			}
			if ( isset( $widget_blocks[ $widget_index ] ) && is_string( $widget_blocks[ $widget_index ] ) && false !== strpos( $widget_blocks[ $widget_index ], 'wp:search' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns true if $block_content has core search block
	 *
	 * @param string $block_content - Block content.
	 *
	 * @return boolean
	 */
	public static function content_has_search_block( $block_content ) {
		return preg_match( '/(<!--\swp:search\s[^>]*-->)/i', $block_content ) > 0;
	}

	/**
	 * Add a search widget above footer for block templates.
	 */
	public function auto_config_fse_theme_footer_search_block() {
		if ( ! class_exists( 'WP_REST_Templates_Controller' ) ) {
			return;
		}
		// We currently check only for a core search block.
		// In the future, we will need to check for a Jetpack Search block once it's available.
		if ( $this->template_parts_have_search_block() ) {
			return;
		}

		$footer = $this->get_template_part( 'footer' );
		if ( ! $footer instanceof \WP_Block_Template ) {
			return;
		}

		$content          = $this->replace_block_patterns( $footer->content );
		$template_part_id = $footer->id;
		$request          = new \WP_REST_Request( 'PUT', "/wp/v2/template-parts/{$template_part_id}" );
		$request->set_header( 'content-type', 'application/json' );
		$request->set_param( 'content', static::inject_search_widget_to_block( $content ) );
		$request->set_param( 'id', $template_part_id );
		$controller = new WP_REST_Templates_Controller( 'wp_template_part' );
		return $controller->update_item( $request );
	}

	/**
	 * Replace pattern blocks with their content.
	 * We don't want to replace recursively for the sake of simplicity.
	 *
	 * @param string $block_content - Content of template part.
	 */
	protected function replace_block_patterns( $block_content ) {
		$matches = array();
		if ( preg_match( '/<!--\s*wp:pattern\s+{.*}\s*\/-->/', $block_content, $matches ) > 0 ) {
			foreach ( $matches as $match ) {
				$pattern_content = $this->get_block_pattern_content( $match );
				$block_content   = str_replace( $match, $pattern_content, $block_content );
			}
		}
		return $block_content;
	}

	/**
	 * Extracts block content only if it consists of a single pattern block.
	 *
	 * @param string $block_pattern - Block content.
	 */
	protected function get_block_pattern_content( $block_pattern ) {
		if ( ! class_exists( 'WP_Block_Parser' ) || ! class_exists( 'WP_Block_Patterns_Registry' ) ) {
			return $block_pattern;
		}
		$blocks = ( new WP_Block_Parser() )->parse( $block_pattern );
		if ( 1 === count( $blocks ) && 'core/pattern' === $blocks[0]['blockName'] ) {
			$slug     = $blocks[0]['attrs']['slug'];
			$registry = WP_Block_Patterns_Registry::get_instance();
			if ( $registry->is_registered( $slug ) ) {
				$pattern = $registry->get_registered( $slug );
				return $pattern['content'];
			}
		}
		return $block_pattern;
	}

	/**
	 * Get template part for current theme.
	 *
	 * @param string $template_part_name - header, footer, home etc.
	 *
	 * @return \WP_Block_Template
	 */
	protected function get_template_part( $template_part_name ) {
		// Check whether block theme functions exist.
		if ( ! function_exists( 'get_block_template' ) ) {
			return null;
		}
		$active_theme     = \wp_get_theme()->get_stylesheet();
		$template_part_id = "{$active_theme}//{$template_part_name}";
		$template_part    = \get_block_template( $template_part_id, 'wp_template_part' );
		if ( is_wp_error( $template_part ) || empty( $template_part ) ) {
			return null;
		}
		return $template_part;
	}

	/**
	 * Returns true if  'header', 'footer' or 'home' has core search block
	 *
	 * @return boolean
	 */
	protected function template_parts_have_search_block() {
		$template_part_names = array( 'header', 'footer', 'home' );
		foreach ( $template_part_names as $part_name ) {
			$part = $this->get_template_part( $part_name );
			if ( $part instanceof \WP_Block_Template && static::content_has_search_block( $part->content ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Append Search block to block if no 'wp:search' exists already.
	 *
	 * @param {string} $block_content - the content to append the search block.
	 */
	public static function inject_search_widget_to_block( $block_content ) {
		$search_block = sprintf(
			'<!-- wp:search {"label":"","buttonText":"%s"} /-->',
			__( 'Search', 'jetpack-search-pkg' )
		);

		// Place the search block on bottom of the first column if there's any.
		$column_end_pattern = '/(<\s*\/div[^>]*>\s*<!--\s*\/wp:column\s+[^>]*-->)/';
		if ( preg_match( $column_end_pattern, $block_content ) ) {
			return preg_replace( $column_end_pattern, "\n" . $search_block . "\n$1", $block_content, 1 );
		}

		// Place the search block on top of footer contents in the most inner group.
		$group_start_pattern = '/((<!--\s*wp:group\s[^>]*-->[.\s]*<\s*div[^>]*>\s*)+)/';
		if ( preg_match( $group_start_pattern, $block_content, $matches ) ) {
			return preg_replace( $group_start_pattern, "$1\n" . $search_block . "\n", $block_content, 1 );
		}

		return $block_content;
	}

	/**
	 * Autoconfig search by adding filter widgets
	 *
	 * @since  8.4.0
	 *
	 * @return array Array of config settings for search widget.
	 */
	protected function get_preconfig_widget_options() {
		$settings = array(
			'title'   => '',
			'filters' => array(),
		);

		$post_types = get_post_types(
			array(
				'public'   => true,
				'_builtin' => false,
			)
		);

		if ( ! empty( $post_types ) ) {
			$settings['filters'][] = array(
				'name'  => '',
				'type'  => 'post_type',
				'count' => 5,
			);
		}

		// Grab a maximum of 3 taxonomies.
		$taxonomies = array_slice(
			get_taxonomies(
				array(
					'public'   => true,
					'_builtin' => false,
				)
			),
			0,
			3
		);

		foreach ( $taxonomies as $t ) {
			$settings['filters'][] = array(
				'name'     => '',
				'type'     => 'taxonomy',
				'taxonomy' => $t,
				'count'    => 5,
			);
		}

		$settings['filters'][] = array(
			'name'     => '',
			'type'     => 'taxonomy',
			'taxonomy' => 'category',
			'count'    => 5,
		);

		$settings['filters'][] = array(
			'name'     => '',
			'type'     => 'taxonomy',
			'taxonomy' => 'post_tag',
			'count'    => 5,
		);

		$settings['filters'][] = array(
			'name'     => '',
			'type'     => 'date_histogram',
			'count'    => 5,
			'field'    => 'post_date',
			'interval' => 'year',
		);

		return $settings;
	}

	/**
	 * Automatically configure post types to exclude from one of the search widgets.
	 * Used primarily for backward compatibility with older Jetpack plugins, which used to store excluded post type configuration within the Jetpack Search plugin instead of as an option.
	 *
	 * @since  8.8.0
	 */
	public function auto_config_excluded_post_types() {
		// if `excluded_post_types` exists, then we do nothing.
		if ( false !== get_option( Options::OPTION_PREFIX . 'excluded_post_types', false ) ) {
			return;
		}
		$post_types         = get_post_types(
			array(
				'exclude_from_search' => false,
				'public'              => true,
			)
		);
		$enabled_post_types = array();
		$widget_options     = get_option( Helper::get_widget_option_name(), array() );

		// Prior to Jetpack 8.8, post types were enabled via Jetpack Search widgets rather than disabled via the Customizer.
		// To continue supporting post types set up in the old way, we iterate through each Jetpack Search
		// widget configuration and append each enabled post type to $enabled_post_types.
		foreach ( $widget_options as $widget_option ) {
			if ( isset( $widget_option['post_types'] ) && is_array( $widget_option['post_types'] ) ) {
				foreach ( $widget_option['post_types'] as $enabled_post_type ) {
					$enabled_post_types[ $enabled_post_type ] = $enabled_post_type;
				}
			}
		}

		if ( ! empty( $enabled_post_types ) ) {
			$post_types_to_disable = array_diff( $post_types, $enabled_post_types );
			// better to use `add_option` which wouldn't override option value if exists.
			add_option( Options::OPTION_PREFIX . 'excluded_post_types', join( ',', $post_types_to_disable ) );
		}
	}

	/**
	 * Automatically set result format.
	 *
	 * @since  9.6.0
	 */
	public function auto_config_result_format() {
		$result_format_option_name = Options::OPTION_PREFIX . 'result_format';
		// Default format `expanded`.
		$result_format_option_value = Options::RESULT_FORMAT_EXPANDED;

		// Result format already set, skip.
		if ( get_option( $result_format_option_name, false ) ) {
			return;
		}

		// Check if WooCommerce plugin is active (based on https://docs.woocommerce.com/document/create-a-plugin/).
		if ( in_array(
			'woocommerce/woocommerce.php',
			apply_filters( 'active_plugins', Helper::get_active_plugins() ),
			true
		) ) {
			$result_format_option_value = Options::RESULT_FORMAT_PRODUCT;
		}

		update_option( $result_format_option_name, $result_format_option_value );
		return true;
	}

	/**
	 * Add current theme name as a body class for easier override
	 *
	 * @param string[] $classes An array of body class names.
	 *
	 * @return string[] The array of classes after filtering
	 */
	public function add_body_class( $classes ) {
		$classes[] = 'jps-theme-' . get_stylesheet();
		return $classes;
	}
}
