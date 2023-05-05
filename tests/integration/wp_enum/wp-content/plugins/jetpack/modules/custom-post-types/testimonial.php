<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Register a Testimonial post type and handle displaying it anywhere on the site.
 *
 * @package automattic/jetpack
 * @phpcs:disable Generic.Files.OneObjectStructurePerFile.MultipleFound
 * @phpcs:disable MediaWiki.Usage.NestedFunctions.NestedFunction
 */

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

/**
 * Add a Testimonial CPT, and display it with a shortcode
 */
class Jetpack_Testimonial {
	const CUSTOM_POST_TYPE       = 'jetpack-testimonial';
	const OPTION_NAME            = 'jetpack_testimonial';
	const OPTION_READING_SETTING = 'jetpack_testimonial_posts_per_page';

	/**
	 * Initialize class.
	 *
	 * @return self
	 */
	public static function init() {
		static $instance = false;

		if ( ! $instance ) {
			$instance = new Jetpack_Testimonial();
		}

		return $instance;
	}

	/**
	 * Conditionally hook into WordPress.
	 *
	 * Setup user option for enabling CPT.
	 * If user has CPT enabled, show in admin.
	 */
	public function __construct() {
		// Make sure the post types are loaded for imports
		add_action( 'import_start', array( $this, 'register_post_types' ) );

		// If called via REST API, we need to register later in lifecycle
		add_action( 'restapi_theme_init', array( $this, 'maybe_register_cpt' ) );

		// Add to REST API post type allowed list.
		add_filter( 'rest_api_allowed_post_types', array( $this, 'allow_cpt_rest_api_type' ) );

		$this->maybe_register_cpt();
	}

	/**
	 * Registers the custom post types and adds action/filter handlers, but
	 * only if the site supports it
	 */
	public function maybe_register_cpt() {
		// Add an option to enable the CPT
		add_action( 'admin_init', array( $this, 'settings_api_init' ) );

		// Check on theme switch if theme supports CPT and setting is disabled
		add_action( 'after_switch_theme', array( $this, 'activation_post_type_support' ) );

		$setting = Jetpack_Options::get_option_and_ensure_autoload( self::OPTION_NAME, '0' );

		// Bail early if Testimonial option is not set and the theme doesn't declare support
		if ( empty( $setting ) && ! $this->site_supports_custom_post_type() ) {
			return;
		}

		if ( ( ! defined( 'IS_WPCOM' ) || ! IS_WPCOM ) && ! Jetpack::is_module_active( 'custom-content-types' ) ) {
			return;
		}

		// CPT magic
		$this->register_post_types();
		add_action( sprintf( 'add_option_%s', self::OPTION_NAME ), array( $this, 'flush_rules_on_enable' ), 10 );
		add_action( sprintf( 'update_option_%s', self::OPTION_NAME ), array( $this, 'flush_rules_on_enable' ), 10 );
		add_action( sprintf( 'publish_%s', self::CUSTOM_POST_TYPE ), array( $this, 'flush_rules_on_first_testimonial' ) );
		add_action( 'after_switch_theme', array( $this, 'flush_rules_on_switch' ) );

		// Admin Customization
		add_filter( 'enter_title_here', array( $this, 'change_default_title' ) );
		add_filter( sprintf( 'manage_%s_posts_columns', self::CUSTOM_POST_TYPE ), array( $this, 'edit_title_column_label' ) );
		add_filter( 'post_updated_messages', array( $this, 'updated_messages' ) );
		add_action( 'customize_register', array( $this, 'customize_register' ) );

		// Only add the 'Customize' sub-menu if the theme supports it.
		if ( is_admin() && current_theme_supports( self::CUSTOM_POST_TYPE ) && ! empty( self::count_testimonials() ) ) {
			add_action( 'admin_menu', array( $this, 'add_customize_page' ) );
		}

		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			// Track all the things
			add_action( sprintf( 'add_option_%s', self::OPTION_NAME ), array( $this, 'new_activation_stat_bump' ) );
			add_action( sprintf( 'update_option_%s', self::OPTION_NAME ), array( $this, 'update_option_stat_bump' ), 11, 2 );
			add_action( sprintf( 'publish_%s', self::CUSTOM_POST_TYPE ), array( $this, 'new_testimonial_stat_bump' ) );

			// Add to Dotcom XML sitemaps
			add_filter( 'wpcom_sitemap_post_types', array( $this, 'add_to_sitemap' ) );
		} else {
			// Add to Jetpack XML sitemap
			add_filter( 'jetpack_sitemap_post_types', array( $this, 'add_to_sitemap' ) );
		}

		// Adjust CPT archive and custom taxonomies to obey CPT reading setting
		add_filter( 'pre_get_posts', array( $this, 'query_reading_setting' ), 20 );
		add_filter( 'infinite_scroll_settings', array( $this, 'infinite_scroll_click_posts_per_page' ) );

		// Register [jetpack_testimonials] always and
		// register [testimonials] if [testimonials] isn't already set
		add_shortcode( 'jetpack_testimonials', array( $this, 'jetpack_testimonial_shortcode' ) );

		if ( ! shortcode_exists( 'testimonials' ) ) {
			add_shortcode( 'testimonials', array( $this, 'jetpack_testimonial_shortcode' ) );
		}

		// If CPT was enabled programatically and no CPT items exist when user switches away, disable
		if ( $setting && $this->site_supports_custom_post_type() ) {
			add_action( 'switch_theme', array( $this, 'deactivation_post_type_support' ) );
		}
	}

	/**
	 * Add a checkbox field in 'Settings' > 'Writing'
	 * for enabling CPT functionality.
	 *
	 * @return void
	 */
	public function settings_api_init() {
		add_settings_field(
			self::OPTION_NAME,
			'<span class="cpt-options">' . __( 'Testimonials', 'jetpack' ) . '</span>',
			array( $this, 'setting_html' ),
			'writing',
			'jetpack_cpt_section'
		);

		register_setting(
			'writing',
			self::OPTION_NAME,
			'intval'
		);

		// Check if CPT is enabled first so that intval doesn't get set to NULL on re-registering.
		if ( $this->site_supports_custom_post_type() ) {
			register_setting(
				'writing',
				self::OPTION_READING_SETTING,
				'intval'
			);
		}
	}

	/**
	 * HTML code to display a checkbox true/false option
	 * for the CPT setting.
	 *
	 * @return void
	 */
	public function setting_html() {
		if ( current_theme_supports( self::CUSTOM_POST_TYPE ) ) : ?>
			<p><?php esc_html_e( 'Your theme supports Testimonials', 'jetpack' ); ?></p>
		<?php else : ?>
			<label for="<?php echo esc_attr( self::OPTION_NAME ); ?>">
				<input name="<?php echo esc_attr( self::OPTION_NAME ); ?>" id="<?php echo esc_attr( self::OPTION_NAME ); ?>" <?php echo checked( get_option( self::OPTION_NAME, '0' ), true, false ); ?> type="checkbox" value="1" />
				<?php esc_html_e( 'Enable Testimonials for this site.', 'jetpack' ); ?>
				<a target="_blank" href="https://en.support.wordpress.com/testimonials/"><?php esc_html_e( 'Learn More', 'jetpack' ); ?></a>
			</label>
			<?php
		endif;

		if ( $this->site_supports_custom_post_type() ) :
			printf(
				'<p><label for="%1$s">%2$s</label></p>',
				esc_attr( self::OPTION_READING_SETTING ),
				sprintf(
					/* translators: %1$s is replaced with an input field for numbers */
					esc_html__( 'Testimonial pages display at most %1$s testimonials', 'jetpack' ),
					sprintf(
						'<input name="%1$s" id="%1$s" type="number" step="1" min="1" value="%2$s" class="small-text" />',
						esc_attr( self::OPTION_READING_SETTING ),
						esc_attr( get_option( self::OPTION_READING_SETTING, '10' ) )
					)
				)
			);
		endif;
	}

	/**
	 * Should this Custom Post Type be made available?
	 */
	private function site_supports_custom_post_type() {
		// If the current theme requests it.
		if ( current_theme_supports( self::CUSTOM_POST_TYPE ) || get_option( self::OPTION_NAME, '0' ) ) {
			return true;
		}

		// Otherwise, say no unless something wants to filter us to say yes.
		/** This action is documented in modules/custom-post-types/nova.php */
		return (bool) apply_filters( 'jetpack_enable_cpt', false, self::CUSTOM_POST_TYPE );
	}

	/**
	 * Add to REST API post type allowed list.
	 *
	 *  @param array $post_types Array of allowed post types.
	 * @return array `$post_types` with our type added.
	 */
	public function allow_cpt_rest_api_type( $post_types ) {
		$post_types[] = self::CUSTOM_POST_TYPE;

		return $post_types;
	}

	/**
	 * Bump Testimonial > New Activation stat
	 */
	public function new_activation_stat_bump() {
		/** This action is documented in modules/widgets/social-media-icons.php */
		do_action( 'jetpack_bump_stats_extras', 'testimonials', 'new-activation' );
	}

	/**
	 * Bump Testimonial > Option On/Off stats to get total active
	 *
	 * @param mixed $old The old option value.
	 * @param mixed $new The new option value.
	 */
	public function update_option_stat_bump( $old, $new ) {
		if ( empty( $old ) && ! empty( $new ) ) {
			/** This action is documented in modules/widgets/social-media-icons.php */
			do_action( 'jetpack_bump_stats_extras', 'testimonials', 'option-on' );
		}

		if ( ! empty( $old ) && empty( $new ) ) {
			/** This action is documented in modules/widgets/social-media-icons.php */
			do_action( 'jetpack_bump_stats_extras', 'testimonials', 'option-off' );
		}
	}

	/**
	 * Bump Testimonial > Published Testimonials stat when testimonials are published
	 */
	public function new_testimonial_stat_bump() {
		/** This action is documented in modules/widgets/social-media-icons.php */
		do_action( 'jetpack_bump_stats_extras', 'testimonials', 'published-testimonials' );
	}

	/**
	 * Flush permalinks when CPT option is turned on/off
	 */
	public function flush_rules_on_enable() {
		flush_rewrite_rules();
	}

	/**
	 * Count published testimonials and flush permalinks when first testimonial is published
	 */
	public function flush_rules_on_first_testimonial() {
		$testimonials = get_transient( 'jetpack-testimonial-count-cache' );

		if ( false === $testimonials ) {
			flush_rewrite_rules();
			$testimonials = (int) wp_count_posts( self::CUSTOM_POST_TYPE )->publish;

			if ( ! empty( $testimonials ) ) {
				set_transient( 'jetpack-testimonial-count-cache', $testimonials, HOUR_IN_SECONDS * 12 );
			}
		}
	}

	/**
	 * Flush permalinks when CPT supported theme is activated
	 */
	public function flush_rules_on_switch() {
		if ( current_theme_supports( self::CUSTOM_POST_TYPE ) ) {
			flush_rewrite_rules();
		}
	}

	/**
	 * On plugin/theme activation, check if current theme supports CPT
	 */
	public static function activation_post_type_support() {
		if ( current_theme_supports( self::CUSTOM_POST_TYPE ) ) {
			update_option( self::OPTION_NAME, '1' );
		}
	}

	/**
	 * On theme switch, check if CPT item exists and disable if not
	 */
	public function deactivation_post_type_support() {
		$portfolios = get_posts(
			array(
				'fields'           => 'ids',
				'posts_per_page'   => 1,
				'post_type'        => self::CUSTOM_POST_TYPE,
				'suppress_filters' => false,
			)
		);

		if ( empty( $portfolios ) ) {
			update_option( self::OPTION_NAME, '0' );
		}
	}

	/**
	 * Register Post Type
	 */
	public function register_post_types() {
		if ( post_type_exists( self::CUSTOM_POST_TYPE ) ) {
			return;
		}

		register_post_type(
			self::CUSTOM_POST_TYPE,
			array(
				'description'     => __( 'Customer Testimonials', 'jetpack' ),
				'labels'          => array(
					'name'                  => esc_html__( 'Testimonials', 'jetpack' ),
					'singular_name'         => esc_html__( 'Testimonial', 'jetpack' ),
					'menu_name'             => esc_html__( 'Testimonials', 'jetpack' ),
					'all_items'             => esc_html__( 'All Testimonials', 'jetpack' ),
					'add_new'               => esc_html__( 'Add New', 'jetpack' ),
					'add_new_item'          => esc_html__( 'Add New Testimonial', 'jetpack' ),
					'edit_item'             => esc_html__( 'Edit Testimonial', 'jetpack' ),
					'new_item'              => esc_html__( 'New Testimonial', 'jetpack' ),
					'view_item'             => esc_html__( 'View Testimonial', 'jetpack' ),
					'search_items'          => esc_html__( 'Search Testimonials', 'jetpack' ),
					'not_found'             => esc_html__( 'No Testimonials found', 'jetpack' ),
					'not_found_in_trash'    => esc_html__( 'No Testimonials found in Trash', 'jetpack' ),
					'filter_items_list'     => esc_html__( 'Filter Testimonials list', 'jetpack' ),
					'items_list_navigation' => esc_html__( 'Testimonial list navigation', 'jetpack' ),
					'items_list'            => esc_html__( 'Testimonials list', 'jetpack' ),
				),
				'supports'        => array(
					'title',
					'editor',
					'thumbnail',
					'page-attributes',
					'revisions',
					'excerpt',
					'newspack_blocks',
				),
				'rewrite'         => array(
					'slug'       => 'testimonial',
					'with_front' => false,
					'feeds'      => false,
					'pages'      => true,
				),
				'public'          => true,
				'show_ui'         => true,
				'menu_position'   => 20, // below Pages
				'menu_icon'       => 'dashicons-testimonial',
				'capability_type' => 'page',
				'map_meta_cap'    => true,
				'has_archive'     => true,
				'query_var'       => 'testimonial',
				'show_in_rest'    => true,
			)
		);
	}

	/**
	 * Update messages for the Testimonial admin.
	 *
	 * @param array $messages Existing post update messages.
	 * @return array Updated `$messages`.
	 */
	public function updated_messages( $messages ) {
		global $post;

		$messages[ self::CUSTOM_POST_TYPE ] = array(
			0  => '', // Unused. Messages start at index 1.
			1  => sprintf(
				/* Translators: link to Testimonial item's page. */
				__( 'Testimonial updated. <a href="%s">View testimonial</a>', 'jetpack' ),
				esc_url( get_permalink( $post->ID ) )
			),
			2  => esc_html__( 'Custom field updated.', 'jetpack' ),
			3  => esc_html__( 'Custom field deleted.', 'jetpack' ),
			4  => esc_html__( 'Testimonial updated.', 'jetpack' ),
			5  => isset( $_GET['revision'] ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Copying core message handling.
				? sprintf(
					/* translators: %s: date and time of the revision */
					esc_html__( 'Testimonial restored to revision from %s', 'jetpack' ),
					wp_post_revision_title( (int) $_GET['revision'], false ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Copying core message handling.
				)
				: false,
			6  => sprintf(
				/* Translators: link to Testimonial item's page. */
				__( 'Testimonial published. <a href="%s">View testimonial</a>', 'jetpack' ),
				esc_url( get_permalink( $post->ID ) )
			),
			7  => esc_html__( 'Testimonial saved.', 'jetpack' ),
			8  => sprintf(
				/* Translators: link to Testimonial item's page. */
				__( 'Testimonial submitted. <a target="_blank" href="%s">Preview testimonial</a>', 'jetpack' ),
				esc_url( add_query_arg( 'preview', 'true', get_permalink( $post->ID ) ) )
			),
			9  => sprintf(
				/* Translators: 1: Publishing date and time. 2. Link to testimonial's item page. */
				__( 'Testimonial scheduled for: <strong>%1$s</strong>. <a target="_blank" href="%2$s">Preview testimonial</a>', 'jetpack' ),
				// translators: Publish box date format, see https://php.net/date
				date_i18n( __( 'M j, Y @ G:i', 'jetpack' ), strtotime( $post->post_date ) ),
				esc_url( get_permalink( $post->ID ) )
			),
			10 => sprintf(
				/* Translators: link to Testimonial item's page. */
				__( 'Testimonial draft updated. <a target="_blank" href="%s">Preview testimonial</a>', 'jetpack' ),
				esc_url( add_query_arg( 'preview', 'true', get_permalink( $post->ID ) ) )
			),
		);

		return $messages;
	}

	/**
	 * Change ‘Enter Title Here’ text for the Testimonial.
	 *
	 * @param string $title Placeholder text. Default 'Add title'.
	 * @return string Replacement title.
	 */
	public function change_default_title( $title ) {
		if ( self::CUSTOM_POST_TYPE === get_post_type() ) {
			$title = esc_html__( "Enter the customer's name here", 'jetpack' );
		}

		return $title;
	}

	/**
	 * Change ‘Title’ column label on all Testimonials page.
	 *
	 * @param array $columns An array of column names.
	 * @return array Updated array.
	 */
	public function edit_title_column_label( $columns ) {
		$columns['title'] = esc_html__( 'Customer Name', 'jetpack' );

		return $columns;
	}

	/**
	 * Follow CPT reading setting on CPT archive page
	 *
	 * @param WP_Query $query A WP_Query instance.
	 */
	public function query_reading_setting( $query ) {
		if ( ! is_admin()
			&& $query->is_main_query()
			&& $query->is_post_type_archive( self::CUSTOM_POST_TYPE )
		) {
			$query->set( 'posts_per_page', get_option( self::OPTION_READING_SETTING, '10' ) );
		}
	}

	/**
	 * If Infinite Scroll is set to 'click', use our custom reading setting instead of core's `posts_per_page`.
	 *
	 * @param array $settings Array of Infinite Scroll settings.
	 * @return array Updated `$settings`.
	 */
	public function infinite_scroll_click_posts_per_page( $settings ) {
		global $wp_query;

		if ( ! is_admin() && true === $settings['click_handle'] && $wp_query->is_post_type_archive( self::CUSTOM_POST_TYPE ) ) {
			$settings['posts_per_page'] = get_option( self::OPTION_READING_SETTING, $settings['posts_per_page'] ); // phpcs:ignore WordPress.WP.PostsPerPage.posts_per_page_posts_per_page
		}

		return $settings;
	}

	/**
	 * Add CPT to Dotcom sitemap
	 *
	 * @param array $post_types Array of post types included in sitemap.
	 * @return array Updated `$post_types`.
	 */
	public function add_to_sitemap( $post_types ) {
		$post_types[] = self::CUSTOM_POST_TYPE;

		return $post_types;
	}

	/**
	 * Count the number of published testimonials.
	 *
	 * @return int
	 */
	private function count_testimonials() {
		$testimonials = get_transient( 'jetpack-testimonial-count-cache' );

		if ( false === $testimonials ) {
			$testimonials = (int) wp_count_posts( self::CUSTOM_POST_TYPE )->publish;

			if ( ! empty( $testimonials ) ) {
				set_transient( 'jetpack-testimonial-count-cache', $testimonials, 60 * 60 * 12 );
			}
		}

		return $testimonials;
	}

	/**
	 * Adds a submenu link to the Customizer.
	 */
	public function add_customize_page() {
		add_submenu_page(
			'edit.php?post_type=' . self::CUSTOM_POST_TYPE,
			esc_html__( 'Customize Testimonials Archive', 'jetpack' ),
			esc_html__( 'Customize', 'jetpack' ),
			'edit_theme_options',
			add_query_arg(
				array(
					'url'                => rawurlencode( home_url( '/testimonial/' ) ),
					'autofocus[section]' => 'jetpack_testimonials',
				),
				'customize.php'
			)
		);
	}

	/**
	 * Adds testimonial section to the Customizer.
	 *
	 * @param WP_Customize_Manager $wp_customize Customizer instance.
	 */
	public function customize_register( $wp_customize ) {
		jetpack_testimonial_custom_control_classes();

		$wp_customize->add_section(
			'jetpack_testimonials',
			array(
				'title'          => esc_html__( 'Testimonials', 'jetpack' ),
				'theme_supports' => self::CUSTOM_POST_TYPE,
				'priority'       => 130,
			)
		);

		$wp_customize->add_setting(
			'jetpack_testimonials[page-title]',
			array(
				'default'              => esc_html__( 'Testimonials', 'jetpack' ),
				'sanitize_callback'    => array( 'Jetpack_Testimonial_Title_Control', 'sanitize_content' ),
				'sanitize_js_callback' => array( 'Jetpack_Testimonial_Title_Control', 'sanitize_content' ),
			)
		);
		$wp_customize->add_control(
			'jetpack_testimonials[page-title]',
			array(
				'section' => 'jetpack_testimonials',
				'label'   => esc_html__( 'Testimonial Archive Title', 'jetpack' ),
				'type'    => 'text',
			)
		);

		$wp_customize->add_setting(
			'jetpack_testimonials[page-content]',
			array(
				'default'              => '',
				'sanitize_callback'    => array( 'Jetpack_Testimonial_Textarea_Control', 'sanitize_content' ),
				'sanitize_js_callback' => array( 'Jetpack_Testimonial_Textarea_Control', 'sanitize_content' ),
			)
		);
		$wp_customize->add_control(
			new Jetpack_Testimonial_Textarea_Control(
				$wp_customize,
				'jetpack_testimonials[page-content]',
				array(
					'section'  => 'jetpack_testimonials',
					'settings' => 'jetpack_testimonials[page-content]',
					'label'    => esc_html__( 'Testimonial Archive Content', 'jetpack' ),
				)
			)
		);

		$wp_customize->add_setting(
			'jetpack_testimonials[featured-image]',
			array(
				'default'              => '',
				'sanitize_callback'    => 'attachment_url_to_postid',
				'sanitize_js_callback' => 'attachment_url_to_postid',
				'theme_supports'       => 'post-thumbnails',
			)
		);
		$wp_customize->add_control(
			new WP_Customize_Image_Control(
				$wp_customize,
				'jetpack_testimonials[featured-image]',
				array(
					'section' => 'jetpack_testimonials',
					'label'   => esc_html__( 'Testimonial Archive Featured Image', 'jetpack' ),
				)
			)
		);

		// The featured image control doesn't display properly in the Customizer unless we coerce
		// it back into a URL sooner, since that's what WP_Customize_Upload_Control::to_json() expects
		if ( is_admin() ) {
			add_filter( 'theme_mod_jetpack_testimonials', array( $this, 'coerce_testimonial_image_to_url' ) );
		}
	}

	/**
	 * Add Featured image to theme mod if necessary.
	 *
	 * @param array $opt The value of the current theme modification.
	 * @return array Updated `$opt`.
	 */
	public function coerce_testimonial_image_to_url( $opt ) {
		if ( ! $opt || ! is_array( $opt ) ) {
			return $opt;
		}
		if ( ! isset( $opt['featured-image'] ) || ! is_scalar( $opt['featured-image'] ) ) {
			return $opt;
		}
		$url = wp_get_attachment_url( $opt['featured-image'] );
		if ( $url ) {
			$opt['featured-image'] = $url;
		}
		return $opt;
	}

	/**
	 * Our [testimonial] shortcode.
	 * Prints Testimonial data styled to look good on *any* theme.
	 *
	 * @param array $atts Shortcode attributes.
	 *
	 * @return string HTML from `self::jetpack_testimonial_shortcode_html()`.
	 */
	public static function jetpack_testimonial_shortcode( $atts ) {
		// Default attributes.
		$atts = shortcode_atts(
			array(
				'display_content' => true, // Can be false, true, or full.
				'image'           => true,
				'columns'         => 1,
				'showposts'       => -1,
				'order'           => 'asc',
				'orderby'         => 'menu_order,date',
			),
			$atts,
			'testimonial'
		);

		// A little sanitization.
		if (
			$atts['display_content']
			&& 'true' != $atts['display_content'] // phpcs:ignore Universal.Operators.StrictComparisons.LooseNotEqual
			&& 'full' !== $atts['display_content']
		) {
			$atts['display_content'] = false;
		}

		if ( $atts['image'] && 'true' != $atts['image'] ) { // phpcs:ignore Universal.Operators.StrictComparisons.LooseNotEqual
			$atts['image'] = false;
		}

		$atts['columns'] = absint( $atts['columns'] );

		$atts['showposts'] = (int) $atts['showposts'];

		if ( $atts['order'] ) {
			$atts['order'] = urldecode( $atts['order'] );
			$atts['order'] = strtoupper( $atts['order'] );
			if ( 'DESC' !== $atts['order'] ) {
				$atts['order'] = 'ASC';
			}
		}

		if ( $atts['orderby'] ) {
			$atts['orderby'] = urldecode( $atts['orderby'] );
			$atts['orderby'] = strtolower( $atts['orderby'] );
			$allowed_keys    = array( 'author', 'date', 'title', 'menu_order', 'rand' );

			$parsed = array();
			foreach ( explode( ',', $atts['orderby'] ) as $orderby ) {
				if ( ! in_array( $orderby, $allowed_keys, true ) ) {
					continue;
				}
				$parsed[] = $orderby;
			}

			if ( empty( $parsed ) ) {
				unset( $atts['orderby'] );
			} else {
				$atts['orderby'] = implode( ' ', $parsed );
			}
		}

		// enqueue shortcode styles when shortcode is used
		if ( ! wp_style_is( 'jetpack-testimonial-style', 'enqueued' ) ) {
			wp_enqueue_style( 'jetpack-testimonial-style', plugins_url( 'css/testimonial-shortcode.css', __FILE__ ), array(), '20140326' );
		}

		return self::jetpack_testimonial_shortcode_html( $atts );
	}

	/**
	 * The Testimonial shortcode loop.
	 *
	 * @param array $atts Shortcode attributes.
	 *
	 * @return string html
	 */
	private static function jetpack_testimonial_shortcode_html( $atts ) {
		// Default query arguments
		$defaults = array(
			'order'          => $atts['order'],
			'orderby'        => $atts['orderby'],
			'posts_per_page' => $atts['showposts'],
		);

		$args              = wp_parse_args( $atts, $defaults );
		$args['post_type'] = self::CUSTOM_POST_TYPE; // Force this post type
		$query             = new WP_Query( $args );

		$testimonial_index_number = 0;

		ob_start();

		// If we have testimonials, create the html
		if ( $query->have_posts() ) {

			?>
			<div class="jetpack-testimonial-shortcode column-<?php echo esc_attr( $atts['columns'] ); ?>">
				<?php
				// Construct the loop...
				while ( $query->have_posts() ) {
					$query->the_post();
					$post_id = get_the_ID();
					?>
					<div class="testimonial-entry <?php echo esc_attr( self::get_testimonial_class( $testimonial_index_number, $atts['columns'], has_post_thumbnail( $post_id ) ) ); ?>">
						<?php
						// The content
						if ( false !== $atts['display_content'] ) {
							if ( 'full' === $atts['display_content'] ) {
								?>
								<div class="testimonial-entry-content"><?php the_content(); ?></div>
								<?php
							} else {
								?>
								<div class="testimonial-entry-content"><?php the_excerpt(); ?></div>
								<?php
							}
						}
						?>
						<span class="testimonial-entry-title">&#8213; <a href="<?php echo esc_url( get_permalink() ); ?>" title="<?php echo esc_attr( the_title_attribute() ); ?>"><?php the_title(); ?></a></span>
						<?php
						// Featured image
						if ( false !== $atts['image'] ) :
							echo self::get_testimonial_thumbnail_link( $post_id ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in method.
						endif;
						?>
					</div><!-- close .testimonial-entry -->
					<?php
					++$testimonial_index_number;
				} // end of while loop

				wp_reset_postdata();
				?>
			</div><!-- close .jetpack-testimonial-shortcode -->
			<?php
		} else {
			?>
			<p><em><?php esc_html_e( 'Your Testimonial Archive currently has no entries. You can start creating them on your dashboard.', 'jetpack' ); ?></p></em>
			<?php
		}
		$html = ob_get_clean();

		// Return the HTML block
		return $html;
	}

	/**
	 * Individual testimonial class
	 *
	 * @param int  $testimonial_index_number iterator count the number of columns up starting from 0.
	 * @param int  $columns number of columns to display the content in.
	 * @param bool $image has a thumbnail or not.
	 *
	 * @return string
	 */
	private static function get_testimonial_class( $testimonial_index_number, $columns, $image ) {
		$class = array();

		$class[] = 'testimonial-entry-column-' . $columns;

		if ( $columns > 1 ) {
			if ( ( $testimonial_index_number % 2 ) === 0 ) {
				$class[] = 'testimonial-entry-mobile-first-item-row';
			} else {
				$class[] = 'testimonial-entry-mobile-last-item-row';
			}
		}

		// add first and last classes to first and last items in a row
		if ( ( $testimonial_index_number % $columns ) === 0 ) {
			$class[] = 'testimonial-entry-first-item-row';
		} elseif ( ( $testimonial_index_number % $columns ) === ( $columns - 1 ) ) {
			$class[] = 'testimonial-entry-last-item-row';
		}

		// add class if testimonial has a featured image
		if ( false !== $image ) {
			$class[] = 'has-testimonial-thumbnail';
		}

		/**
		 * Filter the class applied to testimonial div in the testimonial
		 *
		 * @module custom-content-types
		 *
		 * @since 3.4.0
		 *
		 * @param string $class class name of the div.
		 * @param int $testimonial_index_number iterator count the number of columns up starting from 0.
		 * @param int $columns number of columns to display the content in.
		 * @param boolean $image has a thumbnail or not.
		 */
		return apply_filters( 'testimonial-entry-post-class', implode( ' ', $class ), $testimonial_index_number, $columns, $image ); // phpcs:ignore WordPress.NamingConventions.ValidHookName.UseUnderscores
	}

	/**
	 * Display the featured image if it's available
	 *
	 * @param int $post_id Post ID.
	 *
	 * @return string html
	 */
	private static function get_testimonial_thumbnail_link( $post_id ) {
		if ( has_post_thumbnail( $post_id ) ) {
			/**
			 * Change the thumbnail size for the Testimonial CPT.
			 *
			 * @module custom-content-types
			 *
			 * @since 3.4.0
			 *
			 * @param string|array $var Either a registered size keyword or size array.
			 */
			return '<a class="testimonial-featured-image" href="' . esc_url( get_permalink( $post_id ) ) . '">' . get_the_post_thumbnail( $post_id, apply_filters( 'jetpack_testimonial_thumbnail_size', 'thumbnail' ) ) . '</a>';
		}
	}
}

/**
 * Additional Testimonial customizer options.
 */
function jetpack_testimonial_custom_control_classes() {
	/**
	 * Clean the title parameter.
	 */
	class Jetpack_Testimonial_Title_Control extends WP_Customize_Control {
		/**
		 * Sanitize content passed to control.
		 *
		 * @param string $value Control value.
		 * @return string Sanitized value.
		 */
		public static function sanitize_content( $value ) {
			if ( '' != $value ) { // phpcs:ignore Universal.Operators.StrictComparisons.LooseNotEqual
				$value = trim( convert_chars( wptexturize( $value ) ) );
			}

			return $value;
		}
	}

	/**
	 * Clean textarea content.
	 */
	class Jetpack_Testimonial_Textarea_Control extends WP_Customize_Control {
		/**
		 * Control type.
		 *
		 * @var string
		 */
		public $type = 'textarea';

		/**
		 * Render the control's content.
		 */
		public function render_content() {
			?>
			<label>
				<span class="customize-control-title"><?php echo esc_html( $this->label ); ?></span>
				<textarea rows="5" style="width:100%;" <?php $this->link(); ?>><?php echo esc_textarea( $this->value() ); ?></textarea>
			</label>
			<?php
		}

		/**
		 * Sanitize content passed to control.
		 *
		 * @param string $value Control value.
		 * @return string Sanitized value.
		 */
		public static function sanitize_content( $value ) {
			if ( ! empty( $value ) ) {
				/** This filter is already documented in core. wp-includes/post-template.php */
				$value = apply_filters( 'the_content', $value );
			}

			$value = preg_replace( '@<div id="jp-post-flair"([^>]+)?>(.+)?</div>@is', '', $value ); // Strip WPCOM and Jetpack post flair if included in content

			return $value;
		}
	}
}

add_action( 'init', array( 'Jetpack_Testimonial', 'init' ) );

// Check on plugin activation if theme supports CPT
register_activation_hook( __FILE__, array( 'Jetpack_Testimonial', 'activation_post_type_support' ) );
add_action( 'jetpack_activate_module_custom-content-types', array( 'Jetpack_Testimonial', 'activation_post_type_support' ) );
