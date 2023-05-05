<?php //phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Module Name: Likes
 * Module Description: Give visitors an easy way to show they appreciate your content.
 * First Introduced: 2.2
 * Sort Order: 23
 * Requires Connection: Yes
 * Auto Activate: No
 * Module Tags: Social
 * Feature: Engagement
 * Additional Search Queries: like, likes, wordpress.com
 *
 * @package automattic/jetpack
 */
/**
 * NOTE: While the front-end behavior currently varies, try to keep the data
 * model here the same as on wpcom to facilitate Simple→Atomic moves and
 * possible future work to recombine the front-ends.
 */

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

use Automattic\Jetpack\Assets;

Assets::add_resource_hint(
	array(
		'//widgets.wp.com',
		'//s0.wp.com',
		'//0.gravatar.com',
		'//1.gravatar.com',
		'//2.gravatar.com',
	),
	'dns-prefetch'
);

require_once __DIR__ . '/likes/jetpack-likes-master-iframe.php';
require_once __DIR__ . '/likes/jetpack-likes-settings.php';

/**
 * Jetpack Like Class
 */
class Jetpack_Likes {

	/**
	 * Jetpack_Likes_Settings object
	 *
	 * @var Jetpack_Likes_Settings
	 */
	public $settings;

	/**
	 * Initialize class
	 */
	public static function init() {
		static $instance = null;

		if ( ! $instance ) {
			$instance = new Jetpack_Likes();
		}

		return $instance;
	}

	/**
	 * Constructs Likes class
	 */
	public function __construct() {
		$this->settings = new Jetpack_Likes_Settings();

		// We need to run on wp hook rather than init because we check is_amp_endpoint()
		// when bootstrapping hooks.
		add_action( 'wp', array( $this, 'action_init' ), 99 );

		add_action( 'admin_init', array( $this, 'admin_init' ) );

		add_action( 'jetpack_activate_module_likes', array( $this, 'set_social_notifications_like' ) );
		add_action( 'jetpack_deactivate_module_likes', array( $this, 'delete_social_notifications_like' ) );

		Jetpack::enable_module_configurable( __FILE__ );
		add_filter( 'jetpack_module_configuration_url_likes', array( $this, 'jetpack_likes_configuration_url' ) );
		add_action( 'admin_print_scripts-settings_page_sharing', array( $this, 'load_jp_css' ) );
		add_filter( 'sharing_show_buttons_on_row_start', array( $this, 'configuration_target_area' ) );

		$active = Jetpack::get_active_modules();

		if ( ! in_array( 'sharedaddy', $active, true ) && ! in_array( 'publicize', $active, true ) ) {
			// we don't have a sharing page yet.
			add_action( 'admin_menu', array( $this->settings, 'sharing_menu' ) );
		}

		if ( in_array( 'publicize', $active, true ) && ! in_array( 'sharedaddy', $active, true ) ) {
			// we have a sharing page but not the global options area.
			add_action( 'pre_admin_screen_sharing', array( $this->settings, 'sharing_block' ), 20 );
			add_action( 'pre_admin_screen_sharing', array( $this->settings, 'updated_message' ), -10 );
		}

		if ( ! in_array( 'sharedaddy', $active, true ) ) {
			add_action( 'admin_init', array( $this->settings, 'process_update_requests_if_sharedaddy_not_loaded' ) );
			add_action( 'sharing_global_options', array( $this->settings, 'admin_settings_showbuttonon_init' ), 19 );
			add_action( 'sharing_admin_update', array( $this->settings, 'admin_settings_showbuttonon_callback' ), 19 );
			add_action( 'admin_init', array( $this->settings, 'add_meta_box' ) );
		} else {
			add_filter( 'sharing_meta_box_title', array( $this->settings, 'add_likes_to_sharing_meta_box_title' ) );
			add_action( 'start_sharing_meta_box_content', array( $this->settings, 'meta_box_content' ) );
		}

		add_action( 'admin_init', array( $this, 'admin_discussion_likes_settings_init' ) ); // Likes notifications.

		add_action( 'admin_bar_menu', array( $this, 'admin_bar_likes' ), 60 );

		add_action( 'wp_enqueue_scripts', array( $this, 'load_styles_register_scripts' ) );

		add_action( 'save_post', array( $this->settings, 'meta_box_save' ) );
		add_action( 'edit_attachment', array( $this->settings, 'meta_box_save' ) );
		add_action( 'sharing_global_options', array( $this->settings, 'admin_settings_init' ), 20 );
		add_action( 'sharing_admin_update', array( $this->settings, 'admin_settings_callback' ), 20 );
	}

	/**
	 * Set the social_notifications_like option to `on` when the Likes module is activated.
	 *
	 * @since 3.7.0
	 */
	public function set_social_notifications_like() {
		update_option( 'social_notifications_like', 'on' );
	}

	/**
	 * Delete the social_notifications_like option that was set to `on` on module activation.
	 *
	 * @since 3.7.0
	 */
	public function delete_social_notifications_like() {
		delete_option( 'social_notifications_like' );
	}

	/**
	 * Overrides default configuration url
	 *
	 * @uses admin_url
	 * @return string module settings URL
	 */
	public function jetpack_likes_configuration_url() {
		return admin_url( 'options-general.php?page=sharing#likes' );
	}

	/**
	 * Loads Jetpack's CSS on the sharing page so we can use .jetpack-targetable
	 */
	public function load_jp_css() {
		/**
		* Do we really need `admin_styles`? With the new admin UI, it's breaking some bits.
		* Jetpack::init()->admin_styles();
		*/
	}

	/**
	 * Load scripts and styles for front end.
	 */
	public function load_styles_register_scripts() {
		wp_enqueue_style( 'jetpack_likes', plugins_url( 'likes/style.css', __FILE__ ), array(), JETPACK__VERSION );
		wp_register_script(
			'jetpack_likes_queuehandler',
			Assets::get_file_url_for_environment(
				'_inc/build/likes/queuehandler.min.js',
				'modules/likes/queuehandler.js'
			),
			array(),
			JETPACK__VERSION,
			true
		);
	}

	/**
	 * Adds in the jetpack-targetable class so when we visit sharing#likes our like settings get highlighted by a yellow box
	 *
	 * @param string $html row heading for the sharedaddy "which page" setting.
	 * @return string $html with the jetpack-targetable class and likes id. tbody gets closed after the like settings
	 */
	public function configuration_target_area( $html = '' ) {
		$html = "<tbody id='likes' class='jetpack-targetable'>" . $html;
		return $html;
	}

	/**
	 * Options to be added to the discussion page (see also admin_settings_init, etc below for Sharing settings page)
	 */
	public function admin_discussion_likes_settings_init() {
		// Add a temporary section, until we can move the setting out of there and with the rest of the email notification settings.
		add_settings_section( 'likes-notifications', __( 'Likes Notifications', 'jetpack' ), array( $this, 'admin_discussion_likes_settings_section' ), 'discussion' );
		add_settings_field( 'social-notifications', __( 'Email me whenever', 'jetpack' ), array( $this, 'admin_discussion_likes_settings_field' ), 'discussion', 'likes-notifications' );
		// Register the setting.
		register_setting( 'discussion', 'social_notifications_like', array( $this, 'admin_discussion_likes_settings_validate' ) );
	}

	/** Add email notification options to WordPress discussion settings */
	public function admin_discussion_likes_settings_section() {
		// Atypical usage here.  We emit jquery to move likes notification checkbox to be with the rest of the email notification settings.
		?>
	<script type="text/javascript">
	jQuery( function( $ )  {
		var table = $( '#social_notifications_like' ).parents( 'table:first' ),
			header = table.prevAll( 'h2:first' ),
			newParent = $( '#moderation_notify' ).parent( 'label' ).parent();

		if ( !table.length || !header.length || !newParent.length ) {
			return;
		}

		newParent.append( '<br/>' ).append( table.end().parent( 'label' ).siblings().andSelf() );
		header.remove();
		table.remove();
	} );
	</script>
		<?php
	}

	/** Check if email notifications for likes is on or off.
	 *
	 * @param string $option - which option we're checking (social_notifications_like).
	 */
	public function admin_likes_get_option( $option ) {
		$option_setting = get_option( $option, 'on' );

		return (int) ( 'on' === $option_setting );
	}

	/** Display email notification for likes setting in WordPress' discussion settings. */
	public function admin_discussion_likes_settings_field() {
		$like = $this->admin_likes_get_option( 'social_notifications_like' );
		?>
		<label><input type="checkbox" id="social_notifications_like" name="social_notifications_like" value="1" <?php checked( $like ); ?> /> <?php esc_html_e( 'Someone likes one of my posts', 'jetpack' ); ?></label>
		<?php
	}

	/**
	 * Validate email notification settings.
	 *
	 * @param string $input - determines if checbox is on or off.
	 */
	public function admin_discussion_likes_settings_validate( $input ) {
		// If it's not set (was unchecked during form submission) or was set to off (during option update), return 'off'.
		if ( ! $input || 'off' === $input ) {
			return 'off';
		}
		// Otherwise return 'on'.
		return 'on';
	}

	/** Initialize admin settings */
	public function admin_init() {
		add_filter( 'manage_posts_columns', array( $this, 'add_like_count_column' ) );
		add_filter( 'manage_pages_columns', array( $this, 'add_like_count_column' ) );
		add_action( 'manage_posts_custom_column', array( $this, 'likes_edit_column' ), 10, 2 );
		add_action( 'manage_pages_custom_column', array( $this, 'likes_edit_column' ), 10, 2 );
		add_action( 'admin_print_styles-edit.php', array( $this, 'load_admin_css' ) );
		add_action( 'admin_print_scripts-edit.php', array( $this, 'enqueue_admin_scripts' ) );
	}

	/** Initialize action */
	public function action_init() {
		/*
		 * Only check if the module is enabled here because
		 * we are not currently in The Loop and do not yet have access to check
		 * the switch_like_status post meta flag for the post to be loaded.
		 */
		if ( is_admin() || ! $this->settings->is_likes_module_enabled() ) {
			return;
		}

		if ( ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) ||
			( defined( 'APP_REQUEST' ) && APP_REQUEST ) ||
			( defined( 'REST_API_REQUEST' ) && REST_API_REQUEST ) ||
			( defined( 'COOKIE_AUTH_REQUEST' ) && COOKIE_AUTH_REQUEST ) ||
			( defined( 'JABBER_SERVER' ) && JABBER_SERVER ) ) {
			return;
		}

		if (
			class_exists( 'Jetpack_AMP_Support' )
			&& Jetpack_AMP_Support::is_amp_request()
		) {
			return;
		}

		add_filter( 'the_content', array( $this, 'post_likes' ), 30, 1 );
		add_filter( 'the_excerpt', array( $this, 'post_likes' ), 30, 1 );
	}

	/**
	 * Load the CSS needed for the wp-admin area.
	 */
	public function load_admin_css() {
		?>
		<style type="text/css">
			.vers img { display: none; }
			.metabox-prefs .vers img { display: inline; }
			.fixed .column-likes { width: 5.5em; padding: 8px 0; text-align: left; }
			.fixed .column-stats { width: 5em; }
			.fixed .column-likes .post-com-count {
				-webkit-box-sizing: border-box;
				-moz-box-sizing: border-box;
				box-sizing: border-box;
				display: inline-block;
				padding: 0 8px;
				height: 2em;
				margin-top: 5px;
				-webkit-border-radius: 5px;
				border-radius: 5px;
				background-color: #787c82;
				color: #FFF;
				font-size: 11px;
				line-height: 21px;
			}
			.fixed .column-likes .post-com-count::after { border: none !important; }
			.fixed .column-likes .post-com-count:hover { background-color: #2271b1; }
			.fixed .column-likes .vers:before {
				font: normal 20px/1 dashicons;
				content: '\f155';
				speak: none;
				-webkit-font-smoothing: antialiased;
				-moz-osx-font-smoothing: grayscale;
			}
			@media screen and (max-width: 782px) {
				.fixed .column-likes {
					display: none;
				}
			}
		</style>
		<?php
	}

	/**
	 * Load the JS required for loading the like counts.
	 */
	public function enqueue_admin_scripts() {
		if ( empty( $_GET['post_type'] ) || 'post' === $_GET['post_type'] || 'page' === $_GET['post_type'] ) { //phpcs:ignore WordPress.Security.NonceVerification.Recommended
			wp_enqueue_script(
				'likes-post-count',
				Assets::get_file_url_for_environment(
					'_inc/build/likes/post-count.min.js',
					'modules/likes/post-count.js'
				),
				array( 'jquery' ),
				JETPACK__VERSION,
				$in_footer = false
			);
			wp_enqueue_script(
				'likes-post-count-jetpack',
				Assets::get_file_url_for_environment(
					'_inc/build/likes/post-count-jetpack.min.js',
					'modules/likes/post-count-jetpack.js'
				),
				array( 'jquery', 'likes-post-count' ),
				JETPACK__VERSION,
				$in_footer = false
			);
		}
	}

	/**
	 * Add "Likes" column data to the post edit table in wp-admin.
	 *
	 * @param string $column_name - name of the column.
	 * @param int    $post_id - the post id.
	 */
	public function likes_edit_column( $column_name, $post_id ) {
		if ( 'likes' === $column_name ) {

			$blog_id = Jetpack_Options::get_option( 'id' );

			$permalink = get_permalink( get_the_ID() );
			?>
			<a title="" data-post-id="<?php echo (int) $post_id; ?>" class="post-com-count post-like-count" id="post-like-count-<?php echo (int) $post_id; ?>" data-blog-id="<?php echo (int) $blog_id; ?>" href="<?php echo esc_url( $permalink ); ?>#like-<?php echo (int) $post_id; ?>">
				<span class="comment-count">0</span>
			</a>
			<?php
		}
	}

	/**
	 * Add a "Likes" column header to the post edit table in wp-admin.
	 *
	 * @param array $columns - array of columns in wp-admin.
	 */
	public function add_like_count_column( $columns ) {
		$date = $columns['date'];
		unset( $columns['date'] );

		$columns['likes'] = '<span class="vers"><img title="' . esc_attr__( 'Likes', 'jetpack' ) . '" alt="' . esc_attr__( 'Likes', 'jetpack' ) . '" src="//s0.wordpress.com/i/like-grey-icon.png" /><span class="screen-reader-text">' . __( 'Likes', 'jetpack' ) . '</span></span>';
		$columns['date']  = $date;

		return $columns;
	}

	/**
	 * Append like button to content.
	 *
	 * @param string $content - content of the page.
	 */
	public function post_likes( $content ) {
		global $wp_current_filter;
		$post_id = get_the_ID();

		if ( ! is_numeric( $post_id ) || ! $this->settings->is_likes_visible() ) {
			return $content;
		}

		// Ensure we don't display like button on post excerpts that are hooked inside the post content
		if ( in_array( 'the_excerpt', (array) $wp_current_filter, true ) &&
			in_array( 'the_content', (array) $wp_current_filter, true ) ) {
			return $content;
		}

		$blog_id   = Jetpack_Options::get_option( 'id' );
		$url       = home_url();
		$url_parts = wp_parse_url( $url );
		$domain    = $url_parts['host'];

		// Make sure to include the scripts before the iframe otherwise weird things happen.
		add_action( 'wp_footer', 'jetpack_likes_master_iframe', 21 );

		/**
		* If the same post appears more then once on a page the page goes crazy
		* we need a slightly more unique id / name for the widget wrapper.
		*/
		$uniqid = uniqid();

		$src      = sprintf( 'https://widgets.wp.com/likes/#blog_id=%1$d&amp;post_id=%2$d&amp;origin=%3$s&amp;obj_id=%1$d-%2$d-%4$s', $blog_id, $post_id, $domain, $uniqid );
		$name     = sprintf( 'like-post-frame-%1$d-%2$d-%3$s', $blog_id, $post_id, $uniqid );
		$wrapper  = sprintf( 'like-post-wrapper-%1$d-%2$d-%3$s', $blog_id, $post_id, $uniqid );
		$headline = sprintf(
			/** This filter is already documented in modules/sharedaddy/sharing-service.php */
			apply_filters( 'jetpack_sharing_headline_html', '<h3 class="sd-title">%s</h3>', esc_html__( 'Like this:', 'jetpack' ), 'likes' ),
			esc_html__( 'Like this:', 'jetpack' )
		);

		$title = esc_html__( 'Like or Reblog', 'jetpack' );

		$html  = "<div class='sharedaddy sd-block sd-like jetpack-likes-widget-wrapper jetpack-likes-widget-unloaded' id='$wrapper' data-src='$src' data-name='$name' data-title='$title'>";
		$html .= $headline;
		$html .= "<div class='likes-widget-placeholder post-likes-widget-placeholder' style='height: 55px;'><span class='button'><span>" . esc_html__( 'Like', 'jetpack' ) . '</span></span> <span class="loading">' . esc_html__( 'Loading...', 'jetpack' ) . '</span></div>';
		$html .= "<span class='sd-text-color'></span><a class='sd-link-color'></a>";
		$html .= '</div>';

		// Let's make sure that the script is enqueued.
		wp_enqueue_script( 'jetpack_likes_queuehandler' );

		return $content . $html;
	}

	/** Checks if admin bar is visible.*/
	public function is_admin_bar_button_visible() {
		global $wp_admin_bar;

		if ( ! is_object( $wp_admin_bar ) ) {
			return false;
		}

		if ( ( ! is_singular( 'post' ) && ! is_attachment() && ! is_page() ) ) {
			return false;
		}

		if ( ! $this->settings->is_likes_visible() ) {
			return false;
		}

		if ( ! $this->settings->is_post_likeable() ) {
			return false;
		}

		/**
		 * Filters whether the Like button is enabled in the admin bar.
		 *
		 * @module likes
		 *
		 * @since 2.2.0
		 *
		 * @param bool true Should the Like button be visible in the Admin bar. Default to true.
		 */
		return (bool) apply_filters( 'jetpack_admin_bar_likes_enabled', true );
	}

	/** Adds like section in admin bar. */
	public function admin_bar_likes() {
		global $wp_admin_bar;

		$post_id = get_the_ID();

		if ( ! is_numeric( $post_id ) || ! $this->is_admin_bar_button_visible() ) {
			return;
		}

		$protocol = 'http';
		if ( is_ssl() ) {
			$protocol = 'https';
		}
		$blog_id   = Jetpack_Options::get_option( 'id' );
		$url       = home_url();
		$url_parts = wp_parse_url( $url );
		$domain    = $url_parts['host'];

		// Make sure to include the scripts before the iframe otherwise weird things happen.
		add_action( 'wp_footer', 'jetpack_likes_master_iframe', 21 );

		$src = sprintf( 'https://widgets.wp.com/likes/#blog_id=%2$d&amp;post_id=%3$d&amp;origin=%1$s://%4$s', $protocol, $blog_id, $post_id, $domain );

		$html = "<iframe class='admin-bar-likes-widget jetpack-likes-widget' scrolling='no' frameBorder='0' name='admin-bar-likes-widget' src='$src'></iframe>";

		$node = array(
			'id'   => 'admin-bar-likes-widget',
			'meta' => array(
				'html' => $html,
			),
		);

		$wp_admin_bar->add_node( $node );
	}
}

/**
 * Callback to get the value for the jetpack_likes_enabled field.
 *
 * Warning: this behavior is somewhat complicated!
 * When the switch_like_status post_meta is unset, we follow the global setting in Sharing.
 * When it is set to 0, we disable likes on the post, regardless of the global setting.
 * When it is set to 1, we enable likes on the post, regardless of the global setting.
 *
 * @param array $post - post data we're checking.
 */
function jetpack_post_likes_get_value( array $post ) {
	$post_likes_switched = get_post_meta( $post['id'], 'switch_like_status', true );

	/** This filter is documented in modules/jetpack-likes-settings.php */
	$sitewide_likes_enabled = (bool) apply_filters( 'wpl_is_enabled_sitewide', ! get_option( 'disabled_likes' ) );

	// An empty string: post meta was not set, so go with the global setting.
	if ( '' === $post_likes_switched ) {
		return $sitewide_likes_enabled;
	} elseif ( '0' === $post_likes_switched ) { // User overrode the global setting to disable likes.
		return false;
	} elseif ( '1' === $post_likes_switched ) { // User overrode the global setting to enable likes.
		return true;
	}
	// No default fallback, let's stay explicit.
}

/**
 * Callback to set switch_like_status post_meta when jetpack_likes_enabled is updated.
 *
 * Warning: this behavior is somewhat complicated!
 * When the switch_like_status post_meta is unset, we follow the global setting in Sharing.
 * When it is set to 0, we disable likes on the post, regardless of the global setting.
 * When it is set to 1, we enable likes on the post, regardless of the global setting.
 *
 * @param bool   $enable_post_likes - checks if post likes are enabled.
 * @param object $post_object - object containing post data.
 */
function jetpack_post_likes_update_value( $enable_post_likes, $post_object ) {
	/** This filter is documented in modules/jetpack-likes-settings.php */
	$sitewide_likes_enabled = (bool) apply_filters( 'wpl_is_enabled_sitewide', ! get_option( 'disabled_likes' ) );

	$should_switch_status = $enable_post_likes !== $sitewide_likes_enabled;

	if ( $should_switch_status ) {
		// Set the meta to 0 if the user wants to disable likes, 1 if user wants to enable.
		$switch_like_status = ( $enable_post_likes ? 1 : 0 );
		return update_post_meta( $post_object->ID, 'switch_like_status', $switch_like_status );
	} else {
		// Unset the meta otherwise.
		return delete_post_meta( $post_object->ID, 'switch_like_status' );
	}
}

/**
 * Add Likes post_meta to the REST API Post response.
 *
 * @action rest_api_init
 * @uses register_rest_field
 * @link https://developer.wordpress.org/rest-api/extending-the-rest-api/modifying-responses/
 */
function jetpack_post_likes_register_rest_field() {
	$post_types = get_post_types( array( 'public' => true ) );
	foreach ( $post_types as $post_type ) {
		register_rest_field(
			$post_type,
			'jetpack_likes_enabled',
			array(
				'get_callback'    => 'jetpack_post_likes_get_value',
				'update_callback' => 'jetpack_post_likes_update_value',
				'schema'          => array(
					'description' => __( 'Are Likes enabled?', 'jetpack' ),
					'type'        => 'boolean',
				),
			)
		);

		/**
		 * Ensures all public internal post-types support `likes`
		 * This feature support flag is used by the REST API and Gutenberg.
		 */
		add_post_type_support( $post_type, 'jetpack-post-likes' );
	}
}

// Add Likes post_meta to the REST API Post response.
add_action( 'rest_api_init', 'jetpack_post_likes_register_rest_field' );

// Some CPTs (e.g. Jetpack portfolios and testimonials) get registered with
// restapi_theme_init because they depend on theme support, so let's also hook to that.
add_action( 'restapi_theme_init', 'jetpack_post_likes_register_rest_field', 20 );

/**
 * Set the Likes and Sharing Gutenberg extension availability.
 */
function jetpack_post_likes_set_extension_availability() {
	Jetpack_Gutenberg::set_extension_available( 'likes' );
}

add_action( 'jetpack_register_gutenberg_extensions', 'jetpack_post_likes_set_extension_availability' );

Jetpack_Likes::init();
