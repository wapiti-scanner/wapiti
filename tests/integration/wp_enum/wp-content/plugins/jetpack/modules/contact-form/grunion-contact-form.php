<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Grunion Contact Form
 * Add a contact form to any post, page or text widget.
 * Emails will be sent to the post's author by default, or any email address you choose.
 *
 * @package automattic/jetpack
 */

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Blocks;
use Automattic\Jetpack\Sync\Settings;

define( 'GRUNION_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'GRUNION_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

if ( is_admin() ) {
	require_once GRUNION_PLUGIN_DIR . 'admin.php';
}

add_action( 'rest_api_init', 'grunion_contact_form_require_endpoint' );

/**
 * Require the Grunion endpoint.
 */
function grunion_contact_form_require_endpoint() {
	require_once GRUNION_PLUGIN_DIR . 'class-grunion-contact-form-endpoint.php';
}

/**
 * Sets the 'block_template' attribute on all instances of wp:jetpack/contact-form in
 * the $_wp_current_template_content global variable.
 *
 * The $_wp_current_template_content global variable is hydrated immediately prior to
 * 'template_include' in wp-includes/template-loader.php.
 *
 * This fixes Contact Form Blocks added to FSE _templates_ (e.g. Single or 404).
 *
 * @param string $template Template to be loaded.
 */
function grunion_contact_form_set_block_template_attribute( $template ) {
	global $_wp_current_template_content;
	if ( 'template-canvas.php' === basename( $template ) ) {
		Grunion_Contact_Form::style_on();
		$_wp_current_template_content = grunion_contact_form_apply_block_attribute(
			$_wp_current_template_content,
			array(
				'block_template' => 'canvas',
			)
		);
	}
	return $template;
}
add_filter( 'template_include', 'grunion_contact_form_set_block_template_attribute' );

/**
 * Sets the $grunion_block_template_part_id global.
 *
 * This is part of the fix for Contact Form Blocks added to FSE _template parts_ (e.g footer).
 * The global is processed in Grunion_Contact_Form::parse().
 *
 * @param string $template_part_id ID for the currently rendered template part.
 */
function grunion_contact_form_set_block_template_part_id_global( $template_part_id ) {
	$GLOBALS['grunion_block_template_part_id'] = $template_part_id;
}
add_action( 'render_block_core_template_part_post', 'grunion_contact_form_set_block_template_part_id_global' );
add_action( 'render_block_core_template_part_file', 'grunion_contact_form_set_block_template_part_id_global' );
add_action( 'render_block_core_template_part_none', 'grunion_contact_form_set_block_template_part_id_global' );
add_action( 'gutenberg_render_block_core_template_part_post', 'grunion_contact_form_set_block_template_part_id_global' );
add_action( 'gutenberg_render_block_core_template_part_file', 'grunion_contact_form_set_block_template_part_id_global' );
add_action( 'gutenberg_render_block_core_template_part_none', 'grunion_contact_form_set_block_template_part_id_global' );

/**
 * Unsets the global when block is done rendering.
 *
 * @param string $content Rendered block content.
 * @param array  $block   The full block, including name and attributes.
 * @return string
 */
function grunion_contact_form_unset_block_template_part_id_global( $content, $block ) {
	if ( isset( $block['blockName'] )
		&& 'core/template-part' === $block['blockName']
		&& isset( $GLOBALS['grunion_block_template_part_id'] ) ) {
		unset( $GLOBALS['grunion_block_template_part_id'] );
	}
	return $content;
}
add_filter( 'render_block', 'grunion_contact_form_unset_block_template_part_id_global', 10, 2 );

/**
 * Sets the 'widget' attribute on all instances of the contact form in the widget block.
 *
 * @param string          $content  Existing widget block content.
 * @param array           $instance Array of settings for the current widget.
 * @param WP_Widget_Block $widget   Current Block widget instance.
 * @return string
 */
function grunion_contact_form_filter_widget_block_content( $content, $instance, $widget ) {
	Grunion_Contact_Form::style_on();
	// Inject 'block_template' => <widget-id> into all instances of the contact form block.
	return grunion_contact_form_apply_block_attribute(
		$content,
		array(
			'widget' => $widget->id,
		)
	);
}
add_filter( 'widget_block_content', 'grunion_contact_form_filter_widget_block_content', 1, 3 );

/**
 * Adds a given attribute to all instances of the Contact Form block.
 *
 * @param string $content  Existing content to process.
 * @param array  $new_attr New attributes to add.
 * @return string
 */
function grunion_contact_form_apply_block_attribute( $content, $new_attr ) {
	if ( false === stripos( $content, 'wp:jetpack/contact-form' ) ) {
		return $content;
	}
	return preg_replace_callback(
		'/<!--\s+(?P<closer>\/)?wp:jetpack\/?contact-form\s+(?P<attrs>{(?:(?:[^}]+|}+(?=})|(?!}\s+\/?-->).)*+)?}\s+)?(?P<void>\/)?-->/s',
		function ( $match ) use ( $new_attr ) {
			// Ignore block closers.
			if ( ! empty( $match['closer'] ) ) {
				return $match[0];
			}
			// If block doesn't have attributes, add our own.
			if ( empty( $match['attrs'] ) ) {
				return str_replace(
					'wp:jetpack/contact-form ',
					'wp:jetpack/contact-form ' . wp_json_encode( $new_attr ) . ' ',
					$match[0]
				);
			}
			// $match['attrs'] includes trailing space: '{"customThankyou":"message"} '.
			$attrs = json_decode( rtrim( $match['attrs'], ' ' ), true );
			$attrs = array_merge( $attrs, $new_attr );
			return str_replace(
				$match['attrs'],
				wp_json_encode( $attrs ) . ' ',
				$match[0]
			);
		},
		$content
	);
}

/**
 * Sets up various actions, filters, post types, post statuses, shortcodes.
 */
class Grunion_Contact_Form_Plugin {

	/**
	 *
	 * The Widget ID of the widget currently being processed.  Used to build the unique contact-form ID for forms embedded in widgets.
	 *
	 * @var string
	 */
	public $current_widget_id;

	/**
	 * If the contact form field is being used.
	 *
	 * @var bool
	 */
	public static $using_contact_form_field = false;

	/**
	 *
	 * The last Feedback Post ID Erased as part of the Personal Data Eraser.
	 * Helps with pagination.
	 *
	 * @var int
	 */
	private $pde_last_post_id_erased = 0;

	/**
	 *
	 * The email address for which we are deleting/exporting all feedbacks
	 * as part of a Personal Data Eraser or Personal Data Exporter request.
	 *
	 * @var string
	 */
	private $pde_email_address = '';

	/**
	 * Initializing function.
	 */
	public static function init() {
		static $instance = false;

		if ( ! $instance ) {
			$instance = new Grunion_Contact_Form_Plugin();

			// Schedule our daily cleanup
			add_action( 'wp_scheduled_delete', array( $instance, 'daily_akismet_meta_cleanup' ) );
		}

		return $instance;
	}

	/**
	 * Runs daily to clean up spam detection metadata after 15 days.  Keeps your DB squeaky clean.
	 */
	public function daily_akismet_meta_cleanup() {
		global $wpdb;

		$feedback_ids = $wpdb->get_col( "SELECT p.ID FROM {$wpdb->posts} as p INNER JOIN {$wpdb->postmeta} as m on m.post_id = p.ID WHERE p.post_type = 'feedback' AND m.meta_key = '_feedback_akismet_values' AND DATE_SUB(NOW(), INTERVAL 15 DAY) > p.post_date_gmt LIMIT 10000" );

		if ( empty( $feedback_ids ) ) {
			return;
		}

		/**
		 * Fires right before deleting the _feedback_akismet_values post meta on $feedback_ids
		 *
		 * @module contact-form
		 *
		 * @since 6.1.0
		 *
		 * @param array $feedback_ids list of feedback post ID
		 */
		do_action( 'jetpack_daily_akismet_meta_cleanup_before', $feedback_ids );
		foreach ( $feedback_ids as $feedback_id ) {
			delete_post_meta( $feedback_id, '_feedback_akismet_values' );
		}

		/**
		 * Fires right after deleting the _feedback_akismet_values post meta on $feedback_ids
		 *
		 * @module contact-form
		 *
		 * @since 6.1.0
		 *
		 * @param array $feedback_ids list of feedback post ID
		 */
		do_action( 'jetpack_daily_akismet_meta_cleanup_after', $feedback_ids );
	}

	/**
	 * Strips HTML tags from input.  Output is NOT HTML safe.
	 *
	 * @param mixed $data_with_tags - data we're stripping HTML tags from.
	 * @return mixed
	 */
	public static function strip_tags( $data_with_tags ) {
		$data_without_tags = array();
		if ( is_array( $data_with_tags ) ) {
			foreach ( $data_with_tags as $index => $value ) {
				$index = sanitize_text_field( (string) $index );
				$value = wp_kses( (string) $value, array() );
				$value = str_replace( '&amp;', '&', $value ); // undo damage done by wp_kses_normalize_entities()

				$data_without_tags[ $index ] = $value;
			}
		} else {
			$data_without_tags = wp_kses( (string) $data_with_tags, array() );
			$data_without_tags = str_replace( '&amp;', '&', $data_without_tags ); // undo damage done by wp_kses_normalize_entities()
		}

		return $data_without_tags;
	}

	/**
	 * Class uses singleton pattern; use Grunion_Contact_Form_Plugin::init() to initialize.
	 */
	protected function __construct() {
		$this->add_shortcode();

		// While generating the output of a text widget with a contact-form shortcode, we need to know its widget ID.
		add_action( 'dynamic_sidebar', array( $this, 'track_current_widget' ) );

		// Add a "widget" shortcode attribute to all contact-form shortcodes embedded in widgets
		add_filter( 'widget_text', array( $this, 'widget_atts' ), 0 );

		// If Text Widgets don't get shortcode processed, hack ours into place.
		if (
			version_compare( get_bloginfo( 'version' ), '4.9-z', '<=' )
			&& ! has_filter( 'widget_text', 'do_shortcode' )
		) {
			add_filter( 'widget_text', array( $this, 'widget_shortcode_hack' ), 5 );
		}

		add_filter( 'jetpack_contact_form_is_spam', array( $this, 'is_spam_blocklist' ), 10, 2 );
		add_filter( 'jetpack_contact_form_in_comment_disallowed_list', array( $this, 'is_in_disallowed_list' ), 10, 2 );
		// Akismet to the rescue
		if ( defined( 'AKISMET_VERSION' ) || function_exists( 'akismet_http_post' ) ) {
			add_filter( 'jetpack_contact_form_is_spam', array( $this, 'is_spam_akismet' ), 10, 2 );
			add_action( 'contact_form_akismet', array( $this, 'akismet_submit' ), 10, 2 );
		}

		add_action( 'loop_start', array( 'Grunion_Contact_Form', 'style_on' ) );
		add_action( 'pre_amp_render_post', array( 'Grunion_Contact_Form', 'style_on' ) );

		add_action( 'wp_ajax_grunion-contact-form', array( $this, 'ajax_request' ) );
		add_action( 'wp_ajax_nopriv_grunion-contact-form', array( $this, 'ajax_request' ) );

		// GDPR: personal data exporter & eraser.
		add_filter( 'wp_privacy_personal_data_exporters', array( $this, 'register_personal_data_exporter' ) );
		add_filter( 'wp_privacy_personal_data_erasers', array( $this, 'register_personal_data_eraser' ) );

		// Export to CSV feature
		if ( is_admin() ) {
			add_action( 'wp_ajax_feedback_export', array( $this, 'download_feedback_as_csv' ) );
		}
		add_action( 'admin_menu', array( $this, 'admin_menu' ) );
		add_action( 'current_screen', array( $this, 'unread_count' ) );

		add_filter( 'use_block_editor_for_post_type', array( $this, 'use_block_editor_for_post_type' ), 10, 2 );

		// custom post type we'll use to keep copies of the feedback items
		register_post_type(
			'feedback',
			array(
				'labels'                => array(
					'name'               => __( 'Form Responses', 'jetpack' ),
					'singular_name'      => __( 'Form Responses', 'jetpack' ),
					'search_items'       => __( 'Search Responses', 'jetpack' ),
					'not_found'          => __( 'No responses found', 'jetpack' ),
					'not_found_in_trash' => __( 'No responses found', 'jetpack' ),
				),
				'menu_icon'             => 'dashicons-feedback',
				'show_ui'               => true,
				'show_in_menu'          => false,
				'show_in_admin_bar'     => false,
				'public'                => false,
				'rewrite'               => false,
				'query_var'             => false,
				'capability_type'       => 'page',
				'show_in_rest'          => true,
				'rest_controller_class' => 'Grunion_Contact_Form_Endpoint',
				'capabilities'          => array(
					'create_posts'        => 'do_not_allow',
					'publish_posts'       => 'publish_pages',
					'edit_posts'          => 'edit_pages',
					'edit_others_posts'   => 'edit_others_pages',
					'delete_posts'        => 'delete_pages',
					'delete_others_posts' => 'delete_others_pages',
					'read_private_posts'  => 'read_private_pages',
					'edit_post'           => 'edit_page',
					'delete_post'         => 'delete_page',
					'read_post'           => 'read_page',
				),
				'map_meta_cap'          => true,
			)
		);

		// Add to REST API post type allowed list.
		add_filter( 'rest_api_allowed_post_types', array( $this, 'allow_feedback_rest_api_type' ) );

		// Add "spam" as a post status
		register_post_status(
			'spam',
			array(
				'label'                  => 'Spam',
				'public'                 => false,
				'exclude_from_search'    => true,
				'show_in_admin_all_list' => false,
				// translators: The spam count.
				'label_count'            => _n_noop( 'Spam <span class="count">(%s)</span>', 'Spam <span class="count">(%s)</span>', 'jetpack' ),
				'protected'              => true,
				'_builtin'               => false,
			)
		);

		// POST handler
		if (
			isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) )
			&&
			isset( $_POST['action'] ) && 'grunion-contact-form' === $_POST['action'] // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce verification should happen when hook fires.
			&&
			isset( $_POST['contact-form-id'] ) // phpcs:ignore WordPress.Security.NonceVerification.Missing -- no site changes
		) {
			add_action( 'template_redirect', array( $this, 'process_form_submission' ) );
		}

		/*
		 * Can be dequeued by placing the following in wp-content/themes/yourtheme/functions.php
		 *
		 *  function remove_grunion_style() {
		 *      wp_deregister_style('grunion.css');
		 *  }
		 *  add_action('wp_print_styles', 'remove_grunion_style');
		 */
		wp_register_style( 'grunion.css', GRUNION_PLUGIN_URL . 'css/grunion.css', array(), JETPACK__VERSION );
		wp_style_add_data( 'grunion.css', 'rtl', 'replace' );

		self::register_contact_form_blocks();
	}

	/**
	 * Enqueue scripts responsible for handling contact form styles.
	 */
	private static function enqueue_contact_forms_style_script() {
		add_filter( 'js_do_concat', array( __CLASS__, 'disable_forms_style_script_concat' ), 10, 3 );
		Jetpack_Gutenberg::load_assets_as_required( 'contact-form' );
	}

	/**
	 * Prevent 'contact-form-styles' script from being concatenated.
	 *
	 * @param array  $do_concat - the concatenation flag.
	 * @param string $handle - script name.
	 */
	public static function disable_forms_style_script_concat( $do_concat, $handle ) {
		if ( 'jetpack-block-contact-form' === $handle ) {
			$do_concat = false;
		}
		return $do_concat;
	}

	/**
	 * Register the contact form block.
	 */
	private static function register_contact_form_blocks() {
		Blocks::jetpack_register_block(
			'jetpack/contact-form',
			array(
				'render_callback' => array( __CLASS__, 'gutenblock_render_form' ),
			)
		);

		// Field render methods.
		Blocks::jetpack_register_block(
			'jetpack/field-text',
			array(
				'render_callback' => array( __CLASS__, 'gutenblock_render_field_text' ),
			)
		);
		Blocks::jetpack_register_block(
			'jetpack/field-name',
			array(
				'render_callback' => array( __CLASS__, 'gutenblock_render_field_name' ),
			)
		);
		Blocks::jetpack_register_block(
			'jetpack/field-email',
			array(
				'render_callback' => array( __CLASS__, 'gutenblock_render_field_email' ),
			)
		);
		Blocks::jetpack_register_block(
			'jetpack/field-url',
			array(
				'render_callback' => array( __CLASS__, 'gutenblock_render_field_url' ),
			)
		);
		Blocks::jetpack_register_block(
			'jetpack/field-date',
			array(
				'render_callback' => array( __CLASS__, 'gutenblock_render_field_date' ),
			)
		);
		Blocks::jetpack_register_block(
			'jetpack/field-telephone',
			array(
				'render_callback' => array( __CLASS__, 'gutenblock_render_field_telephone' ),
			)
		);
		Blocks::jetpack_register_block(
			'jetpack/field-textarea',
			array(
				'render_callback' => array( __CLASS__, 'gutenblock_render_field_textarea' ),
			)
		);
		Blocks::jetpack_register_block(
			'jetpack/field-checkbox',
			array(
				'render_callback' => array( __CLASS__, 'gutenblock_render_field_checkbox' ),
			)
		);
		Blocks::jetpack_register_block(
			'jetpack/field-checkbox-multiple',
			array(
				'render_callback' => array( __CLASS__, 'gutenblock_render_field_checkbox_multiple' ),
			)
		);
		Blocks::jetpack_register_block(
			'jetpack/field-option-checkbox',
			array(
				'render_callback' => array( __CLASS__, 'gutenblock_render_field_option' ),
			)
		);
		Blocks::jetpack_register_block(
			'jetpack/field-radio',
			array(
				'render_callback' => array( __CLASS__, 'gutenblock_render_field_radio' ),
			)
		);
		Blocks::jetpack_register_block(
			'jetpack/field-option-radio',
			array(
				'render_callback' => array( __CLASS__, 'gutenblock_render_field_option' ),
			)
		);
		Blocks::jetpack_register_block(
			'jetpack/field-select',
			array(
				'render_callback' => array( __CLASS__, 'gutenblock_render_field_select' ),
			)
		);
		Blocks::jetpack_register_block(
			'jetpack/field-consent',
			array(
				'render_callback' => array( __CLASS__, 'gutenblock_render_field_consent' ),
			)
		);
	}

	/**
	 * Render the gutenblock form.
	 *
	 * @param array  $atts - the block attributes.
	 * @param string $content - html content.
	 *
	 * @return string
	 */
	public static function gutenblock_render_form( $atts, $content ) {
		// Render fallback in other contexts than frontend (i.e. feed, emails, API, etc.), unless the form is being submitted.
		if ( ! jetpack_is_frontend() && ! isset( $_POST['contact-form-id'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			return sprintf(
				'<div class="%1$s"><a href="%2$s" target="_blank" rel="noopener noreferrer">%3$s</a></div>',
				esc_attr( Blocks::classes( 'contact-form', $atts ) ),
				esc_url( get_the_permalink() ),
				esc_html__( 'Submit a form.', 'jetpack' )
			);
		}

		self::enqueue_contact_forms_style_script();

		return Grunion_Contact_Form::parse( $atts, do_blocks( $content ) );
	}

	/**
	 * Turn block attribute to shortcode attributes.
	 *
	 * @param array  $atts - the block attributes.
	 * @param string $type - the type.
	 *
	 * @return array
	 */
	public static function block_attributes_to_shortcode_attributes( $atts, $type ) {
		$atts['type'] = $type;
		if ( isset( $atts['className'] ) ) {
			$atts['class'] = $atts['className'];
			unset( $atts['className'] );
		}

		if ( isset( $atts['defaultValue'] ) ) {
			$atts['default'] = $atts['defaultValue'];
			unset( $atts['defaultValue'] );
		}

		return $atts;
	}

	/**
	 * Render the text field.
	 *
	 * @param array  $atts - the block attributes.
	 * @param string $content - html content.
	 *
	 * @return string HTML for the contact form field.
	 */
	public static function gutenblock_render_field_text( $atts, $content ) {
		$atts = self::block_attributes_to_shortcode_attributes( $atts, 'text' );
		return Grunion_Contact_Form::parse_contact_field( $atts, $content );
	}

	/**
	 * Render the name field.
	 *
	 * @param array  $atts - the block attributes.
	 * @param string $content - html content.
	 *
	 * @return string HTML for the contact form field.
	 */
	public static function gutenblock_render_field_name( $atts, $content ) {
		$atts = self::block_attributes_to_shortcode_attributes( $atts, 'name' );
		return Grunion_Contact_Form::parse_contact_field( $atts, $content );
	}

	/**
	 * Render the email field.
	 *
	 * @param array  $atts - the block attributes.
	 * @param string $content - html content.
	 *
	 * @return string HTML for the contact form field.
	 */
	public static function gutenblock_render_field_email( $atts, $content ) {
		$atts = self::block_attributes_to_shortcode_attributes( $atts, 'email' );
		return Grunion_Contact_Form::parse_contact_field( $atts, $content );
	}

	/**
	 * Render the url field.
	 *
	 * @param array  $atts - the block attributes.
	 * @param string $content - html content.
	 *
	 * @return string HTML for the contact form field.
	 */
	public static function gutenblock_render_field_url( $atts, $content ) {
		$atts = self::block_attributes_to_shortcode_attributes( $atts, 'url' );
		return Grunion_Contact_Form::parse_contact_field( $atts, $content );
	}

	/**
	 * Render the date field.
	 *
	 * @param array  $atts - the block attributes.
	 * @param string $content - html content.
	 *
	 * @return string HTML for the contact form field.
	 */
	public static function gutenblock_render_field_date( $atts, $content ) {
		$atts = self::block_attributes_to_shortcode_attributes( $atts, 'date' );
		return Grunion_Contact_Form::parse_contact_field( $atts, $content );
	}

	/**
	 * Render the telephone field.
	 *
	 * @param array  $atts - the block attributes.
	 * @param string $content - html content.
	 *
	 * @return string HTML for the contact form field.
	 */
	public static function gutenblock_render_field_telephone( $atts, $content ) {
		$atts = self::block_attributes_to_shortcode_attributes( $atts, 'telephone' );
		return Grunion_Contact_Form::parse_contact_field( $atts, $content );
	}

	/**
	 * Render the text area field.
	 *
	 * @param array  $atts - the block attributes.
	 * @param string $content - html content.
	 *
	 * @return string HTML for the contact form field.
	 */
	public static function gutenblock_render_field_textarea( $atts, $content ) {
		$atts = self::block_attributes_to_shortcode_attributes( $atts, 'textarea' );
		return Grunion_Contact_Form::parse_contact_field( $atts, $content );
	}

	/**
	 * Render the checkbox field.
	 *
	 * @param array  $atts - the block attributes.
	 * @param string $content - html content.
	 *
	 * @return string HTML for the contact form field.
	 */
	public static function gutenblock_render_field_checkbox( $atts, $content ) {
		$atts = self::block_attributes_to_shortcode_attributes( $atts, 'checkbox' );
		return Grunion_Contact_Form::parse_contact_field( $atts, $content );
	}

	/**
	 * Render the multiple checkbox field.
	 *
	 * @param array  $atts - the block attributes.
	 * @param string $content - html content.
	 *
	 * @return string HTML for the contact form field.
	 */
	public static function gutenblock_render_field_checkbox_multiple( $atts, $content ) {
		$atts = self::block_attributes_to_shortcode_attributes( $atts, 'checkbox-multiple' );
		return Grunion_Contact_Form::parse_contact_field( $atts, $content );
	}

	/**
	 * Render the multiple choice field option.
	 *
	 * @param array  $atts - the block attributes.
	 * @param string $content - html content.
	 *
	 * @return string HTML for the contact form field.
	 */
	public static function gutenblock_render_field_option( $atts, $content ) {
		$atts = self::block_attributes_to_shortcode_attributes( $atts, 'field-option' );
		return Grunion_Contact_Form::parse_contact_field( $atts, $content );
	}

	/**
	 * Render the radio button field.
	 *
	 * @param array  $atts - the block attributes.
	 * @param string $content - html content.
	 *
	 * @return string HTML for the contact form field.
	 */
	public static function gutenblock_render_field_radio( $atts, $content ) {
		$atts = self::block_attributes_to_shortcode_attributes( $atts, 'radio' );
		return Grunion_Contact_Form::parse_contact_field( $atts, $content );
	}

	/**
	 * Render the select field.
	 *
	 * @param array  $atts - the block attributes.
	 * @param string $content - html content.
	 *
	 * @return string HTML for the contact form field.
	 */
	public static function gutenblock_render_field_select( $atts, $content ) {
		$atts = self::block_attributes_to_shortcode_attributes( $atts, 'select' );
		return Grunion_Contact_Form::parse_contact_field( $atts, $content );
	}

	/**
	 * Render the consent field.
	 *
	 * @param string $atts consent attributes.
	 * @param string $content html content.
	 */
	public static function gutenblock_render_field_consent( $atts, $content ) {
		$atts = self::block_attributes_to_shortcode_attributes( $atts, 'consent' );

		if ( ! isset( $atts['implicitConsentMessage'] ) ) {
			$atts['implicitConsentMessage'] = __( "By submitting your information, you're giving us permission to email you. You may unsubscribe at any time.", 'jetpack' );
		}

		if ( ! isset( $atts['explicitConsentMessage'] ) ) {
			$atts['explicitConsentMessage'] = __( 'Can we send you an email from time to time?', 'jetpack' );
		}

		return Grunion_Contact_Form::parse_contact_field( $atts, $content );
	}

	/**
	 * Add the 'Form Responses' menu item as a submenu of Feedback.
	 */
	public function admin_menu() {
		$slug = 'feedback';

		add_menu_page(
			__( 'Feedback', 'jetpack' ),
			__( 'Feedback', 'jetpack' ),
			'edit_pages',
			$slug,
			null,
			'dashicons-feedback',
			45
		);

		add_submenu_page(
			$slug,
			__( 'Form Responses', 'jetpack' ),
			__( 'Form Responses', 'jetpack' ),
			'edit_pages',
			'edit.php?post_type=feedback',
			null,
			0
		);

		remove_submenu_page(
			$slug,
			$slug
		);
	}

	/**
	 * Add to REST API post type allowed list.
	 *
	 * @param array $post_types - the post types.
	 */
	public function allow_feedback_rest_api_type( $post_types ) {
		$post_types[] = 'feedback';
		return $post_types;
	}

	/**
	 * Display the count of new feedback entries received. It's reset when user visits the Feedback screen.
	 *
	 * @since 4.1.0
	 *
	 * @param object $screen Information about the current screen.
	 */
	public function unread_count( $screen ) {
		if ( isset( $screen->post_type ) && 'feedback' === $screen->post_type ) {
			update_option( 'feedback_unread_count', 0 );
		} else {
			global $submenu;
			if ( isset( $submenu['feedback'] ) && is_array( $submenu['feedback'] ) && ! empty( $submenu['feedback'] ) ) {
				foreach ( $submenu['feedback'] as $index => $menu_item ) {
					if ( 'edit.php?post_type=feedback' === $menu_item[2] ) {
						$unread = get_option( 'feedback_unread_count', 0 );
						if ( $unread > 0 ) {
							$unread_count = current_user_can( 'publish_pages' ) ? " <span class='feedback-unread count-{$unread} awaiting-mod'><span class='feedback-unread-count'>" . number_format_i18n( $unread ) . '</span></span>' : '';

							// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
							$submenu['feedback'][ $index ][0] .= $unread_count;
						}
						break;
					}
				}
			}
		}
	}

	/**
	 * Handles all contact-form POST submissions
	 *
	 * Conditionally attached to `template_redirect`
	 */
	public function process_form_submission() {
		// Add a filter to replace tokens in the subject field with sanitized field values.
		add_filter( 'contact_form_subject', array( $this, 'replace_tokens_with_input' ), 10, 2 );

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Checked below for logged-in users only, see https://plugins.trac.wordpress.org/ticket/1859
		$id   = isset( $_POST['contact-form-id'] ) ? sanitize_text_field( wp_unslash( $_POST['contact-form-id'] ) ) : null;
		$hash = isset( $_POST['contact-form-hash'] ) ? sanitize_text_field( wp_unslash( $_POST['contact-form-hash'] ) ) : null;
		$hash = is_string( $hash ) ? preg_replace( '/[^\da-f]/i', '', $hash ) : $hash;
		// phpcs:enable

		if ( ! is_string( $id ) || ! is_string( $hash ) ) {
			return false;
		}

		if ( is_user_logged_in() ) {
			check_admin_referer( "contact-form_{$id}" );
		}

		$is_widget              = 0 === strpos( $id, 'widget-' );
		$is_block_template      = 0 === strpos( $id, 'block-template-' );
		$is_block_template_part = 0 === strpos( $id, 'block-template-part-' );

		$form = false;

		if ( $is_widget ) {
			// It's a form embedded in a text widget
			$this->current_widget_id = substr( $id, 7 ); // remove "widget-"
			$widget_type             = implode( '-', array_slice( explode( '-', $this->current_widget_id ), 0, -1 ) ); // Remove trailing -#

			// Is the widget active?
			$sidebar = is_active_widget( false, $this->current_widget_id, $widget_type );

			// This is lame - no core API for getting a widget by ID
			$widget = isset( $GLOBALS['wp_registered_widgets'][ $this->current_widget_id ] ) ? $GLOBALS['wp_registered_widgets'][ $this->current_widget_id ] : false;

			if ( $sidebar && $widget && isset( $widget['callback'] ) ) {
				// prevent PHP notices by populating widget args
				$widget_args = array(
					'before_widget' => '',
					'after_widget'  => '',
					'before_title'  => '',
					'after_title'   => '',
				);
				// This is lamer - no API for outputting a given widget by ID
				ob_start();
				// Process the widget to populate Grunion_Contact_Form::$last
				call_user_func( $widget['callback'], $widget_args, $widget['params'][0] );
				ob_end_clean();
			}
		} elseif ( $is_block_template ) {
			/*
			 * Recreate the logic in wp-includes/template-loader.php
			 * that happens *after* 'template_redirect'.
			 *
			 * This logic populates the $_wp_current_template_content
			 * global, which we need in order to render the contact
			 * form for this block template.
			 */
			// start of copy-pasta from wp-includes/template-loader.php.
			$tag_templates = array(
				'is_embed'             => 'get_embed_template',
				'is_404'               => 'get_404_template',
				'is_search'            => 'get_search_template',
				'is_front_page'        => 'get_front_page_template',
				'is_home'              => 'get_home_template',
				'is_privacy_policy'    => 'get_privacy_policy_template',
				'is_post_type_archive' => 'get_post_type_archive_template',
				'is_tax'               => 'get_taxonomy_template',
				'is_attachment'        => 'get_attachment_template',
				'is_single'            => 'get_single_template',
				'is_page'              => 'get_page_template',
				'is_singular'          => 'get_singular_template',
				'is_category'          => 'get_category_template',
				'is_tag'               => 'get_tag_template',
				'is_author'            => 'get_author_template',
				'is_date'              => 'get_date_template',
				'is_archive'           => 'get_archive_template',
			);
			$template      = false;
			// Loop through each of the template conditionals, and find the appropriate template file.
			// This is what calls locate_block_template() to hydrate $_wp_current_template_content.
			foreach ( $tag_templates as $tag => $template_getter ) {
				if ( call_user_func( $tag ) ) {
					$template = call_user_func( $template_getter );
				}
				if ( $template ) {
					if ( 'is_attachment' === $tag ) {
						remove_filter( 'the_content', 'prepend_attachment' );
					}
					break;
				}
			}
			if ( ! $template ) {
				$template = get_index_template();
			}
			// end of copy-pasta from wp-includes/template-loader.php.

			// Ensure 'block_template' attribute is added to any shortcodes in the template.
			$template = grunion_contact_form_set_block_template_attribute( $template );

			// Process the block template to populate Grunion_Contact_Form::$last
			get_the_block_template_html();
		} elseif ( $is_block_template_part ) {
			$block_template_part_id   = str_replace( 'block-template-part-', '', $id );
			$bits                     = explode( '//', $block_template_part_id );
			$block_template_part_slug = array_pop( $bits );
			// Process the block part template to populate Grunion_Contact_Form::$last
			$attributes = array(
				'theme'   => wp_get_theme()->get_stylesheet(),
				'slug'    => $block_template_part_slug,
				'tagName' => 'div',
			);
			do_blocks( '<!-- wp:template-part ' . wp_json_encode( $attributes ) . ' /-->' );
		} else {
			// It's a form embedded in a post
			$post = get_post( $id );

			// Process the content to populate Grunion_Contact_Form::$last
			if ( $post ) {
				/** This filter is already documented in core. wp-includes/post-template.php */
				apply_filters( 'the_content', $post->post_content );
			}
		}

		$form = isset( Grunion_Contact_Form::$forms[ $hash ] ) ? Grunion_Contact_Form::$forms[ $hash ] : null;

		// No form may mean user is using do_shortcode, grab the form using the stored post meta
		if ( ! $form && is_numeric( $id ) && $hash ) {

			// Get shortcode from post meta
			$shortcode = get_post_meta( $id, "_g_feedback_shortcode_{$hash}", true );

			// Format it
			if ( $shortcode !== '' && $shortcode !== false ) {

				// Get attributes from post meta.
				$parameters = '';
				$attributes = get_post_meta( $id, "_g_feedback_shortcode_atts_{$hash}", true );
				if ( ! empty( $attributes ) && is_array( $attributes ) ) {
					foreach ( array_filter( $attributes ) as $param => $value ) {
						$parameters .= " $param=\"$value\"";
					}
				}

				$shortcode = '[contact-form' . $parameters . ']' . $shortcode . '[/contact-form]';
				do_shortcode( $shortcode );

				// Recreate form
				$form = Grunion_Contact_Form::$last;
			}
		}

		if ( ! $form ) {
			return false;
		}

		if ( is_wp_error( $form->errors ) && $form->errors->get_error_codes() ) {
			return $form->errors;
		}

		// Process the form
		return $form->process_submission();
	}

	/**
	 * Handle the ajax request.
	 */
	public function ajax_request() {
		$submission_result = self::process_form_submission();

		if ( ! $submission_result ) {
			header( 'HTTP/1.1 500 Server Error', 500, true );
			echo '<div class="form-error"><ul class="form-errors"><li class="form-error-message">';
			esc_html_e( 'An error occurred. Please try again later.', 'jetpack' );
			echo '</li></ul></div>';
		} elseif ( is_wp_error( $submission_result ) ) {
			header( 'HTTP/1.1 400 Bad Request', 403, true );
			echo '<div class="form-error"><ul class="form-errors"><li class="form-error-message">';
			echo esc_html( $submission_result->get_error_message() );
			echo '</li></ul></div>';
		} else {
			echo '<h4>' . esc_html__( 'Your message has been sent', 'jetpack' ) . '</h4>' . wp_kses(
				$submission_result,
				array(
					'br'         => array(),
					'blockquote' => array( 'class' => array() ),
					'p'          => array(),
				)
			);
		}

		die;
	}

	/**
	 * Ensure the post author is always zero for contact-form feedbacks
	 * Attached to `wp_insert_post_data`
	 *
	 * @see Grunion_Contact_Form::process_submission()
	 *
	 * @param array $data the data to insert.
	 * @param array $postarr the data sent to wp_insert_post().
	 * @return array The filtered $data to insert.
	 */
	public function insert_feedback_filter( $data, $postarr ) {
		if ( $data['post_type'] === 'feedback' && $postarr['post_type'] === 'feedback' ) {
			$data['post_author'] = 0;
		}

		return $data;
	}

	/**
	 * Adds our contact-form shortcode
	 * The "child" contact-field shortcode is enabled as needed by the contact-form shortcode handler
	 */
	public function add_shortcode() {
		add_shortcode( 'contact-form', array( 'Grunion_Contact_Form', 'parse' ) );
		add_shortcode( 'contact-field', array( 'Grunion_Contact_Form', 'parse_contact_field' ) );

		// We need 'contact-field-option' to be registered, so it's included to the get_shortcode_regex() method
		// But we don't need a callback because we're handling contact-field-option manually
		add_shortcode( 'contact-field-option', '__return_null' );
	}

	/**
	 * Tokenize the label.
	 *
	 * @param string $label - the label.
	 *
	 * @return string
	 */
	public static function tokenize_label( $label ) {
		return '{' . trim( preg_replace( '#^\d+_#', '', $label ) ) . '}';
	}

	/**
	 * Sanitize the value.
	 *
	 * @param string $value - the value to sanitize.
	 *
	 * @return string
	 */
	public static function sanitize_value( $value ) {
		if ( null === $value ) {
			return '';
		}
		return preg_replace( '=((<CR>|<LF>|0x0A/%0A|0x0D/%0D|\\n|\\r)\S).*=i', '', $value );
	}

	/**
	 * Replaces tokens like {city} or {City} (case insensitive) with the value
	 * of an input field of that name
	 *
	 * @param string $subject - the subject.
	 * @param array  $field_values Array with field label => field value associations.
	 *
	 * @return string The filtered $subject with the tokens replaced.
	 */
	public function replace_tokens_with_input( $subject, $field_values ) {
		// Wrap labels into tokens (inside {})
		$wrapped_labels = array_map( array( 'Grunion_Contact_Form_Plugin', 'tokenize_label' ), array_keys( $field_values ) );
		// Sanitize all values
		$sanitized_values = array_map( array( 'Grunion_Contact_Form_Plugin', 'sanitize_value' ), array_values( $field_values ) );

		foreach ( $sanitized_values as $k => $sanitized_value ) {
			if ( is_array( $sanitized_value ) ) {
				$sanitized_values[ $k ] = implode( ', ', $sanitized_value );
			}
		}

		// Search for all valid tokens (based on existing fields) and replace with the field's value
		$subject = str_ireplace( $wrapped_labels, $sanitized_values, $subject );
		return $subject;
	}

	/**
	 * Tracks the widget currently being processed.
	 * Attached to `dynamic_sidebar`
	 *
	 * @see $current_widget_id - the current widget ID.
	 *
	 * @param array $widget The widget data.
	 */
	public function track_current_widget( $widget ) {
		$this->current_widget_id = $widget['id'];
	}

	/**
	 * Adds a "widget" attribute to every contact-form embedded in a text widget.
	 * Used to tell the difference between post-embedded contact-forms and widget-embedded contact-forms
	 * Attached to `widget_text`
	 *
	 * @param string $text The widget text.
	 *
	 * @return string The filtered widget text.
	 */
	public function widget_atts( $text ) {
		Grunion_Contact_Form::style( true );

		return preg_replace( '/\[contact-form([^a-zA-Z_-])/', '[contact-form widget="' . $this->current_widget_id . '"\\1', $text );
	}

	/**
	 * For sites where text widgets are not processed for shortcodes, we add this hack to process just our shortcode
	 * Attached to `widget_text`
	 *
	 * @param string $text The widget text.
	 *
	 * @return string The contact-form filtered widget text
	 */
	public function widget_shortcode_hack( $text ) {
		if ( ! preg_match( '/\[contact-form([^a-zA-Z_-])/', $text ) ) {
			return $text;
		}

		$old = $GLOBALS['shortcode_tags'];
		remove_all_shortcodes();
		self::$using_contact_form_field = true;
		$this->add_shortcode();

		$text = do_shortcode( $text );

		self::$using_contact_form_field = false;
		$GLOBALS['shortcode_tags']      = $old; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited

		return $text;
	}

	/**
	 * Check if a submission matches the Comment Blocklist.
	 * The Comment Blocklist is a means to moderate discussion, and contact
	 * forms are 1:1 discussion forums, ripe for abuse by users who are being
	 * removed from the public discussion.
	 * Attached to `jetpack_contact_form_is_spam`
	 *
	 * @param bool  $is_spam - if the submission is spam.
	 * @param array $form - the form data.
	 * @return bool TRUE => spam, FALSE => not spam
	 */
	public function is_spam_blocklist( $is_spam, $form = array() ) {
		if ( $is_spam ) {
			return $is_spam;
		}

		return $this->is_in_disallowed_list( false, $form );
	}

	/**
	 * Check if a submission matches the comment disallowed list.
	 * Attached to `jetpack_contact_form_in_comment_disallowed_list`.
	 *
	 * @param boolean $in_disallowed_list Whether the feedback is in the disallowed list.
	 * @param array   $form The form array.
	 * @return bool Returns true if the form submission matches the disallowed list and false if it doesn't.
	 */
	public function is_in_disallowed_list( $in_disallowed_list, $form = array() ) {
		if ( $in_disallowed_list ) {
			return $in_disallowed_list;
		}

		if (
			wp_check_comment_disallowed_list(
				$form['comment_author'],
				$form['comment_author_email'],
				$form['comment_author_url'],
				$form['comment_content'],
				$form['user_ip'],
				$form['user_agent']
			)
		) {
			return true;
		}

		return false;
	}

	/**
	 * Populate an array with all values necessary to submit a NEW contact-form feedback to Akismet.
	 * Note that this includes the current user_ip etc, so this should only be called when accepting a new item via $_POST
	 *
	 * @param array $form - contact form feedback array.
	 *
	 * @return array feedback array with additional data ready for submission to Akismet.
	 */
	public function prepare_for_akismet( $form ) {
		$form['comment_type'] = 'contact_form';
		$form['user_ip']      = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$form['user_agent']   = isset( $_SERVER['HTTP_USER_AGENT'] ) ? filter_var( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$form['referrer']     = isset( $_SERVER['HTTP_REFERER'] ) ? esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '';
		$form['blog']         = get_option( 'home' );

		foreach ( $_SERVER as $key => $value ) {
			if ( ! is_string( $value ) ) {
				continue;
			}
			if ( in_array( $key, array( 'HTTP_COOKIE', 'HTTP_COOKIE2', 'HTTP_USER_AGENT', 'HTTP_REFERER' ), true ) ) {
				// We don't care about cookies, and the UA and Referrer were caught above.
				continue;
			} elseif ( in_array( $key, array( 'REMOTE_ADDR', 'REQUEST_URI', 'DOCUMENT_URI' ), true ) ) {
				// All three of these are relevant indicators and should be passed along.
				$form[ $key ] = $value;
			} elseif ( wp_startswith( $key, 'HTTP_' ) ) {
				// Any other HTTP header indicators.
				// `wp_startswith()` is a wpcom helper function and is included in Jetpack via `functions.compat.php`
				$form[ $key ] = $value;
			}
		}

		/**
		 * Filter the values that are sent to Akismet for the spam check.
		 *
		 * @module contact-form
		 *
		 * @since 10.2.0
		 *
		 * @param array $form The form values being sent to Akismet.
		 */
		return apply_filters( 'jetpack_contact_form_akismet_values', $form );
	}

	/**
	 * Submit contact-form data to Akismet to check for spam.
	 * If you're accepting a new item via $_POST, run it Grunion_Contact_Form_Plugin::prepare_for_akismet() first
	 * Attached to `jetpack_contact_form_is_spam`
	 *
	 * @param bool  $is_spam - if the submission is spam.
	 * @param array $form - the form data.
	 * @return bool|WP_Error TRUE => spam, FALSE => not spam, WP_Error => stop processing entirely
	 */
	public function is_spam_akismet( $is_spam, $form = array() ) {
		global $akismet_api_host, $akismet_api_port;

		// The signature of this function changed from accepting just $form.
		// If something only sends an array, assume it's still using the old
		// signature and work around it.
		if ( empty( $form ) && is_array( $is_spam ) ) {
			$form    = $is_spam;
			$is_spam = false;
		}

		// If a previous filter has alrady marked this as spam, trust that and move on.
		if ( $is_spam ) {
			return $is_spam;
		}

		if ( ! function_exists( 'akismet_http_post' ) && ! defined( 'AKISMET_VERSION' ) ) {
			return false;
		}

		$query_string = http_build_query( $form );

		if ( method_exists( 'Akismet', 'http_post' ) ) {
			$response = Akismet::http_post( $query_string, 'comment-check' );
		} else {
			$response = akismet_http_post( $query_string, $akismet_api_host, '/1.1/comment-check', $akismet_api_port );
		}

		$result = false;

		if ( isset( $response[0]['x-akismet-pro-tip'] ) && 'discard' === trim( $response[0]['x-akismet-pro-tip'] ) && get_option( 'akismet_strictness' ) === '1' ) {
			$result = new WP_Error( 'feedback-discarded', __( 'Feedback discarded.', 'jetpack' ) );
		} elseif ( isset( $response[1] ) && 'true' === trim( $response[1] ) ) { // 'true' is spam
			$result = true;
		}

		/**
		 * Filter the results returned by Akismet for each submitted contact form.
		 *
		 * @module contact-form
		 *
		 * @since 1.3.1
		 *
		 * @param WP_Error|bool $result Is the submitted feedback spam.
		 * @param array|bool $form Submitted feedback.
		 */
		return apply_filters( 'contact_form_is_spam_akismet', $result, $form );
	}

	/**
	 * Submit a feedback as either spam or ham
	 *
	 * @param string $as - Either 'spam' or 'ham'.
	 * @param array  $form - the contact-form data.
	 *
	 * @return bool|string
	 */
	public function akismet_submit( $as, $form ) {
		global $akismet_api_host, $akismet_api_port;

		if ( ! in_array( $as, array( 'ham', 'spam' ), true ) ) {
			return false;
		}

		$query_string = '';
		if ( is_array( $form ) ) {
			$query_string = http_build_query( $form );
		}
		if ( method_exists( 'Akismet', 'http_post' ) ) {
			$response = Akismet::http_post( $query_string, "submit-{$as}" );
		} else {
			$response = akismet_http_post( $query_string, $akismet_api_host, "/1.1/submit-{$as}", $akismet_api_port );
		}

		return trim( $response[1] );
	}

	/**
	 * Prints a dropdown of posts with forms.
	 *
	 * @param int $selected_id Currently selected post ID.
	 * @return void
	 */
	public static function form_posts_dropdown( $selected_id ) {
		?>
		<select name="jetpack_form_parent_id">
			<option value="all"><?php esc_html_e( 'All sources', 'jetpack' ); ?></option>
			<?php echo self::get_feedbacks_as_options( $selected_id ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- HTML is escaped in the function. ?>
		</select>
		<?php
	}

	/**
	 * Fetch post content for a post and extract just the comment.
	 *
	 * @param int $post_id The post id to fetch the content for.
	 *
	 * @return string Trimmed post comment.
	 *
	 * @codeCoverageIgnore
	 */
	public function get_post_content_for_csv_export( $post_id ) {
		$post_content = get_post_field( 'post_content', $post_id );
		$content      = explode( '<!--more-->', $post_content );

		return trim( $content[0] );
	}

	/**
	 * Get `_feedback_extra_fields` field from post meta data.
	 *
	 * @param int $post_id Id of the post to fetch meta data for.
	 *
	 * @return mixed
	 */
	public function get_post_meta_for_csv_export( $post_id ) {
		$md                     = get_post_meta( $post_id, '_feedback_extra_fields', true );
		$md['-3_response_date'] = get_the_date( 'Y-m-d H:i:s', $post_id );
		$content_fields         = self::parse_fields_from_content( $post_id );
		$md['93_ip_address']    = ( isset( $content_fields['_feedback_ip'] ) ) ? $content_fields['_feedback_ip'] : 0;

		// add the email_marketing_consent to the post meta.
		$md['90_consent'] = 0;
		if ( isset( $content_fields['_feedback_all_fields'] ) ) {
			$all_fields = $content_fields['_feedback_all_fields'];
			// check if the email_marketing_consent field exists.
			if ( isset( $all_fields['email_marketing_consent'] ) ) {
				$md['90_consent'] = $all_fields['email_marketing_consent'];
			}
			// check if the feedback entry has a title.
			if ( isset( $all_fields['entry_title'] ) ) {
				$md['-9_title'] = $all_fields['entry_title'];
			}

			// check if the feedback entry has a permalink we can use.
			if ( isset( $all_fields['entry_permalink'] ) && ! empty( $all_fields['entry_permalink'] ) ) {
				$parsed          = wp_parse_url( $all_fields['entry_permalink'] );
				$md['-6_source'] = '';
				if ( $parsed && ! empty( $parsed['path'] ) && strpos( $parsed['path'], '/' ) === 0 ) {
					$md['-6_source'] .= $parsed['path'];
				}
				if ( $parsed && ! empty( $parsed['query'] ) ) {
					$md['-6_source'] .= '?' . $parsed['query'];
				}
			}
		}

		return $md;
	}

	/**
	 * Get parsed feedback post fields.
	 *
	 * @param int $post_id Id of the post to fetch parsed contents for.
	 *
	 * @return array
	 *
	 * @codeCoverageIgnore - No need to be covered.
	 */
	public function get_parsed_field_contents_of_post( $post_id ) {
		return self::parse_fields_from_content( $post_id );
	}

	/**
	 * Properly maps fields that are missing from the post meta data
	 * to names, that are similar to those of the post meta.
	 *
	 * @param array $parsed_post_content Parsed post content.
	 *
	 * @see parse_fields_from_content for how the input data is generated.
	 *
	 * @return array Mapped fields.
	 */
	public function map_parsed_field_contents_of_post_to_field_names( $parsed_post_content ) {

		$mapped_fields = array();

		$field_mapping = array(
			// TODO: Commented out since we'll be re-introducing this after some other changes
			// '_feedback_subject'      => __( 'Contact Form', 'jetpack' ),
			'_feedback_author'       => '1_Name',
			'_feedback_author_email' => '2_Email',
			'_feedback_author_url'   => '3_Website',
			'_feedback_main_comment' => '4_Comment',
			'_feedback_ip'           => '93_ip_address',
		);

		foreach ( $field_mapping as $parsed_field_name => $field_name ) {
			if (
				isset( $parsed_post_content[ $parsed_field_name ] )
				&& ! empty( $parsed_post_content[ $parsed_field_name ] )
			) {
				$mapped_fields[ $field_name ] = $parsed_post_content[ $parsed_field_name ];
			}
		}

		return $mapped_fields;
	}

	/**
	 * Registers the personal data exporter.
	 *
	 * @since 6.1.1
	 *
	 * @param  array $exporters An array of personal data exporters.
	 *
	 * @return array $exporters An array of personal data exporters.
	 */
	public function register_personal_data_exporter( $exporters ) {
		$exporters['jetpack-feedback'] = array(
			'exporter_friendly_name' => __( 'Feedback', 'jetpack' ),
			'callback'               => array( $this, 'personal_data_exporter' ),
		);

		return $exporters;
	}

	/**
	 * Registers the personal data eraser.
	 *
	 * @since 6.1.1
	 *
	 * @param  array $erasers An array of personal data erasers.
	 *
	 * @return array $erasers An array of personal data erasers.
	 */
	public function register_personal_data_eraser( $erasers ) {
		$erasers['jetpack-feedback'] = array(
			'eraser_friendly_name' => __( 'Feedback', 'jetpack' ),
			'callback'             => array( $this, 'personal_data_eraser' ),
		);

		return $erasers;
	}

	/**
	 * Exports personal data.
	 *
	 * @since 6.1.1
	 *
	 * @param  string $email  Email address.
	 * @param  int    $page   Page to export.
	 *
	 * @return array  $return Associative array with keys expected by core.
	 */
	public function personal_data_exporter( $email, $page = 1 ) {
		return $this->internal_personal_data_exporter( $email, $page );
	}

	/**
	 * Internal method for exporting personal data.
	 *
	 * Allows us to have a different signature than core expects
	 * while protecting against future core API changes.
	 *
	 * @internal
	 * @since 6.5
	 *
	 * @param  string $email    Email address.
	 * @param  int    $page     Page to export.
	 * @param  int    $per_page Number of feedbacks to process per page. Internal use only (testing).
	 *
	 * @return array            Associative array with keys expected by core.
	 */
	public function internal_personal_data_exporter( $email, $page = 1, $per_page = 250 ) {
		$export_data = array();
		$post_ids    = $this->personal_data_post_ids_by_email( $email, $per_page, $page );

		foreach ( $post_ids as $post_id ) {
			$post_fields = $this->get_parsed_field_contents_of_post( $post_id );

			if ( ! is_array( $post_fields ) || empty( $post_fields['_feedback_subject'] ) ) {
				continue; // Corrupt data.
			}

			$post_fields['_feedback_main_comment'] = $this->get_post_content_for_csv_export( $post_id );
			$post_fields                           = $this->map_parsed_field_contents_of_post_to_field_names( $post_fields );

			if ( ! is_array( $post_fields ) || empty( $post_fields ) ) {
				continue; // No fields to export.
			}

			$post_meta = $this->get_post_meta_for_csv_export( $post_id );
			$post_meta = is_array( $post_meta ) ? $post_meta : array();

			$post_export_data = array();
			$post_data        = array_merge( $post_fields, $post_meta );
			ksort( $post_data );

			foreach ( $post_data as $post_data_key => $post_data_value ) {
				$post_export_data[] = array(
					'name'  => preg_replace( '/^[0-9]+_/', '', $post_data_key ),
					'value' => $post_data_value,
				);
			}

			$export_data[] = array(
				'group_id'    => 'feedback',
				'group_label' => __( 'Feedback', 'jetpack' ),
				'item_id'     => 'feedback-' . $post_id,
				'data'        => $post_export_data,
			);
		}

		return array(
			'data' => $export_data,
			'done' => count( $post_ids ) < $per_page,
		);
	}

	/**
	 * Erases personal data.
	 *
	 * @since 6.1.1
	 *
	 * @param  string $email Email address.
	 * @param  int    $page  Page to erase.
	 *
	 * @return array         Associative array with keys expected by core.
	 */
	public function personal_data_eraser( $email, $page = 1 ) {
		return $this->_internal_personal_data_eraser( $email, $page );
	}

	/**
	 * Internal method for erasing personal data.
	 *
	 * Allows us to have a different signature than core expects
	 * while protecting against future core API changes.
	 *
	 * @internal
	 * @since 6.5
	 *
	 * @param  string $email    Email address.
	 * @param  int    $page     Page to erase.
	 * @param  int    $per_page Number of feedbacks to process per page. Internal use only (testing).
	 *
	 * @return array            Associative array with keys expected by core.
	 */
	public function _internal_personal_data_eraser( $email, $page = 1, $per_page = 250 ) { // phpcs:ignore PSR2.Methods.MethodDeclaration.Underscore -- this is called in other files.
		$removed      = false;
		$retained     = false;
		$messages     = array();
		$option_name  = sprintf( '_jetpack_pde_feedback_%s', md5( $email ) );
		$last_post_id = 1 === $page ? 0 : get_option( $option_name, 0 );
		$post_ids     = $this->personal_data_post_ids_by_email( $email, $per_page, $page, $last_post_id );

		foreach ( $post_ids as $post_id ) {
			/**
			 * Filters whether to erase a particular Feedback post.
			 *
			 * @since 6.3.0
			 *
			 * @param bool|string $prevention_message Whether to apply erase the Feedback post (bool).
			 *                                        Custom prevention message (string). Default true.
			 * @param int         $post_id            Feedback post ID.
			 */
			$prevention_message = apply_filters( 'grunion_contact_form_delete_feedback_post', true, $post_id );

			if ( true !== $prevention_message ) {
				if ( $prevention_message && is_string( $prevention_message ) ) {
					$messages[] = esc_html( $prevention_message );
				} else {
					$messages[] = sprintf(
					// translators: %d: Post ID.
						__( 'Feedback ID %d could not be removed at this time.', 'jetpack' ),
						$post_id
					);
				}

				$retained = true;

				continue;
			}

			if ( wp_delete_post( $post_id, true ) ) {
				$removed = true;
			} else {
				$retained   = true;
				$messages[] = sprintf(
				// translators: %d: Post ID.
					__( 'Feedback ID %d could not be removed at this time.', 'jetpack' ),
					$post_id
				);
			}
		}

		$done = count( $post_ids ) < $per_page;

		if ( $done ) {
			delete_option( $option_name );
		} else {
			update_option( $option_name, (int) $post_id );
		}

		return array(
			'items_removed'  => $removed,
			'items_retained' => $retained,
			'messages'       => $messages,
			'done'           => $done,
		);
	}

	/**
	 * Queries personal data by email address.
	 *
	 * @since 6.1.1
	 *
	 * @param  string $email        Email address.
	 * @param  int    $per_page     Post IDs per page. Default is `250`.
	 * @param  int    $page         Page to query. Default is `1`.
	 * @param  int    $last_post_id Page to query. Default is `0`. If non-zero, used instead of $page.
	 *
	 * @return array An array of post IDs.
	 */
	public function personal_data_post_ids_by_email( $email, $per_page = 250, $page = 1, $last_post_id = 0 ) {
		add_filter( 'posts_search', array( $this, 'personal_data_search_filter' ) );

		$this->pde_last_post_id_erased = $last_post_id;
		$this->pde_email_address       = $email;

		$post_ids = get_posts(
			array(
				'post_type'        => 'feedback',
				'post_status'      => 'publish',
				// This search parameter gets overwritten in ->personal_data_search_filter()
				's'                => '..PDE..AUTHOR EMAIL:..PDE..',
				'sentence'         => true,
				'order'            => 'ASC',
				'orderby'          => 'ID',
				'fields'           => 'ids',
				'posts_per_page'   => $per_page,
				'paged'            => $last_post_id ? 1 : $page,
				'suppress_filters' => false,
			)
		);

		$this->pde_last_post_id_erased = 0;
		$this->pde_email_address       = '';

		remove_filter( 'posts_search', array( $this, 'personal_data_search_filter' ) );

		return $post_ids;
	}

	/**
	 * Filters searches by email address.
	 *
	 * @since 6.1.1
	 *
	 * @param  string $search SQL where clause.
	 *
	 * @return array          Filtered SQL where clause.
	 */
	public function personal_data_search_filter( $search ) {
		global $wpdb;

		/*
		 * Limits search to `post_content` only, and we only match the
		 * author's email address whenever it's on a line by itself.
		 */
		if ( $this->pde_email_address && false !== strpos( $search, '..PDE..AUTHOR EMAIL:..PDE..' ) ) {
			$search = $wpdb->prepare(
				" AND (
					{$wpdb->posts}.post_content LIKE %s
					OR {$wpdb->posts}.post_content LIKE %s
				)",
				// `chr( 10 )` = `\n`, `chr( 13 )` = `\r` - Keeping this in case someone needs it for reference.
				'%' . $wpdb->esc_like( chr( 10 ) . 'AUTHOR EMAIL: ' . $this->pde_email_address . chr( 10 ) ) . '%',
				'%' . $wpdb->esc_like( chr( 13 ) . 'AUTHOR EMAIL: ' . $this->pde_email_address . chr( 13 ) ) . '%'
			);

			if ( $this->pde_last_post_id_erased ) {
				$search .= $wpdb->prepare( " AND {$wpdb->posts}.ID > %d", $this->pde_last_post_id_erased );
			}
		}

		return $search;
	}

	/**
	 * Prepares feedback post data for CSV export.
	 *
	 * @param array $post_ids Post IDs to fetch the data for. These need to be Feedback posts.
	 *
	 * @return array
	 */
	public function get_export_data_for_posts( $post_ids ) {

		$posts_data  = array();
		$field_names = array();
		$result      = array();

		/**
		 * Fetch posts and get the possible field names for later use
		 */
		foreach ( $post_ids as $post_id ) {

			/**
			 * Fetch post main data, because we need the subject and author data for the feedback form.
			 */
			$post_real_data = $this->get_parsed_field_contents_of_post( $post_id );

			/**
			 * If `$post_real_data` is not an array or there is no `_feedback_subject` set,
			 * then something must be wrong with the feedback post. Skip it.
			 */
			if ( ! is_array( $post_real_data ) || ! isset( $post_real_data['_feedback_subject'] ) ) {
				continue;
			}

			/**
			 * Fetch main post comment. This is from the default textarea fields.
			 * If it is non-empty, then we add it to data, otherwise skip it.
			 */
			$post_comment_content = $this->get_post_content_for_csv_export( $post_id );
			if ( ! empty( $post_comment_content ) ) {
				$post_real_data['_feedback_main_comment'] = $post_comment_content;
			}

			/**
			 * Map parsed fields to proper field names
			 */
			$mapped_fields = $this->map_parsed_field_contents_of_post_to_field_names( $post_real_data );

			/**
			 * Fetch post meta data.
			 */
			$post_meta_data = $this->get_post_meta_for_csv_export( $post_id );

			/**
			 * If `$post_meta_data` is not an array or if it is empty, then there is no
			 * extra feedback to work with. Create an empty array.
			 */
			if ( ! is_array( $post_meta_data ) || empty( $post_meta_data ) ) {
				$post_meta_data = array();
			}

			/**
			 * Prepend the feedback subject to the list of fields.
			 */
			$post_meta_data = array_merge(
				$mapped_fields,
				$post_meta_data
			);

			/**
			 * Save post metadata for later usage.
			 */
			$posts_data[ $post_id ] = $post_meta_data;

			/**
			 * Save field names, so we can use them as header fields later in the CSV.
			 */
			$field_names = array_merge( $field_names, array_keys( $post_meta_data ) );
		}

		/**
		 * Make sure the field names are unique, because we don't want duplicate data.
		 */
		$field_names = array_unique( $field_names );

		/**
		 * Sort the field names by the field id number
		 */
		sort( $field_names, SORT_NUMERIC );

		$well_known_column_names = $this->get_well_known_column_names();
		$result                  = array();

		/**
		 * Loop through every post, which is essentially CSV row.
		 */
		foreach ( $posts_data as $post_id => $single_post_data ) {
			/**
			 * Go through all the possible fields and check if the field is available
			 * in the current post.
			 *
			 * If it is - add the data as a value.
			 * If it is not - add an empty string, which is just a placeholder in the CSV.
			 */
			foreach ( $field_names as $single_field_name ) {
				$renamed_field = isset( $well_known_column_names[ $single_field_name ] )
					? $well_known_column_names[ $single_field_name ]
					: $single_field_name;

				/**
				 * Remove the numeral prefix -3_, 1_, 2_, etc, only for export results.
				 * Prefixes can be both positive and negative numeral values, functional to the SORT_NUMERIC above.
				 * TODO: to return fieldnames based on field label, we need to work both field names and post data:
				 * unique -> sort -> unique/rename
				 * $renamed_field = preg_replace( '/^(-?\d{1,2}_)/', '', $renamed_field );
				 */

				if ( ! isset( $result[ $renamed_field ] ) ) {
					$result[ $renamed_field ] = array();
				}

				if (
					isset( $single_post_data[ $single_field_name ] )
					&& ! empty( $single_post_data[ $single_field_name ] )
				) {
					$result[ $renamed_field ][] = trim( $single_post_data[ $single_field_name ] );
				} else {
					$result[ $renamed_field ][] = '';
				}
			}
		}

		return $result;
	}

	/**
	 * Returns an array of [prefixed column name] => [translated column name], used on export.
	 * Prefix indicates the position in which the column will be rendered:
	 * - Negative numbers render BEFORE any form field/value column: -5, -3, -1...
	 * - Positive values render AFTER any form field/value column: 1, 30, 93...
	 *   Mind using high numbering on these ones as the prefix is used on regular inputs: 1_Name, 2_Email, etc
	 *
	 * @return array
	 */
	public function get_well_known_column_names() {
		return array(
			'-9_title'         => __( 'Title', 'jetpack' ),
			'-6_source'        => __( 'Source', 'jetpack' ),
			'-3_response_date' => __( 'Response Date', 'jetpack' ),
			'90_consent'       => _x( 'Consent', 'noun', 'jetpack' ),
			'93_ip_address'    => __( 'IP Address', 'jetpack' ),
		);
	}

	/**
	 * Extracts feedback entries based on POST data.
	 */
	public function get_feedback_entries_from_post() {
		if ( empty( $_POST['feedback_export_nonce_csv'] ) && empty( $_POST['feedback_export_nonce_gdrive'] ) ) {
			return;
		} elseif ( ! empty( $_POST['feedback_export_nonce_csv'] ) ) {
			check_admin_referer( 'feedback_export', 'feedback_export_nonce_csv' );
		} elseif ( ! empty( $_POST['feedback_export_nonce_gdrive'] ) ) {
			check_admin_referer( 'feedback_export', 'feedback_export_nonce_gdrive' );
		}

		if ( ! current_user_can( 'export' ) ) {
			return;
		}

		$args = array(
			'posts_per_page'   => -1,
			'post_type'        => 'feedback',
			'post_status'      => 'publish',
			'order'            => 'ASC',
			'fields'           => 'ids',
			'suppress_filters' => false,
			'date_query'       => array(),
		);

		// Check if we want to download all the feedbacks or just a certain contact form
		if ( ! empty( $_POST['post'] ) && $_POST['post'] !== 'all' ) {
			$args['post_parent'] = (int) $_POST['post'];
		}

		if ( ! empty( $_POST['year'] ) && intval( $_POST['year'] ) > 0 ) {
			$args['date_query']['year'] = intval( $_POST['year'] );
		}

		if ( ! empty( $_POST['month'] ) && intval( $_POST['month'] ) > 0 ) {
			$args['date_query']['month'] = intval( $_POST['month'] );
		}

		if ( ! empty( $_POST['selected'] ) && is_array( $_POST['selected'] ) ) {
			$args['include'] = array_filter(
				array_map(
					function ( $selected ) {
						return intval( $selected );
					},
					$_POST['selected'] // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				)
			);
		}

		$feedbacks = get_posts( $args );

		if ( empty( $feedbacks ) ) {
			return;
		}

		/**
		 * Prepare data for export.
		 */
		$data = $this->get_export_data_for_posts( $feedbacks );

		/**
		 * If `$data` is empty, there's nothing we can do below.
		 */
		if ( ! is_array( $data ) || empty( $data ) ) {
			return;
		}

		return $data;
	}

	/**
	 * Download exported data as CSV
	 */
	public function download_feedback_as_csv() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verification is done on get_feedback_entries_from_post function
		$post_data = wp_unslash( $_POST );
		$data      = $this->get_feedback_entries_from_post();

		if ( empty( $data ) ) {
			return;
		}

		// Check if we want to download all the feedbacks or just a certain contact form
		if ( ! empty( $post_data['post'] ) && $post_data['post'] !== 'all' ) {
			$filename = sprintf(
				'%s - %s.csv',
				Grunion_Admin::init()->get_export_filename( get_the_title( (int) $post_data['post'] ) ),
				gmdate( 'Y-m-d H:i' )
			);
		} else {
			$filename = sprintf(
				'%s - %s.csv',
				Grunion_Admin::init()->get_export_filename(),
				gmdate( 'Y-m-d H:i' )
			);
		}

		/**
		 * Extract field names from `$data` for later use.
		 */
		$fields = array_keys( $data );

		/**
		 * Count how many rows will be exported.
		 */
		$row_count = count( reset( $data ) );

		// Forces the download of the CSV instead of echoing
		header( 'Content-Disposition: attachment; filename=' . $filename );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );
		header( 'Content-Type: text/csv; charset=utf-8' );

		$output = fopen( 'php://output', 'w' );

		/**
		 * Print CSV headers
		 */
		fputcsv( $output, $fields );

		/**
		 * Print rows to the output.
		 */
		for ( $i = 0; $i < $row_count; $i++ ) {

			$current_row = array();

			/**
			 * Put all the fields in `$current_row` array.
			 */
			foreach ( $fields as $single_field_name ) {
				$current_row[] = $this->esc_csv( $data[ $single_field_name ][ $i ] );
			}

			/**
			 * Output the complete CSV row
			 */
			fputcsv( $output, $current_row );
		}

		fclose( $output ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_fclose

		$this->record_tracks_event( 'forms_export_responses', array( 'format' => 'csv' ) );
		exit();
	}

	/**
	 * Send an event to Tracks
	 *
	 * @param string $event_name - the name of the event.
	 * @param array  $event_props - event properties to send.
	 *
	 * @return null|void
	 */
	public function record_tracks_event( $event_name, $event_props ) {
		/*
		 * Event details.
		 */
		$event_user = wp_get_current_user();

		/*
		 * Record event.
		 * We use different libs on wpcom and Jetpack.
		 */
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$event_name             = 'wpcom_' . $event_name;
			$event_props['blog_id'] = get_current_blog_id();
			// logged out visitor, record event with blog owner.
			if ( empty( $event_user->ID ) ) {
				$event_user_id = wpcom_get_blog_owner( $event_props['blog_id'] );
				$event_user    = get_userdata( $event_user_id );
			}

			require_lib( 'tracks/client' );
			tracks_record_event( $event_user, $event_name, $event_props );
		} else {
			$user_connected = ( new \Automattic\Jetpack\Connection\Manager( 'jetpack-forms' ) )->is_user_connected( get_current_user_id() );
			if ( ! $user_connected ) {
				return;
			}
			// logged out visitor, record event with Jetpack master user.
			if ( empty( $event_user->ID ) ) {
				$master_user_id = Jetpack_Options::get_option( 'master_user' );
				if ( ! empty( $master_user_id ) ) {
					$event_user = get_userdata( $master_user_id );
				}
			}

			$tracking = new \Automattic\Jetpack\Tracking();
			$tracking->record_user_event( $event_name, $event_props, $event_user );
		}
	}

	/**
	 * Escape a string to be used in a CSV context
	 *
	 * Malicious input can inject formulas into CSV files, opening up the possibility for phishing attacks and
	 * disclosure of sensitive information.
	 *
	 * Additionally, Excel exposes the ability to launch arbitrary commands through the DDE protocol.
	 *
	 * @see https://www.contextis.com/en/blog/comma-separated-vulnerabilities
	 *
	 * @param string $field - the CSV field.
	 *
	 * @return string
	 */
	public function esc_csv( $field ) {
		$active_content_triggers = array( '=', '+', '-', '@' );

		if ( in_array( mb_substr( $field, 0, 1 ), $active_content_triggers, true ) ) {
			$field = "'" . $field;
		}

		return $field;
	}

	/**
	 * Returns a string of HTML <option> items from an array of posts
	 *
	 * @param int $selected_id Currently selected post ID.
	 * @return string a string of HTML <option> items
	 */
	protected static function get_feedbacks_as_options( $selected_id = 0 ) {
		$options = '';

		// Get the feedbacks' parents' post IDs
		$feedbacks  = get_posts(
			array(
				'fields'           => 'id=>parent',
				'posts_per_page'   => 100000, // phpcs:ignore WordPress.WP.PostsPerPage.posts_per_page_posts_per_page
				'post_type'        => 'feedback',
				'post_status'      => 'publish',
				'suppress_filters' => false,
			)
		);
		$parent_ids = array_unique( array_values( $feedbacks ) );

		// creates the string of <option> elements
		foreach ( $parent_ids as $parent_id ) {
			$parent_url = get_permalink( $parent_id );
			$parsed_url = wp_parse_url( $parent_url );

			$options .= sprintf(
				'<option value="%s" %s>/%s</option>',
				esc_attr( $parent_id ),
				$selected_id === $parent_id ? 'selected' : '',
				esc_html( basename( $parsed_url['path'] ) )
			);
		}

		return $options;
	}

	/**
	 * Get the names of all the form's fields
	 *
	 * @param array|int $posts the post we want the fields of.
	 *
	 * @return array     the array of fields
	 *
	 * @deprecated As this is no longer necessary as of the CSV export rewrite. - 2015-12-29
	 */
	protected function get_field_names( $posts ) {
		$posts      = (array) $posts;
		$all_fields = array();

		foreach ( $posts as $post ) {
			$fields = self::parse_fields_from_content( $post );

			if ( isset( $fields['_feedback_all_fields'] ) ) {
				$extra_fields = array_keys( $fields['_feedback_all_fields'] );
				$all_fields   = array_merge( $all_fields, $extra_fields );
			}
		}

		$all_fields = array_unique( $all_fields );
		return $all_fields;
	}

	/**
	 * Parse the contact form fields.
	 *
	 * @param int $post_id - the post ID.
	 * @return array Fields.
	 */
	public static function parse_fields_from_content( $post_id ) {
		static $post_fields;

		if ( ! is_array( $post_fields ) ) {
			$post_fields = array();
		}

		if ( isset( $post_fields[ $post_id ] ) ) {
			return $post_fields[ $post_id ];
		}

		$all_values   = array();
		$post_content = get_post_field( 'post_content', $post_id );
		$content      = explode( '<!--more-->', $post_content );
		$lines        = array();

		if ( count( $content ) > 1 ) {
			$content = str_ireplace( array( '<br />', ')</p>' ), '', $content[1] );
			if ( strpos( $content, 'JSON_DATA' ) !== false ) {
				$chunks     = explode( "\nJSON_DATA", $content );
				$all_values = json_decode( $chunks[1], true );
				if ( is_array( $all_values ) ) {
					$fields_array = array_keys( $all_values );
				}
				$lines = array_filter( explode( "\n", $chunks[0] ) );
			} else {
				$fields_array = preg_replace( '/.*Array\s\( (.*)\)/msx', '$1', $content );

				// TODO: some explanation on this regex could help
				preg_match_all( '/^\s*\[([^\]]+)\] =\&gt\; (.*)(?=^\s*(\[[^\]]+\] =\&gt\;)|\z)/msU', $fields_array, $matches );

				if ( count( $matches ) > 1 ) {
					$all_values = array_combine( array_map( 'trim', $matches[1] ), array_map( 'trim', $matches[2] ) );
				}

				$lines = array_filter( explode( "\n", $content ) );
			}
		}

		$var_map = array(
			'AUTHOR'       => '_feedback_author',
			'AUTHOR EMAIL' => '_feedback_author_email',
			'AUTHOR URL'   => '_feedback_author_url',
			'SUBJECT'      => '_feedback_subject',
			'IP'           => '_feedback_ip',
		);

		$fields = array();

		foreach ( $lines as $line ) {
			$vars = explode( ': ', $line, 2 );
			if ( ! empty( $vars ) ) {
				if ( isset( $var_map[ $vars[0] ] ) ) {
					$fields[ $var_map[ $vars[0] ] ] = self::strip_tags( trim( $vars[1] ) );
				}
			}
		}

		$fields['_feedback_all_fields'] = $all_values;

		$post_fields[ $post_id ] = $fields;

		return $fields;
	}

	/**
	 * Creates a valid csv row from a post id
	 *
	 * @param int   $post_id The id of the post.
	 * @param array $fields  An array containing the names of all the fields of the csv.
	 *
	 * @return String The csv row
	 *
	 * @deprecated This is no longer needed, as of the CSV export rewrite.
	 */
	protected static function make_csv_row_from_feedback( $post_id, $fields ) {
		$content_fields = self::parse_fields_from_content( $post_id );
		$all_fields     = array();

		if ( isset( $content_fields['_feedback_all_fields'] ) ) {
			$all_fields = $content_fields['_feedback_all_fields'];
		}

		// Overwrite the parsed content with the content we stored in post_meta in a better format.
		$extra_fields = get_post_meta( $post_id, '_feedback_extra_fields', true );
		foreach ( $extra_fields as $extra_field => $extra_value ) {
			$all_fields[ $extra_field ] = $extra_value;
		}

		// The first element in all of the exports will be the subject
		$row_items   = array();
		$row_items[] = $content_fields['_feedback_subject'];

		// Loop the fields array in order to fill the $row_items array correctly
		foreach ( $fields as $field ) {
			if ( $field === __( 'Contact Form', 'jetpack' ) ) { // the first field will ever be the contact form, so we can continue
				continue;
			} elseif ( array_key_exists( $field, $all_fields ) ) {
				$row_items[] = $all_fields[ $field ];
			} else {
				$row_items[] = '';
			}
		}

		return $row_items;
	}

	/**
	 * Get the IP address.
	 *
	 * @return string|null IP address.
	 */
	public static function get_ip_address() {
		return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : null;
	}

	/**
	 * Disable Block Editor for feedbacks.
	 *
	 * @param bool   $can_edit Whether the post type can be edited or not.
	 * @param string $post_type The post type being checked.
	 * @return bool
	 */
	public function use_block_editor_for_post_type( $can_edit, $post_type ) {
		return 'feedback' === $post_type ? false : $can_edit;
	}

	/**
	 * Kludge method: reverses the output of a standard print_r( $array ).
	 * Sort of what unserialize does to a serialized object.
	 * This is here while we work on a better data storage inside the posts. See:
	 * - p1675781140892129-slack-C01CSBEN0QZ
	 * - https://www.php.net/manual/en/function.print-r.php#93529
	 *
	 * @param string $print_r_output The array string to be reverted. Needs to being with 'Array'.
	 * @param bool   $parse_html Whether to run html_entity_decode on each line.
	 *                           As strings are stored right now, they are all escaped, so '=>' are '&gt;'.
	 * @return array|string Array when succesfully reconstructed, string otherwise. Output will always be esc_html'd.
	 */
	public static function reverse_that_print( $print_r_output, $parse_html = false ) {
		$lines = explode( "\n", trim( $print_r_output ) );
		if ( $parse_html ) {
			$lines = array_map( 'html_entity_decode', $lines );
		}

		if ( trim( $lines[0] ) !== 'Array' ) {
			// bottomed out to something that isn't an array, escape it and be done
			return esc_html( $print_r_output );
		} else {
			// this is an array, lets parse it
			if ( preg_match( '/(\s{5,})\(/', $lines[1], $match ) ) {
				// this is a tested array/recursive call to this function
				// take a set of spaces off the beginning
				$spaces        = $match[1];
				$spaces_length = strlen( $spaces );
				$lines_total   = count( $lines );

				for ( $i = 0; $i < $lines_total; $i++ ) {
					if ( substr( $lines[ $i ], 0, $spaces_length ) === $spaces ) {
						$lines[ $i ] = substr( $lines[ $i ], $spaces_length );
					}
				}
			}

			array_shift( $lines ); // Array
			array_shift( $lines ); // (
			array_pop( $lines ); // )
			$print_r_output = implode( "\n", $lines );

			// make sure we only match stuff with 4 preceding spaces (stuff for this array and not a nested one
			preg_match_all( '/^\s{4}\[(.+?)\] \=\> /m', $print_r_output, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER );

			$pos          = array();
			$previous_key = '';
			$in_length    = strlen( $print_r_output );

			// store the following in $pos:
			// array with key = key of the parsed array's item
			// value = array(start position in $print_r_output, $end position in $print_r_output)
			foreach ( $matches as $match ) {
				$key         = $match[1][0];
				$start       = $match[0][1] + strlen( $match[0][0] );
				$pos[ $key ] = array( $start, $in_length );

				if ( $previous_key !== '' ) {
					$pos[ $previous_key ][1] = $match[0][1] - 1;
				}

				$previous_key = $key;
			}

			$ret = array();

			foreach ( $pos as $key => $where ) {
				// recursively see if the parsed out value is an array too
				$ret[ $key ] = self::reverse_that_print( substr( $print_r_output, $where[0], $where[1] - $where[0] ), $parse_html );
			}

			return $ret;
		}
	}
}

/**
 * Generic shortcode class.
 * Does nothing other than store structured data and output the shortcode as a string
 *
 * Not very general - specific to Grunion.
 *
 * // phpcs:disable Generic.Files.OneObjectStructurePerFile.MultipleFound
 */
class Crunion_Contact_Form_Shortcode {
	/**
	 * The name of the shortcode: [$shortcode_name /].
	 *
	 * @var string
	 */
	public $shortcode_name;

	/**
	 * Key => value pairs for the shortcode's attributes: [$shortcode_name key="value" ... /]
	 *
	 * @var array
	 */
	public $attributes;

	/**
	 * Key => value pair for attribute defaults.
	 *
	 * @var array
	 */
	public $defaults = array();

	/**
	 * The inner content of otherwise: [$shortcode_name]$content[/$shortcode_name]. Null for selfclosing shortcodes.
	 *
	 * @var null|string
	 */
	public $content;

	/**
	 * Associative array of inner "child" shortcodes equivalent to the $content: [$shortcode_name][child 1/][child 2/][/$shortcode_name]
	 *
	 * @var array
	 */
	public $fields;

	/**
	 * The HTML of the parsed inner "child" shortcodes".  Null for selfclosing shortcodes.
	 *
	 * @var null|string
	 */
	public $body;

	/**
	 * Constructor function.
	 *
	 * @param array       $attributes An associative array of shortcode attributes.  @see shortcode_atts().
	 * @param null|string $content Null for selfclosing shortcodes.  The inner content otherwise.
	 */
	public function __construct( $attributes, $content = null ) {
		$this->attributes = $this->unesc_attr( $attributes );
		if ( is_array( $content ) ) {
			$string_content = '';
			foreach ( $content as $field ) {
				$string_content .= (string) $field;
			}

			$this->content = $string_content;
		} else {
			$this->content = $content;
		}

		$this->parse_content( $this->content );
	}

	/**
	 * Processes the shortcode's inner content for "child" shortcodes.
	 *
	 * @param string $content The shortcode's inner content: [shortcode]$content[/shortcode].
	 */
	public function parse_content( $content ) {
		if ( $content === null ) {
			$this->body = null;
		} else {
			$this->body = do_shortcode( $content );
		}
	}

	/**
	 * Returns the value of the requested attribute.
	 *
	 * @param string $key The attribute to retrieve.
	 *
	 * @return mixed
	 */
	public function get_attribute( $key ) {
		return isset( $this->attributes[ $key ] ) ? $this->attributes[ $key ] : null;
	}

	/**
	 * Escape attributes.
	 *
	 * @param array $value - the value we're escaping.
	 *
	 * @return array
	 */
	public function esc_attr( $value ) {
		if ( is_array( $value ) ) {
			return array_map( array( $this, 'esc_attr' ), $value );
		}

		$value = Grunion_Contact_Form_Plugin::strip_tags( $value );
		$value = _wp_specialchars( $value, ENT_QUOTES, false, true );

		// Shortcode attributes can't contain "]"
		$value = str_replace( ']', '', $value );
		$value = str_replace( ',', '&#x002c;', $value ); // store commas encoded
		$value = strtr(
			$value,
			array(
				'%' => '%25',
				'&' => '%26',
			)
		);

		// shortcode_parse_atts() does stripcslashes() so we have to do it here.
		$value = addslashes( $value );
		return $value;
	}

	/**
	 * Unescape attributes.
	 *
	 * @param array $value - the value we're escaping.
	 *
	 * @return array
	 */
	public function unesc_attr( $value ) {
		if ( is_array( $value ) ) {
			return array_map( array( $this, 'unesc_attr' ), $value );
		}

		// For back-compat with old Grunion encoding
		// Also, unencode commas
		$value = strtr(
			(string) $value,
			array(
				'%26' => '&',
				'%25' => '%',
			)
		);
		$value = preg_replace( array( '/&#x0*22;/i', '/&#x0*27;/i', '/&#x0*26;/i', '/&#x0*2c;/i' ), array( '"', "'", '&', ',' ), $value );
		$value = htmlspecialchars_decode( $value, ENT_QUOTES );
		$value = Grunion_Contact_Form_Plugin::strip_tags( $value );

		return $value;
	}

	/**
	 * Generates the shortcode
	 */
	public function __toString() {
		$r = "[{$this->shortcode_name} ";

		foreach ( $this->attributes as $key => $value ) {
			if ( ! $value ) {
				continue;
			}

			if ( isset( $this->defaults[ $key ] ) && $this->defaults[ $key ] === $value ) {
				continue;
			}

			if ( 'id' === $key ) {
				continue;
			}

			$value = $this->esc_attr( $value );

			if ( is_array( $value ) ) {
				$value = join( ',', $value );
			}

			if ( false === strpos( $value, "'" ) ) {
				$value = "'$value'";
			} elseif ( false === strpos( $value, '"' ) ) {
				$value = '"' . $value . '"';
			} else {
				// Shortcodes can't contain both '"' and "'".  Strip one.
				$value = str_replace( "'", '', $value );
				$value = "'$value'";
			}

			$r .= "{$key}={$value} ";
		}

		$r = rtrim( $r );

		if ( $this->fields ) {
			$r .= ']';

			foreach ( $this->fields as $field ) {
				$r .= (string) $field;
			}

			$r .= "[/{$this->shortcode_name}]";
		} else {
			$r .= '/]';
		}

		return $r;
	}
}

/**
 * Class for the contact-form shortcode.
 * Parses shortcode to output the contact form as HTML
 * Sends email and stores the contact form response (a.k.a. "feedback")
 */
class Grunion_Contact_Form extends Crunion_Contact_Form_Shortcode {

	/**
	 * The shortcode name.
	 *
	 * @var string
	 */
	public $shortcode_name = 'contact-form';

	/**
	 *
	 * Stores form submission errors.
	 *
	 * @var WP_Error
	 */
	public $errors;

	/**
	 * The SHA1 hash of the attributes that comprise the form.
	 *
	 * @var string
	 */
	public $hash;

	/**
	 * The most recent (inclusive) contact-form shortcode processed.
	 *
	 * @var Grunion_Contact_Form
	 */
	public static $last;

	/**
	 * Form we are currently looking at. If processed, will become $last
	 *
	 * @var Whatever
	 */
	public static $current_form;

	/**
	 * All found forms, indexed by hash.
	 *
	 * @var array
	 */
	public static $forms = array();

	/**
	 * Whether to print the grunion.css style when processing the contact-form shortcode
	 *
	 * @var bool
	 */
	public static $style = false;

	/**
	 * When printing the submit button, what tags are allowed
	 *
	 * @var array
	 */
	public static $allowed_html_tags_for_submit_button = array( 'br' => array() );

	/**
	 * Construction function.
	 *
	 * @param array  $attributes - the attributes.
	 * @param string $content - the content.
	 */
	public function __construct( $attributes, $content = null ) {
		global $post;

		$this->hash                 = sha1( wp_json_encode( $attributes ) . $content );
		self::$forms[ $this->hash ] = $this;

		// Set up the default subject and recipient for this form.
		$default_to      = '';
		$default_subject = '[' . get_option( 'blogname' ) . ']';

		if ( ! isset( $attributes ) || ! is_array( $attributes ) ) {
			$attributes = array();
		}

		if ( $post ) {
			$default_subject = sprintf(
				// translators: the blog name and post title.
				_x( '%1$s %2$s', '%1$s = blog name, %2$s = post title', 'jetpack' ),
				$default_subject,
				Grunion_Contact_Form_Plugin::strip_tags( $post->post_title )
			);
		}

		if ( ! empty( $attributes['widget'] ) && $attributes['widget'] ) {
			$default_to      .= get_option( 'admin_email' );
			$attributes['id'] = 'widget-' . $attributes['widget'];
			// translators: the blog name (and post name, if applicable).
			$default_subject = sprintf( _x( '%1$s Sidebar', '%1$s = blog name', 'jetpack' ), $default_subject );
		} elseif ( ! empty( $attributes['block_template'] ) && $attributes['block_template'] ) {
			$default_to      .= get_option( 'admin_email' );
			$attributes['id'] = 'block-template-' . $attributes['block_template'];
		} elseif ( ! empty( $attributes['block_template_part'] ) && $attributes['block_template_part'] ) {
			$default_to      .= get_option( 'admin_email' );
			$attributes['id'] = 'block-template-part-' . $attributes['block_template_part'];
		} elseif ( $post ) {
			$attributes['id'] = $post->ID;
			$post_author      = get_userdata( $post->post_author );
			$default_to      .= isset( $post_author->user_email ) ? $post_author->user_email : '';
		}

		// Keep reference to $this for parsing form fields.
		self::$current_form = $this;

		$this->defaults = array(
			'to'                     => $default_to,
			'subject'                => $default_subject,
			'show_subject'           => 'no', // only used in back-compat mode
			'widget'                 => 0,    // Not exposed to the user. Works with Grunion_Contact_Form_Plugin::widget_atts()
			'block_template'         => null, // Not exposed to the user. Works with template_loader
			'block_template_part'    => null, // Not exposed to the user. Works with Grunion_Contact_Form::parse()
			'id'                     => null, // Not exposed to the user. Set above.
			'submit_button_text'     => __( 'Submit', 'jetpack' ),
			// These attributes come from the block editor, so use camel case instead of snake case.
			'customThankyou'         => '', // Whether to show a custom thankyou response after submitting a form. '' for no, 'message' for a custom message, 'redirect' to redirect to a new URL.
			'customThankyouHeading'  => __( 'Your message has been sent', 'jetpack' ), // The text to show above customThankyouMessage.
			'customThankyouMessage'  => __( 'Thank you for your submission!', 'jetpack' ), // The message to show when customThankyou is set to 'message'.
			'customThankyouRedirect' => '', // The URL to redirect to when customThankyou is set to 'redirect'.
			'jetpackCRM'             => true, // Whether Jetpack CRM should store the form submission.
			'className'              => null,
		);

		$attributes = shortcode_atts( $this->defaults, $attributes, 'contact-form' );

		// We only enable the contact-field shortcode temporarily while processing the contact-form shortcode.
		Grunion_Contact_Form_Plugin::$using_contact_form_field = true;

		parent::__construct( $attributes, $content );

		// There were no fields in the contact form. The form was probably just [contact-form /]. Build a default form.
		if ( empty( $this->fields ) ) {
			// same as the original Grunion v1 form.
			$default_form = '
				[contact-field label="' . __( 'Name', 'jetpack' ) . '" type="name"  required="true" /]
				[contact-field label="' . __( 'Email', 'jetpack' ) . '" type="email" required="true" /]
				[contact-field label="' . __( 'Website', 'jetpack' ) . '" type="url" /]';

			if ( 'yes' === strtolower( $this->get_attribute( 'show_subject' ) ) ) {
				$default_form .= '
					[contact-field label="' . __( 'Subject', 'jetpack' ) . '" type="subject" /]';
			}

			$default_form .= '
				[contact-field label="' . __( 'Message', 'jetpack' ) . '" type="textarea" /]';

			$this->parse_content( $default_form );

			// Store the shortcode.
			$this->store_shortcode( $default_form, $attributes, $this->hash );
		} else {
			// Store the shortcode.
			$this->store_shortcode( $content, $attributes, $this->hash );
		}

		// $this->body and $this->fields have been setup.  We no longer need the contact-field shortcode.
		Grunion_Contact_Form_Plugin::$using_contact_form_field = false;
	}

	/**
	 * Store shortcode content for recall later
	 *  - used to receate shortcode when user uses do_shortcode
	 *
	 * @param string $content - the content.
	 * @param array  $attributes - the attributes.
	 * @param string $hash - the hash.
	 */
	public static function store_shortcode( $content = null, $attributes = null, $hash = null ) {

		if ( $content && isset( $attributes['id'] ) ) {

			if ( empty( $hash ) ) {
				$hash = sha1( wp_json_encode( $attributes ) . $content );
			}

			$shortcode_meta = (string) get_post_meta( $attributes['id'], "_g_feedback_shortcode_{$hash}", true );

			if ( $shortcode_meta !== '' || $shortcode_meta !== $content ) {
				update_post_meta( $attributes['id'], "_g_feedback_shortcode_{$hash}", $content );

				// Save attributes to post_meta for later use. They're not available later in do_shortcode situations.
				update_post_meta( $attributes['id'], "_g_feedback_shortcode_atts_{$hash}", $attributes );
			}
		}
	}

	/**
	 * Toggle for printing the grunion.css stylesheet
	 *
	 * @param bool $style - the CSS style.
	 *
	 * @return bool
	 */
	public static function style( $style ) {
		$previous_style = self::$style;
		self::$style    = (bool) $style;
		return $previous_style;
	}

	/**
	 * Turn on printing of grunion.css stylesheet
	 *
	 * @see ::style()
	 * @internal
	 *
	 * @return bool
	 */
	public static function style_on() {
		return self::style( true );
	}

	/**
	 * The contact-form shortcode processor
	 *
	 * @param array       $attributes Key => Value pairs as parsed by shortcode_parse_atts().
	 * @param string|null $content The shortcode's inner content: [contact-form]$content[/contact-form].
	 *
	 * @return string HTML for the concat form.
	 */
	public static function parse( $attributes, $content ) {
		if ( Settings::is_syncing() ) {
			return '';
		}
		if ( isset( $GLOBALS['grunion_block_template_part_id'] ) ) {
			self::style_on();
			if ( is_array( $attributes ) ) {
				$attributes['block_template_part'] = $GLOBALS['grunion_block_template_part_id'];
			}
		}
		// Create a new Grunion_Contact_Form object (this class)
		$form = new Grunion_Contact_Form( $attributes, $content );

		$id = $form->get_attribute( 'id' );

		if ( ! $id ) { // something terrible has happened
			return '[contact-form]';
		}

		if ( is_feed() ) {
			return '[contact-form]';
		}

		self::$last = $form;

		// Enqueue the grunion.css stylesheet if self::$style allows it
		if ( self::$style && ( empty( $_REQUEST['action'] ) || $_REQUEST['action'] !== 'grunion_shortcode_to_json' ) ) {
			// Enqueue the style here instead of printing it, because if some other plugin has run the_post()+rewind_posts(),
			// (like VideoPress does), the style tag gets "printed" the first time and discarded, leaving the contact form unstyled.
			// when WordPress does the real loop.
			wp_enqueue_style( 'grunion.css' );
		}

		$container_classes        = array( 'wp-block-jetpack-contact-form-container' );
		$container_classes[]      = self::get_block_alignment_class( $attributes );
		$container_classes_string = implode( ' ', $container_classes );

		$r  = '';
		$r .= "<div data-test='contact-form' id='contact-form-$id' class='{$container_classes_string}'>\n";

		if ( is_wp_error( $form->errors ) && $form->errors->get_error_codes() ) {
			// There are errors.  Display them
			$r .= "<div class='form-error'>\n<h3>" . __( 'Error!', 'jetpack' ) . "</h3>\n<ul class='form-errors'>\n";
			foreach ( $form->errors->get_error_messages() as $message ) {
				$r .= "\t<li class='form-error-message'>" . esc_html( $message ) . "</li>\n";
			}
			$r .= "</ul>\n</div>\n\n";
		}

		if ( isset( $_GET['contact-form-id'] )
			&& (int) $_GET['contact-form-id'] === (int) self::$last->get_attribute( 'id' )
			&& isset( $_GET['contact-form-sent'], $_GET['contact-form-hash'] )
			&& is_string( $_GET['contact-form-hash'] )
			&& hash_equals( $form->hash, wp_unslash( $_GET['contact-form-hash'] ) ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			// The contact form was submitted.  Show the success message/results.
			$feedback_id = (int) $_GET['contact-form-sent'];

			$back_url = remove_query_arg( array( 'contact-form-id', 'contact-form-sent', '_wpnonce' ) );
			$r       .= '<div class="contact-form-submission">';

			$r_success_message = '<p class="go-back-message"> <a class="link" href="' . esc_url( $back_url ) . '">' . esc_html__( 'Go back', 'jetpack' ) . '</a> </p>';

			$r_success_message .=
				'<h4 id="contact-form-success-header">' . esc_html( $form->get_attribute( 'customThankyouHeading' ) ) .
				"</h4>\n\n";

			// Don't show the feedback details unless the nonce matches
			if ( $feedback_id && isset( $_GET['_wpnonce'] ) && wp_verify_nonce( stripslashes( $_GET['_wpnonce'] ), "contact-form-sent-{$feedback_id}" ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				$r_success_message .= self::success_message( $feedback_id, $form );
			}

			/**
			 * Filter the message returned after a successful contact form submission.
			 *
			 * @module contact-form
			 *
			 * @since 1.3.1
			 *
			 * @param string $r_success_message Success message.
			 */
			$r .= apply_filters( 'grunion_contact_form_success_message', $r_success_message );
			$r .= '</div>';
		} else {
			// Nothing special - show the normal contact form
			if ( $form->get_attribute( 'widget' )
				|| $form->get_attribute( 'block_template' )
				|| $form->get_attribute( 'block_template_part' ) ) {
				// Submit form to the current URL
				$url = remove_query_arg( array( 'contact-form-id', 'contact-form-sent', 'action', '_wpnonce' ) );
			} else {
				// Submit form to the post permalink
				$url = get_permalink();
			}

			// For SSL/TLS page. See RFC 3986 Section 4.2
			$url = set_url_scheme( $url );

			// May eventually want to send this to admin-post.php...
			/**
			 * Filter the contact form action URL.
			 *
			 * @module contact-form
			 *
			 * @since 1.3.1
			 *
			 * @param string $contact_form_id Contact form post URL.
			 * @param $post $GLOBALS['post'] Post global variable.
			 * @param int $id Contact Form ID.
			 */
			$url                     = apply_filters( 'grunion_contact_form_form_action', "{$url}#contact-form-{$id}", $GLOBALS['post'], $id );
			$has_submit_button_block = ! ( false === strpos( $content, 'wp-block-jetpack-button' ) );
			$form_classes            = 'contact-form commentsblock';

			if ( $has_submit_button_block ) {
				$form_classes .= ' wp-block-jetpack-contact-form';
			}

			$r .= "<form action='" . esc_url( $url ) . "' method='post' class='" . esc_attr( $form_classes ) . "'>\n";
			$r .= self::get_script_for_form();

			$r .= $form->body;

			// In new versions of the contact form block the button is an inner block
			// so the button does not need to be constructed server-side.
			if ( ! $has_submit_button_block ) {
				$r .= "\t<p class='contact-submit'>\n";

				$gutenberg_submit_button_classes = '';
				if ( ! empty( $attributes['submitButtonClasses'] ) ) {
					$gutenberg_submit_button_classes = ' ' . $attributes['submitButtonClasses'];
				}

				/**
				 * Filter the contact form submit button class attribute.
				 *
				 * @module contact-form
				 *
				 * @since 6.6.0
				 *
				 * @param string $class Additional CSS classes for button attribute.
				 */
				$submit_button_class = apply_filters( 'jetpack_contact_form_submit_button_class', 'pushbutton-wide' . $gutenberg_submit_button_classes );

				$submit_button_styles = '';
				if ( ! empty( $attributes['customBackgroundButtonColor'] ) ) {
					$submit_button_styles .= 'background-color: ' . $attributes['customBackgroundButtonColor'] . '; ';
				}
				if ( ! empty( $attributes['customTextButtonColor'] ) ) {
					$submit_button_styles .= 'color: ' . $attributes['customTextButtonColor'] . ';';
				}
				if ( ! empty( $attributes['submitButtonText'] ) ) {
					$submit_button_text = $attributes['submitButtonText'];
				} else {
					$submit_button_text = $form->get_attribute( 'submit_button_text' );
				}

				$r .= "\t\t<button type='submit' class='" . esc_attr( $submit_button_class ) . "'";
				if ( ! empty( $submit_button_styles ) ) {
					$r .= " style='" . esc_attr( $submit_button_styles ) . "'";
				}
				$r .= '>';
				$r .= wp_kses(
					$submit_button_text,
					self::$allowed_html_tags_for_submit_button
				) . '</button>';
			}

			if ( is_user_logged_in() ) {
				$r .= "\t\t" . wp_nonce_field( 'contact-form_' . $id, '_wpnonce', true, false ) . "\n"; // nonce and referer
			}

			if ( isset( $attributes['hasFormSettingsSet'] ) && $attributes['hasFormSettingsSet'] ) {
				$r .= "\t\t<input type='hidden' name='is_block' value='1' />\n";
			}
			$r .= "\t\t<input type='hidden' name='contact-form-id' value='$id' />\n";
			$r .= "\t\t<input type='hidden' name='action' value='grunion-contact-form' />\n";
			$r .= "\t\t<input type='hidden' name='contact-form-hash' value='" . esc_attr( $form->hash ) . "' />\n";

			if ( ! $has_submit_button_block ) {
				$r .= "\t</p>\n";
			}

			$r .= "</form>\n";
		}

		$r .= '</div>';

		/**
		 * Filter the contact form, allowing plugins to modify the HTML.
		 *
		 * @module contact-form
		 *
		 * @since 10.2.0
		 *
		 * @param string $r The contact form HTML.
		 */
		return apply_filters( 'jetpack_contact_form_html', $r );
	}

	/**
	 * Returns a success message to be returned if the form is sent via AJAX.
	 *
	 * @param int                         $feedback_id - the feedback ID.
	 * @param object Grunion_Contact_Form $form - the contact form.
	 *
	 * @return string $message
	 */
	public static function success_message( $feedback_id, $form ) {
		if ( 'message' === $form->get_attribute( 'customThankyou' ) ) {
			$message = wpautop( $form->get_attribute( 'customThankyouMessage' ) );
		} else {
			$message = '<p>' . join( '</p><p>', self::get_compiled_form( $feedback_id, $form ) ) . '</p>';
		}

		return wp_kses(
			$message,
			array(
				'br'         => array(),
				'blockquote' => array( 'class' => array() ),
				'p'          => array(),
				'div'        => array(
					'class' => array(),
					'style' => array(),
				),
			)
		);
	}

	/**
	 * Returns a script that disables the contact form button after a form submission.
	 *
	 * @return string The script.
	 */
	private static function get_script_for_form() {
		return "<script>
			( function () {
				const contact_forms = document.getElementsByClassName('contact-form');

				for ( const form of contact_forms ) {
					form.onsubmit = function() {
						const buttons = form.getElementsByTagName('button');

						for( const button of buttons ) {
							button.setAttribute('disabled', true);
						}
					}
				}
			} )();
		</script>";
	}

	/**
	 * Returns a compiled form with labels and values in a form of  an array
	 * of lines.
	 *
	 * @param int                         $feedback_id - the feedback ID.
	 * @param object Grunion_Contact_Form $form - the form.
	 *
	 * @return array $lines
	 */
	public static function get_compiled_form( $feedback_id, $form ) {
		$feedback       = get_post( $feedback_id );
		$field_ids      = $form->get_field_ids();
		$content_fields = Grunion_Contact_Form_Plugin::parse_fields_from_content( $feedback_id );

		// Maps field_ids to post_meta keys
		$field_value_map = array(
			'name'     => 'author',
			'email'    => 'author_email',
			'url'      => 'author_url',
			'subject'  => 'subject',
			'textarea' => false, // not a post_meta key.  This is stored in post_content
		);

		$compiled_form = array();

		// "Standard" field allowed list.
		foreach ( $field_value_map as $type => $meta_key ) {
			if ( isset( $field_ids[ $type ] ) ) {
				$field = $form->fields[ $field_ids[ $type ] ];

				if ( $meta_key ) {
					if ( isset( $content_fields[ "_feedback_{$meta_key}" ] ) ) {
						$value = $content_fields[ "_feedback_{$meta_key}" ];
					}
				} else {
					// The feedback content is stored as the first "half" of post_content
					$value         = $feedback->post_content;
					list( $value ) = explode( '<!--more-->', $value );
					$value         = trim( $value );
				}

				// If we still do not have any value, bail.
				if ( empty( $value ) ) {
					continue;
				}

				$field_index = array_search( $field_ids[ $type ], $field_ids['all'], true );
				$field_label = $field->get_attribute( 'label' ) ? $field->get_attribute( 'label' ) . ':' : '';

				$compiled_form[ $field_index ] = sprintf(
					'<div class="field-name">%1$s</div> <div class="field-value">%2$s</div>',
					wp_kses( $field_label, array() ),
					self::escape_and_sanitize_field_value( $value )
				);
			}
		}

		// "Non-standard" fields
		if ( $field_ids['extra'] ) {
			// array indexed by field label (not field id)
			$extra_fields = get_post_meta( $feedback_id, '_feedback_extra_fields', true );

			/**
			 * Only get data for the compiled form if `$extra_fields` is a valid and non-empty array.
			 */
			if ( is_array( $extra_fields ) && ! empty( $extra_fields ) ) {

				$extra_field_keys = array_keys( $extra_fields );

				$i = 0;
				foreach ( $field_ids['extra'] as $field_id ) {
					$field       = $form->fields[ $field_id ];
					$field_index = array_search( $field_id, $field_ids['all'], true );

					$label = $field->get_attribute( 'label' ) ? $field->get_attribute( 'label' ) . ':' : '';

					$compiled_form[ $field_index ] = sprintf(
						'<div class="field-name">%1$s</div> <div class="field-value">%2$s</div>',
						wp_kses( $label, array() ),
						self::escape_and_sanitize_field_value( $extra_fields[ $extra_field_keys[ $i ] ] )
					);

					++$i;
				}
			}
		}

		// Sorting lines by the field index
		ksort( $compiled_form );

		return $compiled_form;
	}

	/**
	 * Returns a compiled form with labels and values formatted for the email response
	 * in a form of an array of lines.
	 *
	 * @param int                         $feedback_id - the feedback ID.
	 * @param object Grunion_Contact_Form $form - the form.
	 *
	 * @return array $lines
	 */
	public static function get_compiled_form_for_email( $feedback_id, $form ) {
		$feedback       = get_post( $feedback_id );
		$field_ids      = $form->get_field_ids();
		$content_fields = Grunion_Contact_Form_Plugin::parse_fields_from_content( $feedback_id );

		// Maps field_ids to post_meta keys
		$field_value_map = array(
			'name'     => 'author',
			'email'    => 'author_email',
			'url'      => 'author_url',
			'subject'  => 'subject',
			'textarea' => false, // not a post_meta key.  This is stored in post_content
		);

		$compiled_form = array();

		// "Standard" field allowed list.
		foreach ( $field_value_map as $type => $meta_key ) {
			if ( isset( $field_ids[ $type ] ) ) {
				$field = $form->fields[ $field_ids[ $type ] ];

				if ( $meta_key ) {
					if ( isset( $content_fields[ "_feedback_{$meta_key}" ] ) ) {
						$value = $content_fields[ "_feedback_{$meta_key}" ];
					}
				} else {
					// The feedback content is stored as the first "half" of post_content
					$value         = $feedback->post_content;
					list( $value ) = explode( '<!--more-->', $value );
					$value         = trim( $value );
				}

				// If we still do not have any value, bail.
				if ( empty( $value ) ) {
					continue;
				}

				$field_index = array_search( $field_ids[ $type ], $field_ids['all'], true );
				$field_label = $field->get_attribute( 'label' ) ? $field->get_attribute( 'label' ) . ':' : '';

				$compiled_form[ $field_index ] = sprintf(
					'<p><strong>%1$s</strong><br /><span>%2$s</span></p>',
					wp_kses( $field_label, array() ),
					self::escape_and_sanitize_field_value( $value )
				);
			}
		}

		// "Non-standard" fields
		if ( $field_ids['extra'] ) {
			// array indexed by field label (not field id)
			$extra_fields = get_post_meta( $feedback_id, '_feedback_extra_fields', true );

			/**
			 * Only get data for the compiled form if `$extra_fields` is a valid and non-empty array.
			 */
			if ( is_array( $extra_fields ) && ! empty( $extra_fields ) ) {

				$extra_field_keys = array_keys( $extra_fields );

				$i = 0;
				foreach ( $field_ids['extra'] as $field_id ) {
					$field       = $form->fields[ $field_id ];
					$field_index = array_search( $field_id, $field_ids['all'], true );

					$field_label = $field->get_attribute( 'label' ) ? $field->get_attribute( 'label' ) . ':' : '';

					$compiled_form[ $field_index ] = sprintf(
						'<p><strong>%1$s</strong><br /><span>%2$s</span></p>',
						wp_kses( $field_label, array() ),
						self::escape_and_sanitize_field_value( $extra_fields[ $extra_field_keys[ $i ] ] )
					);

					++$i;
				}
			}
		}

		// Sorting lines by the field index
		ksort( $compiled_form );

		return $compiled_form;
	}

	/**
	 * Escape and sanitize the field value.
	 *
	 * @param string $value - the value we're escaping and sanitizing.
	 *
	 * @return string
	 */
	public static function escape_and_sanitize_field_value( $value ) {
		$value = str_replace( array( '[', ']' ), array( '&#91;', '&#93;' ), $value );
		return nl2br( wp_kses( $value, array() ) );
	}

	/**
	 * Only strip out empty string values and keep all the other values as they are.
	 *
	 * @param string $single_value - the single value.
	 *
	 * @return bool
	 */
	public static function remove_empty( $single_value ) {
		return ( $single_value !== '' );
	}

	/**
	 * Escape a shortcode value.
	 *
	 * Shortcode attribute values have a number of unfortunate restrictions, which fortunately we
	 * can get around by adding some extra HTML encoding.
	 *
	 * The output HTML will have a few extra escapes, but that makes no functional difference.
	 *
	 * @since 9.1.0
	 * @param string $val Value to escape.
	 * @return string
	 */
	private static function esc_shortcode_val( $val ) {
		return strtr(
			esc_html( $val ),
			array(
				// Brackets in attribute values break the shortcode parser.
				'['  => '&#091;',
				']'  => '&#093;',
				// Shortcode parser screws up backslashes too, thanks to calls to `stripcslashes`.
				'\\' => '&#092;',
				// The existing code here represents arrays as comma-separated strings.
				// Rather than trying to change representations now, just escape the commas in values.
				','  => '&#044;',
			)
		);
	}

	/**
	 * The contact-field shortcode processor.
	 * We use an object method here instead of a static Grunion_Contact_Form_Field class method to parse contact-field shortcodes so that we can tie them to the contact-form object.
	 *
	 * @param array       $attributes Key => Value pairs as parsed by shortcode_parse_atts().
	 * @param string|null $content The shortcode's inner content: [contact-field]$content[/contact-field].
	 * @return string HTML for the contact form field
	 */
	public static function parse_contact_field( $attributes, $content ) {
		// Don't try to parse contact form fields if not inside a contact form
		if ( ! Grunion_Contact_Form_Plugin::$using_contact_form_field ) {
			$type = isset( $attributes['type'] ) ? $attributes['type'] : null;

			if ( $type === 'checkbox-multiple' || $type === 'radio' ) {
				preg_match_all( '/' . get_shortcode_regex() . '/s', $content, $matches );

				if ( ! empty( $matches[0] ) ) {
					$options = array();
					foreach ( $matches[0] as $shortcode ) {
						$attr = shortcode_parse_atts( $shortcode );
						if ( ! empty( $attr['label'] ) ) {
							$options[] = $attr['label'];
						}
					}

					$attributes['options'] = $options;
				}
			}

			if ( ! isset( $attributes['label'] ) ) {
				$attributes['label'] = self::get_default_label_from_type( $type );
			}

			$att_strs = array();
			foreach ( $attributes as $att => $val ) {
				if ( is_numeric( $att ) ) { // Is a valueless attribute
					$att_strs[] = self::esc_shortcode_val( $val );
				} elseif ( isset( $val ) ) { // A regular attr - value pair
					if ( ( $att === 'options' || $att === 'values' ) && is_string( $val ) ) { // remove any empty strings
						$val = explode( ',', $val );
					}
					if ( is_array( $val ) ) {
						$val        = array_filter( $val, array( __CLASS__, 'remove_empty' ) ); // removes any empty strings
						$att_strs[] = esc_html( $att ) . '="' . implode( ',', array_map( array( __CLASS__, 'esc_shortcode_val' ), $val ) ) . '"';
					} elseif ( is_bool( $val ) ) {
						$att_strs[] = esc_html( $att ) . '="' . ( $val ? '1' : '' ) . '"';
					} else {
						$att_strs[] = esc_html( $att ) . '="' . self::esc_shortcode_val( $val ) . '"';
					}
				}
			}

			$shortcode_type = 'contact-field';
			if ( $type === 'field-option' ) {
				$shortcode_type = 'contact-field-option';
			}

			$html = '[' . $shortcode_type . ' ' . implode( ' ', $att_strs );

			if ( isset( $content ) && ! empty( $content ) ) { // If there is content, let's add a closing tag
				$html .= ']' . esc_html( $content ) . '[/contact-field]';
			} else { // Otherwise let's add a closing slash in the first tag
				$html .= '/]';
			}

			return $html;
		}

		$form = self::$current_form;

		$field = new Grunion_Contact_Form_Field( $attributes, $content, $form );

		$field_id = $field->get_attribute( 'id' );
		if ( $field_id ) {
			$form->fields[ $field_id ] = $field;
		} else {
			$form->fields[] = $field;
		}

		if ( // phpcs:disable WordPress.Security.NonceVerification.Missing
			isset( $_POST['action'] ) && 'grunion-contact-form' === $_POST['action']
			&&
			isset( $_POST['contact-form-id'] ) && (string) $form->get_attribute( 'id' ) === $_POST['contact-form-id']
			&&
			isset( $_POST['contact-form-hash'] ) && is_string( $_POST['contact-form-hash'] ) && hash_equals( $form->hash, wp_unslash( $_POST['contact-form-hash'] ) )
		) { // phpcs:enable
			// If we're processing a POST submission for this contact form, validate the field value so we can show errors as necessary.
			$field->validate();
		}

		// Output HTML
		return $field->render();
	}

	/**
	 * Get the default label from type.
	 *
	 * @param string $type - the type of label.
	 *
	 * @return string
	 */
	public static function get_default_label_from_type( $type ) {
		$str = null;
		switch ( $type ) {
			case 'text':
				$str = __( 'Text', 'jetpack' );
				break;
			case 'name':
				$str = __( 'Name', 'jetpack' );
				break;
			case 'email':
				$str = __( 'Email', 'jetpack' );
				break;
			case 'url':
				$str = __( 'Website', 'jetpack' );
				break;
			case 'date':
				$str = __( 'Date', 'jetpack' );
				break;
			case 'telephone':
				$str = __( 'Phone', 'jetpack' );
				break;
			case 'textarea':
				$str = __( 'Message', 'jetpack' );
				break;
			case 'checkbox-multiple':
				$str = __( 'Choose several options', 'jetpack' );
				break;
			case 'radio':
				$str = __( 'Choose one option', 'jetpack' );
				break;
			case 'select':
				$str = __( 'Select one option', 'jetpack' );
				break;
			case 'consent':
				$str = __( 'Consent', 'jetpack' );
				break;
			default:
				$str = null;
		}
		return $str;
	}

	/**
	 * Loops through $this->fields to generate a (structured) list of field IDs.
	 *
	 * Important: Currently the allowed fields are defined as follows:
	 *  `name`, `email`, `url`, `subject`, `textarea`
	 *
	 * If you need to add new fields to the Contact Form, please don't add them
	 * to the allowed fields and leave them as extra fields.
	 *
	 * The reasoning behind this is that both the admin Feedback view and the CSV
	 * export will not include any fields that are added to the list of
	 * allowed fields without taking proper care to add them to all the
	 * other places where they accessed/used/saved.
	 *
	 * The safest way to add new fields is to add them to the dropdown and the
	 * HTML list ( @see Grunion_Contact_Form_Field::render ) and don't add them
	 * to the list of allowed fields. This way they will become a part of the
	 * `extra fields` which are saved in the post meta and will be properly
	 * handled by the admin Feedback view and the CSV Export without any extra
	 * work.
	 *
	 * If there is need to add a field to the allowed fields, then please
	 * take proper care to add logic to handle the field in the following places:
	 *
	 *  - Below in the switch statement - so the field is recognized as allowed.
	 *
	 *  - Grunion_Contact_Form::process_submission - validation and logic.
	 *
	 *  - Grunion_Contact_Form::process_submission - add the field as an additional
	 *      field in the `post_content` when saving the feedback content.
	 *
	 *  - Grunion_Contact_Form_Plugin::parse_fields_from_content - add mapping
	 *      for the field, defined in the above method.
	 *
	 *  - Grunion_Contact_Form_Plugin::map_parsed_field_contents_of_post_to_field_names -
	 *      add mapping of the field for the CSV Export. Otherwise it will be missing
	 *      from the exported data.
	 *
	 *  - admin.php / grunion_manage_post_columns - add the field to the render logic.
	 *      Otherwise it will be missing from the admin Feedback view.
	 *
	 * @return array
	 */
	public function get_field_ids() {
		$field_ids = array(
			'all'   => array(), // array of all field_ids.
			'extra' => array(), // array of all non-allowed field IDs.

			// Allowed "standard" field IDs:
			// 'email'    => field_id,
			// 'name'     => field_id,
			// 'url'      => field_id,
			// 'subject'  => field_id,
			// 'textarea' => field_id,
		);

		// Initialize marketing consent
		$field_ids['email_marketing_consent'] = null;

		foreach ( $this->fields as $id => $field ) {
			$field_ids['all'][] = $id;

			$type = $field->get_attribute( 'type' );
			if ( isset( $field_ids[ $type ] ) ) {
				// This type of field is already present in our allowed list of "standard" fields for this form
				// Put it in extra
				$field_ids['extra'][] = $id;
				continue;
			}

			/**
			 * See method description before modifying the switch cases.
			 */
			switch ( $type ) {
				case 'email':
				case 'name':
				case 'url':
				case 'subject':
				case 'textarea':
					$field_ids[ $type ] = $id;
					break;
				case 'consent':
					// Set email marketing consent for the first Consent type field
					if ( null === $field_ids['email_marketing_consent'] ) {
						if ( $field->value ) {
							$field_ids['email_marketing_consent'] = true;
						} else {
							$field_ids['email_marketing_consent'] = false;
						}
					}
					$field_ids['extra'][] = $id;
					break;
				default:
					// Put everything else in extra
					$field_ids['extra'][] = $id;
			}
		}

		return $field_ids;
	}

	/**
	 * Process the contact form's POST submission
	 * Stores feedback.  Sends email.
	 */
	public function process_submission() {
		global $post;

		$plugin = Grunion_Contact_Form_Plugin::init();

		$id                  = $this->get_attribute( 'id' );
		$to                  = $this->get_attribute( 'to' );
		$widget              = $this->get_attribute( 'widget' );
		$block_template      = $this->get_attribute( 'block_template' );
		$block_template_part = $this->get_attribute( 'block_template_part' );

		$contact_form_subject = $this->get_attribute( 'subject' );

		$to     = str_replace( ' ', '', $to );
		$emails = explode( ',', $to );

		$valid_emails = array();

		foreach ( (array) $emails as $email ) {
			if ( ! is_email( $email ) ) {
				continue;
			}

			if ( function_exists( 'is_email_address_unsafe' ) && is_email_address_unsafe( $email ) ) {
				continue;
			}

			$valid_emails[] = $email;
		}

		// No one to send it to, which means none of the "to" attributes are valid emails.
		// Use default email instead.
		if ( ! $valid_emails ) {
			$valid_emails = $this->defaults['to'];
		}

		$to = $valid_emails;

		// Last ditch effort to set a recipient if somehow none have been set.
		if ( empty( $to ) ) {
			$to = get_option( 'admin_email' );
		}

		// Make sure we're processing the form we think we're processing... probably a redundant check.
		if ( $widget ) {
			if ( isset( $_POST['contact-form-id'] ) && 'widget-' . $widget !== $_POST['contact-form-id'] ) { // phpcs:Ignore WordPress.Security.NonceVerification.Missing -- check done by caller process_form_submission()
				return false;
			}
		} elseif ( $block_template ) {
			if ( isset( $_POST['contact-form-id'] ) && 'block-template-' . $block_template !== $_POST['contact-form-id'] ) { // phpcs:Ignore WordPress.Security.NonceVerification.Missing -- check done by caller process_form_submission()
				return false;
			}
		} elseif ( $block_template_part ) {
			if ( isset( $_POST['contact-form-id'] ) && 'block-template-part-' . $block_template_part !== $_POST['contact-form-id'] ) { // phpcs:Ignore WordPress.Security.NonceVerification.Missing -- check done by caller process_form_submission()
				return false;
			}
		} elseif ( isset( $_POST['contact-form-id'] ) && $post->ID !== (int) $_POST['contact-form-id'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- check done by caller process_form_submission()
			return false;
		}

		$field_ids = $this->get_field_ids();

		// Initialize all these "standard" fields to null
		$comment_author_email = null;
		$comment_author       = null;
		$comment_author_url   = null;
		$comment_content      = null;

		// For each of the "standard" fields, grab their field label and value.
		if ( isset( $field_ids['name'] ) ) {
			$field          = $this->fields[ $field_ids['name'] ];
			$comment_author = Grunion_Contact_Form_Plugin::strip_tags(
				stripslashes(
					/** This filter is already documented in core/wp-includes/comment-functions.php */
					apply_filters( 'pre_comment_author_name', addslashes( $field->value ) )
				)
			);
		}

		if ( isset( $field_ids['email'] ) ) {
			$field                = $this->fields[ $field_ids['email'] ];
			$comment_author_email = Grunion_Contact_Form_Plugin::strip_tags(
				stripslashes(
					/** This filter is already documented in core/wp-includes/comment-functions.php */
					apply_filters( 'pre_comment_author_email', addslashes( $field->value ) )
				)
			);
		}

		if ( isset( $field_ids['url'] ) ) {
			$field              = $this->fields[ $field_ids['url'] ];
			$comment_author_url = Grunion_Contact_Form_Plugin::strip_tags(
				stripslashes(
					/** This filter is already documented in core/wp-includes/comment-functions.php */
					apply_filters( 'pre_comment_author_url', addslashes( $field->value ) )
				)
			);
			if ( 'http://' === $comment_author_url ) {
				$comment_author_url = '';
			}
		}

		if ( isset( $field_ids['textarea'] ) ) {
			$field           = $this->fields[ $field_ids['textarea'] ];
			$comment_content = trim( Grunion_Contact_Form_Plugin::strip_tags( $field->value ) );
		}

		if ( isset( $field_ids['subject'] ) ) {
			$field = $this->fields[ $field_ids['subject'] ];
			if ( $field->value ) {
				$contact_form_subject = Grunion_Contact_Form_Plugin::strip_tags( $field->value );
			}
		}

		// Set marketing consent
		$email_marketing_consent = $field_ids['email_marketing_consent'];

		if ( null === $email_marketing_consent ) {
			$email_marketing_consent = false;
		}

		$all_values   = array();
		$extra_values = array();
		$i            = 1; // Prefix counter for stored metadata

		// For all fields, grab label and value
		foreach ( $field_ids['all'] as $field_id ) {
			$field = $this->fields[ $field_id ];
			$label = $i . '_' . $field->get_attribute( 'label' );
			$value = $field->value;

			$all_values[ $label ] = $value;
			++$i; // Increment prefix counter for the next field
		}

		// For the "non-standard" fields, grab label and value
		// Extra fields have their prefix starting from count( $all_values ) + 1
		foreach ( $field_ids['extra'] as $field_id ) {
			$field = $this->fields[ $field_id ];
			$label = $i . '_' . $field->get_attribute( 'label' );
			$value = $field->value;

			if ( is_array( $value ) ) {
				$value = implode( ', ', $value );
			}

			$extra_values[ $label ] = $value;
			++$i; // Increment prefix counter for the next extra field
		}

		if ( ! empty( $_REQUEST['is_block'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- not changing the site.
			$extra_values['is_block'] = true;
		}

		$contact_form_subject = trim( $contact_form_subject );

		$comment_author_IP = Grunion_Contact_Form_Plugin::get_ip_address(); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.VariableNotSnakeCase

		$vars = array( 'comment_author', 'comment_author_email', 'comment_author_url', 'contact_form_subject', 'comment_author_IP' );
		foreach ( $vars as $var ) {
			$$var = str_replace( array( "\n", "\r" ), '', (string) $$var );
		}

		// Ensure that Akismet gets all of the relevant information from the contact form,
		// not just the textarea field and predetermined subject.
		$akismet_vars                    = compact( $vars );
		$akismet_vars['comment_content'] = $comment_content;

		foreach ( array_merge( $field_ids['all'], $field_ids['extra'] ) as $field_id ) {
			$field = $this->fields[ $field_id ];

			// Skip any fields that are just a choice from a pre-defined list. They wouldn't have any value
			// from a spam-filtering point of view.
			if ( in_array( $field->get_attribute( 'type' ), array( 'select', 'checkbox', 'checkbox-multiple', 'radio' ), true ) ) {
				continue;
			}

			// Normalize the label into a slug.
			$field_slug = trim( // Strip all leading/trailing dashes.
				preg_replace(   // Normalize everything to a-z0-9_-
					'/[^a-z0-9_]+/',
					'-',
					strtolower( $field->get_attribute( 'label' ) ) // Lowercase
				),
				'-'
			);

			$field_value = ( is_array( $field->value ) ) ? trim( implode( ', ', $field->value ) ) : trim( $field->value );

			// Skip any values that are already in the array we're sending.
			if ( $field_value && in_array( $field_value, $akismet_vars, true ) ) {
				continue;
			}

			$akismet_vars[ 'contact_form_field_' . $field_slug ] = $field_value;
		}

		$spam           = '';
		$akismet_values = $plugin->prepare_for_akismet( $akismet_vars );

		// Is it spam?
		/** This filter is already documented in modules/contact-form/admin.php */
		$is_spam = apply_filters( 'jetpack_contact_form_is_spam', false, $akismet_values );
		if ( is_wp_error( $is_spam ) ) { // WP_Error to abort
			return $is_spam; // abort
		} elseif ( $is_spam === true ) {  // TRUE to flag a spam
			$spam = '***SPAM*** ';
		}

		/**
		 * Filter whether a submitted contact form is in the comment disallowed list.
		 *
		 * @module contact-form
		 *
		 * @since 8.9.0
		 *
		 * @param bool  $result         Is the submitted feedback in the disallowed list.
		 * @param array $akismet_values Feedack values returned by the Akismet plugin.
		 */
		$in_comment_disallowed_list = apply_filters( 'jetpack_contact_form_in_comment_disallowed_list', false, $akismet_values );

		if ( ! $comment_author ) {
			$comment_author = $comment_author_email;
		}

		/**
		 * Filter the email where a submitted feedback is sent.
		 *
		 * @module contact-form
		 *
		 * @since 1.3.1
		 *
		 * @param string|array $to Array of valid email addresses, or single email address.
		 * @param array $all_values Contact form fields
		 */
		$to            = (array) apply_filters( 'contact_form_to', $to, $all_values );
		$reply_to_addr = $to[0]; // get just the address part before the name part is added

		foreach ( $to as $to_key => $to_value ) {
			$to[ $to_key ] = Grunion_Contact_Form_Plugin::strip_tags( $to_value );
			$to[ $to_key ] = self::add_name_to_address( $to_value );
		}

		$blog_url        = wp_parse_url( site_url() );
		$from_email_addr = 'wordpress@' . $blog_url['host'];

		if ( ! empty( $comment_author_email ) ) {
			$reply_to_addr = $comment_author_email;
		}

		/*
		 * The email headers here are formatted in a format
		 * that is the most likely to be accepted by wp_mail(),
		 * without escaping.
		 * More info: https://github.com/Automattic/jetpack/pull/19727
		 */
		$headers = 'From: ' . $comment_author . ' <' . $from_email_addr . ">\r\n" .
			'Reply-To: ' . $comment_author . ' <' . $reply_to_addr . ">\r\n";

		/**
		 * Allow customizing the email headers.
		 *
		 * Warning: DO NOT add headers or header data from the form submission without proper
		 * escaping and validation, or you're liable to allow abusers to use your site to send spam.
		 *
		 * Especially DO NOT take email addresses from the form data to add as CC or BCC headers
		 * without strictly validating each address against a list of allowed addresses.
		 *
		 * @module contact-form
		 *
		 * @since 10.2.0
		 *
		 * @param string|array $headers        Email headers.
		 * @param string       $comment_author Name of the author of the submitted feedback, if provided in form.
		 * @param string       $reply_to_addr  Email of the author of the submitted feedback, if provided in form.
		 * @param string|array $to             Array of valid email addresses, or single email address, where the form is sent.
		 */
		$headers = apply_filters(
			'jetpack_contact_form_email_headers',
			$headers,
			$comment_author,
			$reply_to_addr,
			$to
		);

		$all_values['email_marketing_consent'] = $email_marketing_consent;

		// Build feedback reference
		$feedback_time  = current_time( 'mysql' );
		$feedback_title = "{$comment_author} - {$feedback_time}";
		$feedback_id    = md5( $feedback_title );

		$entry_values = array(
			'entry_title'     => the_title_attribute( 'echo=0' ),
			'entry_permalink' => esc_url( get_permalink( get_the_ID() ) ),
			'feedback_id'     => $feedback_id,
		);

		$all_values = array_merge( $all_values, $entry_values );

		/** This filter is already documented in modules/contact-form/admin.php */
		$subject = apply_filters( 'contact_form_subject', $contact_form_subject, $all_values );
		$url     = $block_template || $block_template_part || $widget ? home_url( '/' ) : get_permalink( $post->ID );

		// translators: the time of the form submission.
		$date_time_format = _x( '%1$s \a\t %2$s', '{$date_format} \a\t {$time_format}', 'jetpack' );
		$date_time_format = sprintf( $date_time_format, get_option( 'date_format' ), get_option( 'time_format' ) );
		$time             = wp_date( $date_time_format );

		// Keep a copy of the feedback as a custom post type.
		if ( $in_comment_disallowed_list ) {
			$feedback_status = 'trash';
		} elseif ( $is_spam ) {
			$feedback_status = 'spam';
		} else {
			$feedback_status = 'publish';
		}

		foreach ( (array) $akismet_values as $av_key => $av_value ) {
			$akismet_values[ $av_key ] = Grunion_Contact_Form_Plugin::strip_tags( $av_value );
		}

		foreach ( (array) $all_values as $all_key => $all_value ) {
			$all_values[ $all_key ] = Grunion_Contact_Form_Plugin::strip_tags( $all_value );
		}

		foreach ( (array) $extra_values as $ev_key => $ev_value ) {
			$extra_values[ $ev_key ] = Grunion_Contact_Form_Plugin::strip_tags( $ev_value );
		}

		/*
		 * We need to make sure that the post author is always zero for contact
		 * form submissions.  This prevents export/import from trying to create
		 * new users based on form submissions from people who were logged in
		 * at the time.
		 *
		 * Unfortunately wp_insert_post() tries very hard to make sure the post
		 * author gets the currently logged in user id.  That is how we ended up
		 * with this work around.
		 */
		add_filter( 'wp_insert_post_data', array( $plugin, 'insert_feedback_filter' ), 10, 2 );

		$post_id = wp_insert_post(
			array(
				'post_date'    => addslashes( $feedback_time ),
				'post_type'    => 'feedback',
				'post_status'  => addslashes( $feedback_status ),
				'post_parent'  => $post ? (int) $post->ID : 0,
				'post_title'   => addslashes( wp_kses( $feedback_title, array() ) ),
				// phpcs:ignore WordPress.NamingConventions.ValidVariableName.InterpolatedVariableNotSnakeCase, WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.PHP.DevelopmentFunctions.error_log_print_r
				'post_content' => addslashes( wp_kses( "$comment_content\n<!--more-->\nAUTHOR: {$comment_author}\nAUTHOR EMAIL: {$comment_author_email}\nAUTHOR URL: {$comment_author_url}\nSUBJECT: {$subject}\nIP: {$comment_author_IP}\nJSON_DATA\n" . @wp_json_encode( $all_values, true ), array() ) ), // so that search will pick up this data
				'post_name'    => $feedback_id,
			)
		);

		// once insert has finished we don't need this filter any more
		remove_filter( 'wp_insert_post_data', array( $plugin, 'insert_feedback_filter' ), 10 );

		update_post_meta( $post_id, '_feedback_extra_fields', $this->addslashes_deep( $extra_values ) );

		if ( 'publish' === $feedback_status ) {
			// Increase count of unread feedback.
			$unread = get_option( 'feedback_unread_count', 0 ) + 1;
			update_option( 'feedback_unread_count', $unread );
		}

		if ( defined( 'AKISMET_VERSION' ) ) {
			update_post_meta( $post_id, '_feedback_akismet_values', $this->addslashes_deep( $akismet_values ) );
		}

		/**
		 * Fires after the feedback post for the contact form submission has been inserted.
		 *
		 * @module contact-form
		 *
		 * @since 8.6.0
		 *
		 * @param integer $post_id The post id that contains the contact form data.
		 * @param array   $this->fields An array containg the form's Grunion_Contact_Form_Field objects.
		 * @param boolean $is_spam Whether the form submission has been identified as spam.
		 * @param array   $entry_values The feedback entry values.
		 */
		do_action( 'grunion_after_feedback_post_inserted', $post_id, $this->fields, $is_spam, $entry_values );

		$message = self::get_compiled_form_for_email( $post_id, $this );

		array_push(
			$message,
			'<br />',
			'<hr />',
			__( 'Time:', 'jetpack' ) . ' ' . $time . '<br />',
			__( 'IP Address:', 'jetpack' ) . ' ' . $comment_author_IP . '<br />', // phpcs:ignore WordPress.NamingConventions.ValidVariableName.VariableNotSnakeCase
			__( 'Contact Form URL:', 'jetpack' ) . ' ' . $url . '<br />'
		);

		if ( is_user_logged_in() ) {
			array_push(
				$message,
				sprintf(
					// translators: the the name of the site.
					'<p>' . __( 'Sent by a verified %s user.', 'jetpack' ) . '</p>',
					isset( $GLOBALS['current_site']->site_name ) && $GLOBALS['current_site']->site_name ?
						$GLOBALS['current_site']->site_name : '"' . get_option( 'blogname' ) . '"'
				)
			);
		} else {
			array_push( $message, '<p>' . __( 'Sent by an unverified visitor to your site.', 'jetpack' ) . '</p>' );
		}

		$message = join( '', $message );

		/**
		 * Filters the message sent via email after a successful form submission.
		 *
		 * @module contact-form
		 *
		 * @since 1.3.1
		 *
		 * @param string $message Feedback email message.
		 */
		$message = apply_filters( 'contact_form_message', $message );

		// This is called after `contact_form_message`, in order to preserve back-compat
		$message = self::wrap_message_in_html_tags( $message );

		update_post_meta( $post_id, '_feedback_email', $this->addslashes_deep( compact( 'to', 'message' ) ) );

		/**
		 * Fires right before the contact form message is sent via email to
		 * the recipient specified in the contact form.
		 *
		 * @module contact-form
		 *
		 * @since 1.3.1
		 *
		 * @param integer $post_id Post contact form lives on
		 * @param array $all_values Contact form fields
		 * @param array $extra_values Contact form fields not included in $all_values
		 */
		do_action( 'grunion_pre_message_sent', $post_id, $all_values, $extra_values );

		// schedule deletes of old spam feedbacks
		if ( ! wp_next_scheduled( 'grunion_scheduled_delete' ) ) {
			wp_schedule_event( time() + 250, 'daily', 'grunion_scheduled_delete' );
		}

		if (
			$is_spam !== true &&
			/**
			 * Filter to choose whether an email should be sent after each successful contact form submission.
			 *
			 * @module contact-form
			 *
			 * @since 2.6.0
			 *
			 * @param bool true Should an email be sent after a form submission. Default to true.
			 * @param int $post_id Post ID.
			 */
			true === apply_filters( 'grunion_should_send_email', true, $post_id )
		) {
			self::wp_mail( $to, "{$spam}{$subject}", $message, $headers );
		} elseif (
			true === $is_spam &&
			/**
			 * Choose whether an email should be sent for each spam contact form submission.
			 *
			 * @module contact-form
			 *
			 * @since 1.3.1
			 *
			 * @param bool false Should an email be sent after a spam form submission. Default to false.
			 */
			apply_filters( 'grunion_still_email_spam', false )
		) { // don't send spam by default.  Filterable.
			self::wp_mail( $to, "{$spam}{$subject}", $message, $headers );
		}

		/**
		 * Fires an action hook right after the email(s) have been sent.
		 *
		 * @module contact-form
		 *
		 * @since 7.3.0
		 *
		 * @param int $post_id Post contact form lives on.
		 * @param string|array $to Array of valid email addresses, or single email address.
		 * @param string $subject Feedback email subject.
		 * @param string $message Feedback email message.
		 * @param string|array $headers Optional. Additional headers.
		 * @param array $all_values Contact form fields.
		 * @param array $extra_values Contact form fields not included in $all_values
		 */
		do_action( 'grunion_after_message_sent', $post_id, $to, $subject, $message, $headers, $all_values, $extra_values );

		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			return self::success_message( $post_id, $this );
		}

		$redirect        = '';
		$custom_redirect = false;
		if ( 'redirect' === $this->get_attribute( 'customThankyou' ) ) {
			$custom_redirect = true;
			$redirect        = esc_url_raw( $this->get_attribute( 'customThankyouRedirect' ) );
		}

		if ( ! $redirect ) {
			$custom_redirect = false;
			$redirect        = wp_get_referer();
		}

		if ( ! $redirect ) { // wp_get_referer() returns false if the referer is the same as the current page.
			$custom_redirect = false;
			$redirect        = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		}

		if ( ! $custom_redirect ) {
			$redirect = add_query_arg(
				urlencode_deep(
					array(
						'contact-form-id'   => $id,
						'contact-form-sent' => $post_id,
						'contact-form-hash' => $this->hash,
						'_wpnonce'          => wp_create_nonce( "contact-form-sent-{$post_id}" ), // wp_nonce_url HTMLencodes :( .
					)
				),
				$redirect
			);
		}

		/**
		 * Filter the URL where the reader is redirected after submitting a form.
		 *
		 * @module contact-form
		 *
		 * @since 1.9.0
		 *
		 * @param string $redirect Post submission URL.
		 * @param int $id Contact Form ID.
		 * @param int $post_id Post ID.
		 */
		$redirect = apply_filters( 'grunion_contact_form_redirect_url', $redirect, $id, $post_id );

		// phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- We intentially allow external redirects here.
		wp_redirect( $redirect );
		exit;
	}

	/**
	 * Wrapper for wp_mail() that enables HTML messages with text alternatives
	 *
	 * @param string|array $to          Array or comma-separated list of email addresses to send message.
	 * @param string       $subject     Email subject.
	 * @param string       $message     Message contents.
	 * @param string|array $headers     Optional. Additional headers.
	 * @param string|array $attachments Optional. Files to attach.
	 *
	 * @return bool Whether the email contents were sent successfully.
	 */
	public static function wp_mail( $to, $subject, $message, $headers = '', $attachments = array() ) {
		add_filter( 'wp_mail_content_type', __CLASS__ . '::get_mail_content_type' );
		add_action( 'phpmailer_init', __CLASS__ . '::add_plain_text_alternative' );

		$result = wp_mail( $to, $subject, $message, $headers, $attachments );

		remove_filter( 'wp_mail_content_type', __CLASS__ . '::get_mail_content_type' );
		remove_action( 'phpmailer_init', __CLASS__ . '::add_plain_text_alternative' );

		return $result;
	}

	/**
	 * Add a display name part to an email address
	 *
	 * SpamAssassin doesn't like addresses in HTML messages that are missing display names (e.g., `foo@bar.org`
	 * instead of `Foo Bar <foo@bar.org>`.
	 *
	 * @param string $address - the email address.
	 *
	 * @return string
	 */
	public function add_name_to_address( $address ) {
		// If it's just the address, without a display name
		if ( is_email( $address ) ) {
			$address_parts = explode( '@', $address );

			/*
			 * The email address format here is formatted in a format
			 * that is the most likely to be accepted by wp_mail(),
			 * without escaping.
			 * More info: https://github.com/Automattic/jetpack/pull/19727
			 */
			$address = sprintf( '%s <%s>', $address_parts[0], $address );
		}

		return $address;
	}

	/**
	 * Get the content type that should be assigned to outbound emails
	 *
	 * @return string
	 */
	public static function get_mail_content_type() {
		return 'text/html';
	}

	/**
	 * Wrap a message body with the appropriate in HTML tags
	 *
	 * This helps to ensure correct parsing by clients, and also helps avoid triggering spam filtering rules
	 *
	 * @param string $body - the message body.
	 *
	 * @return string
	 */
	public static function wrap_message_in_html_tags( $body ) {
		// Don't do anything if the message was already wrapped in HTML tags
		// That could have be done by a plugin via filters
		if ( false !== strpos( $body, '<html' ) ) {
			return $body;
		}

		$html_message = sprintf(
			// The tabs are just here so that the raw code is correctly formatted for developers
			// They're removed so that they don't affect the final message sent to users
			str_replace(
				"\t",
				'',
				'<!doctype html>
				<html xmlns="http://www.w3.org/1999/xhtml">
				<body>

				%s

				</body>
				</html>'
			),
			$body
		);

		return $html_message;
	}

	/**
	 * Add a plain-text alternative part to an outbound email
	 *
	 * This makes the message more accessible to mail clients that aren't HTML-aware, and decreases the likelihood
	 * that the message will be flagged as spam.
	 *
	 * @param PHPMailer $phpmailer - the phpmailer.
	 */
	public static function add_plain_text_alternative( $phpmailer ) {
		// phpcs:disable WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase

		// Add an extra break so that the extra space above the <p> is preserved after the <p> is stripped out
		$alt_body = str_replace( '<p>', '<p><br />', $phpmailer->Body );

		// Convert <br> to \n breaks, to preserve the space between lines that we want to keep
		$alt_body = str_replace( array( '<br>', '<br />' ), "\n", $alt_body );

		// Convert <div> to \n breaks, to preserve space between lines for new email formatting.
		$alt_body = str_replace( '<div', "\n<div", $alt_body );

		// Convert <hr> to an plain-text equivalent, to preserve the integrity of the message
		$alt_body = str_replace( array( '<hr>', '<hr />' ), "----\n", $alt_body );

		// Trim the plain text message to remove the \n breaks that were after <doctype>, <html>, and <body>
		$phpmailer->AltBody = trim( wp_strip_all_tags( $alt_body ) );
		// phpcs:enable WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
	}

	/**
	 * Add deepslashes.
	 *
	 * @param array $value - the value.
	 * @return array The value, with slashes added.
	 */
	public function addslashes_deep( $value ) {
		if ( is_array( $value ) ) {
			return array_map( array( $this, 'addslashes_deep' ), $value );
		} elseif ( is_object( $value ) ) {
			$vars = get_object_vars( $value );
			foreach ( $vars as $key => $data ) {
				$value->{$key} = $this->addslashes_deep( $data );
			}
			return $value;
		}

		return addslashes( $value );
	}

	/**
	 * Rough implementation of Gutenberg's align-attribute-to-css-class map.
	 * Only allowin "wide" and "full" as "center", "left" and "right" don't
	 * make much sense for the form.
	 *
	 * @param array $attributes Block attributes.
	 * @return string The CSS alignment class: alignfull | alignwide.
	 */
	public static function get_block_alignment_class( $attributes = array() ) {
		$align_to_class_map = array(
			'wide' => 'alignwide',
			'full' => 'alignfull',
		);
		if ( empty( $attributes['align'] ) || ! array_key_exists( $attributes['align'], $align_to_class_map ) ) {
			return '';
		}
		return $align_to_class_map[ $attributes['align'] ];
	}
} // end class Grunion_Contact_Form

// phpcs:disable Generic.Files.OneObjectStructurePerFile.MultipleFound -- how many times I have to disable this?
/**
 * Class for the contact-field shortcode.
 * Parses shortcode to output the contact form field as HTML.
 * Validates input.
 */
class Grunion_Contact_Form_Field extends Crunion_Contact_Form_Shortcode {

	/**
	 * The shortcode name.
	 *
	 * @var string
	 */
	public $shortcode_name = 'contact-field';

	/**
	 * The parent form.
	 *
	 * @var Grunion_Contact_Form
	 */
	public $form;

	/**
	 * Default or POSTed value.
	 *
	 * @var string
	 */
	public $value;

	/**
	 * Is the input valid?
	 *
	 * @var bool
	 */
	public $error = false;

	/**
	 * Styles to be applied to the field
	 *
	 * @var string
	 */
	public $block_styles = '';

	/**
	 * Styles to be applied to the field
	 *
	 * @var string
	 */
	public $field_styles = '';

	/**
	 * Styles to be applied to the field option
	 *
	 * @var string
	 */
	public $option_styles = '';

	/**
	 * Styles to be applied to the field
	 *
	 * @var string
	 */
	public $label_styles = '';

	/**
	 * Constructor function.
	 *
	 * @param array                $attributes An associative array of shortcode attributes.  @see shortcode_atts().
	 * @param null|string          $content Null for selfclosing shortcodes.  The inner content otherwise.
	 * @param Grunion_Contact_Form $form The parent form.
	 */
	public function __construct( $attributes, $content = null, $form = null ) {
		$attributes = shortcode_atts(
			array(
				'label'                  => null,
				'togglelabel'            => null,
				'type'                   => 'text',
				'required'               => false,
				'requiredtext'           => null,
				'options'                => array(),
				'id'                     => null,
				'style'                  => null,
				'fieldbackgroundcolor'   => null,
				'textcolor'              => null,
				'default'                => null,
				'values'                 => null,
				'placeholder'            => null,
				'class'                  => null,
				'width'                  => null,
				'consenttype'            => null,
				'implicitconsentmessage' => null,
				'explicitconsentmessage' => null,
				'borderradius'           => null,
				'borderwidth'            => null,
				'lineheight'             => null,
				'labellineheight'        => null,
				'bordercolor'            => null,
				'inputcolor'             => null,
				'labelcolor'             => null,
				'labelfontsize'          => null,
				'fieldfontsize'          => null,
			),
			$attributes,
			'contact-field'
		);

		// special default for subject field
		if ( 'subject' === $attributes['type'] && $attributes['default'] === null && $form !== null ) {
			$attributes['default'] = $form->get_attribute( 'subject' );
		}

		// allow required=1 or required=true
		if ( '1' === $attributes['required'] || 'true' === strtolower( $attributes['required'] ) ) {
			$attributes['required'] = true;
		} else {
			$attributes['required'] = false;
		}

		if ( $attributes['requiredtext'] === null ) {
			$attributes['requiredtext'] = __( '(required)', 'jetpack' );
		}

		// parse out comma-separated options list (for selects, radios, and checkbox-multiples)
		if ( ! empty( $attributes['options'] ) && is_string( $attributes['options'] ) ) {
			$attributes['options'] = array_map( 'trim', explode( ',', $attributes['options'] ) );

			if ( ! empty( $attributes['values'] ) && is_string( $attributes['values'] ) ) {
				$attributes['values'] = array_map( 'trim', explode( ',', $attributes['values'] ) );
			}
		}

		if ( $form ) {
			// make a unique field ID based on the label, with an incrementing number if needed to avoid clashes
			$form_id = $form->get_attribute( 'id' );
			$id      = isset( $attributes['id'] ) ? $attributes['id'] : false;

			$unescaped_label = $this->unesc_attr( $attributes['label'] );
			$unescaped_label = str_replace( '%', '-', $unescaped_label ); // jQuery doesn't like % in IDs?
			$unescaped_label = preg_replace( '/[^a-zA-Z0-9.-_:]/', '', $unescaped_label );

			if ( empty( $id ) ) {
				$id        = sanitize_title_with_dashes( 'g' . $form_id . '-' . $unescaped_label );
				$i         = 0;
				$max_tries = 99;
				while ( isset( $form->fields[ $id ] ) ) {
					++$i;
					$id = sanitize_title_with_dashes( 'g' . $form_id . '-' . $unescaped_label . '-' . $i );

					if ( $i > $max_tries ) {
						break;
					}
				}
			}

			$attributes['id'] = $id;
		}

		parent::__construct( $attributes, $content );

		// Store parent form
		$this->form = $form;
	}

	/**
	 * This field's input is invalid.  Flag as invalid and add an error to the parent form
	 *
	 * @param string $message The error message to display on the form.
	 */
	public function add_error( $message ) {
		$this->is_error = true;

		if ( ! is_wp_error( $this->form->errors ) ) {
			$this->form->errors = new WP_Error();
		}

		$this->form->errors->add( $this->get_attribute( 'id' ), $message );
	}

	/**
	 * Is the field input invalid?
	 *
	 * @see $error
	 *
	 * @return bool
	 */
	public function is_error() {
		return $this->error;
	}

	/**
	 * Validates the form input
	 */
	public function validate() {
		// If it's not required, there's nothing to validate
		if ( ! $this->get_attribute( 'required' ) ) {
			return;
		}

		$field_id    = $this->get_attribute( 'id' );
		$field_type  = $this->maybe_override_type();
		$field_label = $this->get_attribute( 'label' );

		if ( isset( $_POST[ $field_id ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- no site changes.
			if ( is_array( $_POST[ $field_id ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- no site changes.
				$field_value = array_map( 'sanitize_text_field', wp_unslash( $_POST[ $field_id ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce verification should happen in caller.
			} else {
				$field_value = sanitize_text_field( wp_unslash( $_POST[ $field_id ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce verification should happen in caller.
			}
		} else {
			$field_value = '';
		}

		switch ( $field_type ) {
			case 'url':
				if ( ! is_string( $field_value ) || empty( $field_value ) || ! preg_match(
					'%^(?:(?:https?|ftp)://)?(?:\S+(?::\S*)?@|\d{1,3}(?:\.\d{1,3}){3}|(?:(?:[a-z\d\x{00a1}-\x{ffff}]+-?)*[a-z\d\x{00a1}-\x{ffff}]+)(?:\.(?:[a-z\d\x{00a1}-\x{ffff}]+-?)*[a-z\d\x{00a1}-\x{ffff}]+)*(?:\.[a-z\x{00a1}-\x{ffff}]{2,6}))(?::\d+)?(?:[^\s]*)?$%iu',
					$field_value
				) ) {
					/* translators: %s is the name of a form field */
					$this->add_error( sprintf( __( '%s: Please enter a valid URL - https://www.example.com', 'jetpack' ), $field_label ) );
				}
				break;
			case 'email':
				// Make sure the email address is valid
				if ( ! is_string( $field_value ) || ! is_email( $field_value ) ) {
					/* translators: %s is the name of a form field */
					$this->add_error( sprintf( __( '%s requires a valid email address', 'jetpack' ), $field_label ) );
				}
				break;
			case 'checkbox-multiple':
				// Check that there is at least one option selected
				if ( empty( $field_value ) ) {
					/* translators: %s is the name of a form field */
					$this->add_error( sprintf( __( '%s requires at least one selection', 'jetpack' ), $field_label ) );
				}
				break;
			default:
				// Just check for presence of any text
				if ( ! is_string( $field_value ) || ! strlen( trim( $field_value ) ) ) {
					/* translators: %s is the name of a form field */
					$this->add_error( sprintf( __( '%s is required', 'jetpack' ), $field_label ) );
				}
		}
	}

	/**
	 * Check the default value for options field
	 *
	 * @param string $value - the value we're checking.
	 * @param int    $index - the index.
	 * @param string $options - default field option.
	 *
	 * @return string
	 */
	public function get_option_value( $value, $index, $options ) {
		if ( empty( $value[ $index ] ) ) {
			return $options;
		}
		return $value[ $index ];
	}

	/**
	 * Outputs the HTML for this form field
	 *
	 * @return string HTML
	 */
	public function render() {
		global $current_user, $user_identity;

		$field_id            = $this->get_attribute( 'id' );
		$field_type          = $this->maybe_override_type();
		$field_label         = $this->get_attribute( 'label' );
		$field_required      = $this->get_attribute( 'required' );
		$field_required_text = $this->get_attribute( 'requiredtext' );
		$field_placeholder   = $this->get_attribute( 'placeholder' );
		$field_width         = $this->get_attribute( 'width' );
		$class               = 'date' === $field_type ? 'jp-contact-form-date' : $this->get_attribute( 'class' );

		if ( is_numeric( $this->get_attribute( 'borderradius' ) ) ) {
			$this->block_styles .= '--jetpack--contact-form--border-radius: ' . esc_attr( $this->get_attribute( 'borderradius' ) ) . 'px;';
			$this->field_styles .= 'border-radius: ' . (int) $this->get_attribute( 'borderradius' ) . 'px;';
		}
		if ( is_numeric( $this->get_attribute( 'borderwidth' ) ) ) {
			$this->block_styles .= '--jetpack--contact-form--border-size: ' . esc_attr( $this->get_attribute( 'borderwidth' ) ) . 'px;';
			$this->field_styles .= 'border-width: ' . (int) $this->get_attribute( 'borderwidth' ) . 'px;';
		}
		if ( is_numeric( $this->get_attribute( 'lineheight' ) ) ) {
			$this->block_styles  .= '--jetpack--contact-form--line-height: ' . esc_attr( $this->get_attribute( 'lineheight' ) ) . ';';
			$this->field_styles  .= 'line-height: ' . (int) $this->get_attribute( 'lineheight' ) . ';';
			$this->option_styles .= 'line-height: ' . (int) $this->get_attribute( 'lineheight' ) . ';';
		}
		if ( ! empty( $this->get_attribute( 'bordercolor' ) ) ) {
			$this->block_styles .= '--jetpack--contact-form--border-color: ' . esc_attr( $this->get_attribute( 'bordercolor' ) ) . ';';
			$this->field_styles .= 'border-color: ' . esc_attr( $this->get_attribute( 'bordercolor' ) ) . ';';
		}
		if ( ! empty( $this->get_attribute( 'inputcolor' ) ) ) {
			$this->block_styles  .= '--jetpack--contact-form--text-color: ' . esc_attr( $this->get_attribute( 'inputcolor' ) ) . ';';
			$this->field_styles  .= 'color: ' . esc_attr( $this->get_attribute( 'inputcolor' ) ) . ';';
			$this->option_styles .= 'color: ' . esc_attr( $this->get_attribute( 'inputcolor' ) ) . ';';
		}
		if ( ! empty( $this->get_attribute( 'fieldbackgroundcolor' ) ) ) {
			$this->block_styles .= '--jetpack--contact-form--input-background: ' . esc_attr( $this->get_attribute( 'fieldbackgroundcolor' ) ) . ';';
			$this->field_styles .= 'background-color: ' . esc_attr( $this->get_attribute( 'fieldbackgroundcolor' ) ) . ';';
		}
		if ( ! empty( $this->get_attribute( 'fieldfontsize' ) ) ) {
			$this->block_styles  .= '--jetpack--contact-form--font-size: ' . esc_attr( $this->get_attribute( 'fieldfontsize' ) ) . ';';
			$this->field_styles  .= 'font-size: ' . esc_attr( $this->get_attribute( 'fieldfontsize' ) ) . ';';
			$this->option_styles .= 'font-size: ' . esc_attr( $this->get_attribute( 'fieldfontsize' ) ) . ';';
		}

		if ( ! empty( $this->get_attribute( 'labelcolor' ) ) ) {
			$this->label_styles .= 'color: ' . esc_attr( $this->get_attribute( 'labelcolor' ) ) . ';';
		}
		if ( ! empty( $this->get_attribute( 'labelfontsize' ) ) ) {
			$this->label_styles .= 'font-size: ' . esc_attr( $this->get_attribute( 'labelfontsize' ) ) . ';';
		}
		if ( is_numeric( $this->get_attribute( 'labellineheight' ) ) ) {
			$this->label_styles .= 'line-height: ' . (int) $this->get_attribute( 'labellineheight' ) . ';';
		}

		if ( ! empty( $field_width ) ) {
			$class .= ' grunion-field-width-' . $field_width;
		}

		/**
		 * Filters the "class" attribute of the contact form input
		 *
		 * @module contact-form
		 *
		 * @since 6.6.0
		 *
		 * @param string $class Additional CSS classes for input class attribute.
		 */
		$field_class = apply_filters( 'jetpack_contact_form_input_class', $class );

		if ( isset( $_POST[ $field_id ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- no site changes.
			if ( is_array( $_POST[ $field_id ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- no site changes.
				$this->value = array_map( 'sanitize_textarea_field', wp_unslash( $_POST[ $field_id ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- no site changes.
			} else {
				$this->value = sanitize_textarea_field( wp_unslash( $_POST[ $field_id ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- no site changes.
			}
		} elseif ( isset( $_GET[ $field_id ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no site changes.
			$this->value = sanitize_textarea_field( wp_unslash( $_GET[ $field_id ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no site changes.
		} elseif (
			is_user_logged_in() &&
			( ( defined( 'IS_WPCOM' ) && IS_WPCOM ) ||
			/**
			 * Allow third-party tools to prefill the contact form with the user's details when they're logged in.
			 *
			 * @module contact-form
			 *
			 * @since 3.2.0
			 *
			 * @param bool false Should the Contact Form be prefilled with your details when you're logged in. Default to false.
			 */
			true === apply_filters( 'jetpack_auto_fill_logged_in_user', false )
			)
		) {
			// Special defaults for logged-in users
			switch ( $field_type ) {
				case 'email':
					$this->value = $current_user->data->user_email;
					break;
				case 'name':
					$this->value = $user_identity;
					break;
				case 'url':
					$this->value = $current_user->data->user_url;
					break;
				default:
					$this->value = $this->get_attribute( 'default' );
			}
		} else {
			$this->value = $this->get_attribute( 'default' );
		}

		$field_value = Grunion_Contact_Form_Plugin::strip_tags( $this->value );
		$field_label = Grunion_Contact_Form_Plugin::strip_tags( $field_label );

		$rendered_field = $this->render_field( $field_type, $field_id, $field_label, $field_value, $field_class, $field_placeholder, $field_required, $field_required_text );

		/**
		 * Filter the HTML of the Contact Form.
		 *
		 * @module contact-form
		 *
		 * @since 2.6.0
		 *
		 * @param string $rendered_field Contact Form HTML output.
		 * @param string $field_label Field label.
		 * @param int|null $id Post ID.
		 */
		return apply_filters( 'grunion_contact_form_field_html', $rendered_field, $field_label, ( in_the_loop() ? get_the_ID() : null ) );
	}

	/**
	 * Return the HTML for the label.
	 *
	 * @param string $type - the field type.
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 * @param array  $extra_attrs Array of key/value pairs to append as attributes to the element.
	 *
	 * @return string HTML
	 */
	public function render_label( $type, $id, $label, $required, $required_field_text, $extra_attrs = array() ) {
		$form_style = $this->get_form_style();

		if ( ! empty( $form_style ) && $form_style !== 'default' ) {
			return '';
		}

		if ( ! empty( $this->label_styles ) ) {
			$extra_attrs['style'] = $this->label_styles;
		}

		$extra_attrs_string = '';
		if ( is_array( $extra_attrs ) && ! empty( $extra_attrs ) ) {
			foreach ( $extra_attrs as $attr => $val ) {
				$extra_attrs_string .= sprintf( '%s="%s" ', esc_attr( $attr ), esc_attr( $val ) );
			}
		}

		$type_class = $type ? ' ' . $type : '';
		return "<label
				for='" . esc_attr( $id ) . "'
				class='grunion-field-label{$type_class}" . ( $this->is_error() ? ' form-error' : '' ) . "'"
				. $extra_attrs_string . '
				>'
				. esc_html( $label )
				. ( $required ? '<span>' . $required_field_text . '</span>' : '' )
			. "</label>\n";
	}

	/**
	 * Return the HTML for the input field.
	 *
	 * @param string $type - the field type.
	 * @param int    $id - the ID.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param string $placeholder - the field placeholder content.
	 * @param bool   $required - if the field is marked as required.
	 * @param array  $extra_attrs Array of key/value pairs to append as attributes to the element.
	 *
	 * @return string HTML
	 */
	public function render_input_field( $type, $id, $value, $class, $placeholder, $required, $extra_attrs = array() ) {
		$extra_attrs_string = '';

		if ( ! empty( $this->field_styles ) ) {
			$extra_attrs['style'] = $this->field_styles;
		}

		if ( is_array( $extra_attrs ) && ! empty( $extra_attrs ) ) {
			foreach ( $extra_attrs as $attr => $val ) {
				$extra_attrs_string .= sprintf( '%s="%s" ', esc_attr( $attr ), esc_attr( $val ) );
			}
		}
		return "<input
					type='" . esc_attr( $type ) . "'
					name='" . esc_attr( $id ) . "'
					id='" . esc_attr( $id ) . "'
					value='" . esc_attr( $value ) . "'
					" . $class . $placeholder . '
					' . ( $required ? "required aria-required='true'" : '' ) .
					$extra_attrs_string .
					" />\n";
	}

	/**
	 * Return the HTML for the email field.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 * @param string $placeholder - the field placeholder content.
	 *
	 * @return string HTML
	 */
	public function render_email_field( $id, $label, $value, $class, $required, $required_field_text, $placeholder ) {
		$field  = $this->render_label( 'email', $id, $label, $required, $required_field_text );
		$field .= $this->render_input_field( 'email', $id, $value, $class, $placeholder, $required );
		return $field;
	}

	/**
	 * Return the HTML for the telephone field.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 * @param string $placeholder - the field placeholder content.
	 *
	 * @return string HTML
	 */
	public function render_telephone_field( $id, $label, $value, $class, $required, $required_field_text, $placeholder ) {
		$field  = $this->render_label( 'telephone', $id, $label, $required, $required_field_text );
		$field .= $this->render_input_field( 'tel', $id, $value, $class, $placeholder, $required );
		return $field;
	}

	/**
	 * Return the HTML for the URL field.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 * @param string $placeholder - the field placeholder content.
	 *
	 * @return string HTML
	 */
	public function render_url_field( $id, $label, $value, $class, $required, $required_field_text, $placeholder ) {
		$custom_validation_message = __( 'Please enter a valid URL - https://www.example.com', 'jetpack' );
		$validation_attrs          = array(
			'title'              => $custom_validation_message,
			'oninvalid'          => 'setCustomValidity("' . $custom_validation_message . '")',
			'oninput'            => 'setCustomValidity("")',
			'pattern'            => '(([:\/a-zA-Z0-9_\-]+)?(\.[a-zA-Z0-9_\-\/]+)+)',
			'data-type-override' => 'url',
		);

		$field  = $this->render_label( 'url', $id, $label, $required, $required_field_text );
		$field .= $this->render_input_field( 'text', $id, $value, $class, $placeholder, $required, $validation_attrs );
		return $field;
	}

	/**
	 * Return the HTML for the text area field.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 * @param string $placeholder - the field placeholder content.
	 *
	 * @return string HTML
	 */
	public function render_textarea_field( $id, $label, $value, $class, $required, $required_field_text, $placeholder ) {
		$field  = $this->render_label( 'textarea', 'contact-form-comment-' . $id, $label, $required, $required_field_text );
		$field .= "<textarea
		                style='" . $this->field_styles . "'
		                name='" . esc_attr( $id ) . "'
		                id='contact-form-comment-" . esc_attr( $id ) . "'
		                rows='20' "
						. $class
						. $placeholder
						. ' ' . ( $required ? "required aria-required='true'" : '' ) .
						'>' . esc_textarea( $value )
				. "</textarea>\n";
		return $field;
	}

	/**
	 * Return the HTML for the radio field.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 *
	 * @return string HTML
	 */
	public function render_radio_field( $id, $label, $value, $class, $required, $required_field_text ) {
		$field  = $this->render_label( '', $id, $label, $required, $required_field_text );
		$field .= '<div class="grunion-radio-options">';

		$field_style = 'style="' . $this->option_styles . '"';

		foreach ( (array) $this->get_attribute( 'options' ) as $option_index => $option ) {
			$option = Grunion_Contact_Form_Plugin::strip_tags( $option );
			if ( is_string( $option ) && $option !== '' ) {
				$field .= "\t\t<label {$field_style} class='grunion-radio-label radio" . ( $this->is_error() ? ' form-error' : '' ) . "'>";
				$field .= "<input
									type='radio'
									name='" . esc_attr( $id ) . "'
									value='" . esc_attr( $this->get_option_value( $this->get_attribute( 'values' ), $option_index, $option ) ) . "' "
									. $class
									. checked( $option, $value, false ) . ' '
									. ( $required ? "required aria-required='true'" : '' )
									. '/> ';
				$field .= esc_html( $option ) . "</label>\n";
			}
		}
		$field .= '</div>';
		return $field;
	}

	/**
	 * Return the HTML for the checkbox field.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 *
	 * @return string HTML
	 */
	public function render_checkbox_field( $id, $label, $value, $class, $required, $required_field_text ) {
		$field  = "<label class='grunion-field-label checkbox" . ( $this->is_error() ? ' form-error' : '' ) . "' style='" . $this->label_styles . "'>";
		$field .= "\t\t<input type='checkbox' name='" . esc_attr( $id ) . "' value='" . esc_attr__( 'Yes', 'jetpack' ) . "' " . $class . checked( (bool) $value, true, false ) . ' ' . ( $required ? "required aria-required='true'" : '' ) . "/> \n";
		$field .= "\t\t" . esc_html( $label ) . ( $required ? '<span>' . $required_field_text . '</span>' : '' );
		$field .= "</label>\n";
		$field .= "<div class='clear-form'></div>\n";
		return $field;
	}

	/**
	 * Return the HTML for the consent field.
	 *
	 * @param string $id field id.
	 * @param string $class html classes (can be set by the admin).
	 */
	private function render_consent_field( $id, $class ) {
		$consent_type    = 'explicit' === $this->get_attribute( 'consenttype' ) ? 'explicit' : 'implicit';
		$consent_message = 'explicit' === $consent_type ? $this->get_attribute( 'explicitconsentmessage' ) : $this->get_attribute( 'implicitconsentmessage' );

		$field = "<label class='grunion-field-label consent consent-" . $consent_type . "' style='" . $this->label_styles . "'>";

		if ( 'implicit' === $consent_type ) {
			$field .= "\t\t<input aria-hidden='true' type='checkbox' checked name='" . esc_attr( $id ) . "' value='" . esc_attr__( 'Yes', 'jetpack' ) . "' style='display:none;' /> \n";
		} else {
			$field .= "\t\t<input type='checkbox' name='" . esc_attr( $id ) . "' value='" . esc_attr__( 'Yes', 'jetpack' ) . "' " . $class . "/> \n";
		}
		$field .= "\t\t" . esc_html( $consent_message );
		$field .= "</label>\n";
		$field .= "<div class='clear-form'></div>\n";
		return $field;
	}

	/**
	 * Return the HTML for the multiple checkbox field.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 *
	 * @return string HTML
	 */
	public function render_checkbox_multiple_field( $id, $label, $value, $class, $required, $required_field_text ) {
		$field  = $this->render_label( '', $id, $label, $required, $required_field_text );
		$field .= '<div class="grunion-checkbox-multiple-options">';

		$field_style = 'style="' . $this->option_styles . '"';

		foreach ( (array) $this->get_attribute( 'options' ) as $option_index => $option ) {
			$option = Grunion_Contact_Form_Plugin::strip_tags( $option );
			if ( is_string( $option ) && $option !== '' ) {
				$field .= "\t\t<label {$field_style} class='grunion-checkbox-multiple-label checkbox-multiple " . ( $this->is_error() ? ' form-error' : '' ) . "'>";
				$field .= "<input type='checkbox' name='" . esc_attr( $id ) . "[]' value='" . esc_attr( $this->get_option_value( $this->get_attribute( 'values' ), $option_index, $option ) ) . "' " . $class . checked( in_array( $option, (array) $value, true ), true, false ) . ' /> ';
				$field .= esc_html( $option ) . "</label>\n";
			}
		}
		$field .= '</div>';

		return $field;
	}

	/**
	 * Return the HTML for the select field.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 *
	 * @return string HTML
	 */
	public function render_select_field( $id, $label, $value, $class, $required, $required_field_text ) {
		$field  = $this->render_label( 'select', $id, $label, $required, $required_field_text );
		$field .= "\t<select name='" . esc_attr( $id ) . "' id='" . esc_attr( $id ) . "' " . $class . ( $required ? "required aria-required='true'" : '' ) . ">\n";

		if ( $this->get_attribute( 'togglelabel' ) ) {
			$field .= "\t\t<option>" . $this->get_attribute( 'togglelabel' ) . "</option>\n";
		}

		foreach ( (array) $this->get_attribute( 'options' ) as $option_index => $option ) {
			$option = Grunion_Contact_Form_Plugin::strip_tags( $option );
			if ( is_string( $option ) && $option !== '' ) {
				$field .= "\t\t<option"
								. selected( $option, $value, false )
								. " value='" . esc_attr( $this->get_option_value( $this->get_attribute( 'values' ), $option_index, $option ) )
								. "'>" . esc_html( $option )
								. "</option>\n";
			}
		}
		$field .= "\t</select>\n";

		wp_enqueue_style(
			'jquery-ui-selectmenu',
			plugins_url( 'css/jquery-ui-selectmenu.css', __FILE__ ),
			array(),
			'1.13.2'
		);

		wp_enqueue_script( 'jquery-ui-selectmenu' );

		wp_enqueue_script(
			'contact-form-dropdown',
			plugins_url( 'js/dropdown.js', __FILE__ ),
			array( 'jquery', 'jquery-ui-selectmenu' ),
			JETPACK__VERSION,
			true
		);

		return $field;
	}

	/**
	 * Return the HTML for the email field.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 * @param string $placeholder - the field placeholder content.
	 *
	 * @return string HTML
	 */
	public function render_date_field( $id, $label, $value, $class, $required, $required_field_text, $placeholder ) {

		$field  = $this->render_label( 'date', $id, $label, $required, $required_field_text );
		$field .= $this->render_input_field( 'text', $id, $value, $class, $placeholder, $required );

		/* For AMP requests, use amp-date-picker element: https://amp.dev/documentation/components/amp-date-picker */
		if ( class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() ) {
			return sprintf(
				'<%1$s mode="overlay" layout="container" type="single" input-selector="[name=%2$s]">%3$s</%1$s>',
				'amp-date-picker',
				esc_attr( $id ),
				$field
			);
		}

		wp_enqueue_script(
			'grunion-frontend',
			Assets::get_file_url_for_environment(
				'_inc/build/contact-form/js/grunion-frontend.min.js',
				'modules/contact-form/js/grunion-frontend.js'
			),
			array( 'jquery', 'jquery-ui-datepicker' ),
			JETPACK__VERSION,
			false
		);
		wp_enqueue_style( 'jp-jquery-ui-datepicker', plugins_url( 'css/jquery-ui-datepicker.css', __FILE__ ), array( 'dashicons' ), '1.0' );

		// Using Core's built-in datepicker localization routine
		wp_localize_jquery_ui_datepicker();
		return $field;
	}

	/**
	 * Return the HTML for the default field.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 * @param string $placeholder - the field placeholder content.
	 * @param string $type - the type.
	 *
	 * @return string HTML
	 */
	public function render_default_field( $id, $label, $value, $class, $required, $required_field_text, $placeholder, $type ) {
		$field  = $this->render_label( $type, $id, $label, $required, $required_field_text );
		$field .= $this->render_input_field( 'text', $id, $value, $class, $placeholder, $required );
		return $field;
	}

	/**
	 * Return the HTML for the outlined label.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 *
	 * @return string HTML
	 */
	public function render_outline_label( $id, $label, $required, $required_field_text ) {
		return '
			<div class="notched-label">
				<div class="notched-label__leading"></div>
				<div class="notched-label__notch">
					<label
						for="' . esc_attr( $id ) . '"
						class="notched-label__label ' . ( $this->is_error() ? ' form-error' : '' ) . '"
						style="' . $this->label_styles . '"
					>'
						. esc_html( $label )
						. ( $required ? '<span>' . $required_field_text . '</span>' : '' ) .
					'</label>
				</div>
				<div class="notched-label__trailing"></div>
			</div>';
	}

	/**
	 * Return the HTML for the animated label.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 *
	 * @return string HTML
	 */
	public function render_animated_label( $id, $label, $required, $required_field_text ) {
		return '
			<label
				for="' . esc_attr( $id ) . '"
				class="animated-label__label ' . ( $this->is_error() ? ' form-error' : '' ) . '"
				style="' . $this->label_styles . '"
			>'
				. esc_html( $label )
				. ( $required ? '<span>' . $required_field_text . '</span>' : '' ) .
			'</label>';
	}

	/**
	 * Return the HTML for the below label.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 *
	 * @return string HTML
	 */
	public function render_below_label( $id, $label, $required, $required_field_text ) {
		return '
			<label
				for="' . esc_attr( $id ) . '"
				class="below-label__label ' . ( $this->is_error() ? ' form-error' : '' ) . '"
			>'
				. esc_html( $label )
				. ( $required ? '<span>' . $required_field_text . '</span>' : '' ) .
				'</label>';
	}

	/**
	 * Return the HTML for the email field.
	 *
	 * @param string $type - the type.
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param string $placeholder - the field placeholder content.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text for a field marked as required.
	 *
	 * @return string HTML
	 */
	public function render_field( $type, $id, $label, $value, $class, $placeholder, $required, $required_field_text ) {
		$class .= ' grunion-field';

		if ( $type === 'select' ) {
			$class .= ' contact-form-dropdown';
		}

		$form_style = $this->get_form_style();
		if ( ! empty( $form_style ) && $form_style !== 'default' ) {
			if ( empty( $placeholder ) ) {
				$placeholder .= ' ';
			} else {
				$class .= ' has-placeholder';
			}
		}

		$field_placeholder = ( ! empty( $placeholder ) ) ? "placeholder='" . esc_attr( $placeholder ) . "'" : '';
		$field_class       = "class='" . trim( esc_attr( $type ) . ' ' . esc_attr( $class ) ) . "' ";
		$wrap_classes      = empty( $class ) ? '' : implode( '-wrap ', array_filter( explode( ' ', $class ) ) ) . '-wrap'; // this adds

		if ( $type === 'select' ) {
			$wrap_classes .= ' ui-front';
		}

		if ( empty( $label ) ) {
			$wrap_classes .= ' no-label';
		}

		$shell_field_class = "class='grunion-field-" . trim( esc_attr( $type ) . '-wrap ' . esc_attr( $wrap_classes ) ) . "' ";

		/**
		 * Filter the Contact Form required field text
		 *
		 * @module contact-form
		 *
		 * @since 3.8.0
		 *
		 * @param string $var Required field text. Default is "(required)".
		 */
		$required_field_text = esc_html( apply_filters( 'jetpack_required_field_text', $required_field_text ) );

		$block_style = 'style="' . $this->block_styles . '"';

		$field = "\n<div {$block_style} {$shell_field_class} >\n"; // new in Jetpack 6.8.0

		// If they are logged in, and this is their site, don't pre-populate fields
		if ( current_user_can( 'manage_options' ) ) {
			$value = '';
		}

		switch ( $type ) {
			case 'email':
				$field .= $this->render_email_field( $id, $label, $value, $field_class, $required, $required_field_text, $field_placeholder );
				break;
			case 'telephone':
				$field .= $this->render_telephone_field( $id, $label, $value, $field_class, $required, $required_field_text, $field_placeholder );
				break;
			case 'url':
				$field .= $this->render_url_field( $id, $label, $value, $field_class, $required, $required_field_text, $field_placeholder );
				break;
			case 'textarea':
				$field .= $this->render_textarea_field( $id, $label, $value, $field_class, $required, $required_field_text, $field_placeholder );
				break;
			case 'radio':
				$field .= $this->render_radio_field( $id, $label, $value, $field_class, $required, $required_field_text, $field_placeholder );
				break;
			case 'checkbox':
				$field .= $this->render_checkbox_field( $id, $label, $value, $field_class, $required, $required_field_text );
				break;
			case 'checkbox-multiple':
				$field .= $this->render_checkbox_multiple_field( $id, $label, $value, $field_class, $required, $required_field_text );
				break;
			case 'select':
				$field .= $this->render_select_field( $id, $label, $value, $field_class, $required, $required_field_text );
				break;
			case 'date':
				$field .= $this->render_date_field( $id, $label, $value, $field_class, $required, $required_field_text, $field_placeholder );
				break;
			case 'consent':
				$field .= $this->render_consent_field( $id, $field_class );
				break;
			default: // text field
				$field .= $this->render_default_field( $id, $label, $value, $field_class, $required, $required_field_text, $field_placeholder, $type );
				break;
		}

		if ( ! empty( $form_style ) && $form_style !== 'default' && ! in_array( $type, array( 'checkbox', 'consent' ), true ) ) {
			switch ( $form_style ) {
				case 'outlined':
					$field .= $this->render_outline_label( $id, $label, $required, $required_field_text );
					break;
				case 'animated':
					$field .= $this->render_animated_label( $id, $label, $required, $required_field_text );
					break;
				case 'below':
					$field .= $this->render_below_label( $id, $label, $required, $required_field_text );
					break;
			}
		}

		$field .= "\t</div>\n";
		return $field;
	}

	/**
	 * Overrides input type (maybe).
	 *
	 * @module contact-form
	 *
	 * Custom input types, like URL, will rely on browser's implementation to validate
	 * the value. If the input carries a data-type-override, we allow to override
	 * the type at render/submit so it can be validated with custom patterns.
	 * This method will try to match the input's type to a custom data-type-override
	 * attribute and return it. Defaults to input's type.
	 *
	 * @return string The input's type attribute or the overriden type.
	 */
	private function maybe_override_type() {
		// Define overridables-to-custom-type, extend as needed.
		$overridable_types = array( 'text' => array( 'url' ) );
		$type              = $this->get_attribute( 'type' );

		if ( ! array_key_exists( $type, $overridable_types ) ) {
			return $type;
		}

		$override_type = $this->get_attribute( 'data-type-override' );

		if ( in_array( $override_type, $overridable_types[ $type ], true ) ) {
			return $override_type;
		}

		return $type;
	}

	/**
	 * Gets the form style based on its CSS class.
	 *
	 * @return string The form style type.
	 */
	private function get_form_style() {
		$class_name = $this->form->get_attribute( 'className' );
		preg_match( '/is-style-([^\s]+)/i', $class_name, $matches );
		return count( $matches ) >= 2 ? $matches[1] : null;
	}
}

add_action( 'init', array( 'Grunion_Contact_Form_Plugin', 'init' ), 9 );

add_action( 'grunion_scheduled_delete', 'grunion_delete_old_spam' );

/**
 * Deletes old spam feedbacks to keep the posts table size under control
 */
function grunion_delete_old_spam() {
	global $wpdb;

	$grunion_delete_limit = 100;

	$now_gmt  = current_time( 'mysql', 1 );
	$sql      = $wpdb->prepare(
		"
		SELECT `ID`
		FROM $wpdb->posts
		WHERE DATE_SUB( %s, INTERVAL 15 DAY ) > `post_date_gmt`
			AND `post_type` = 'feedback'
			AND `post_status` = 'spam'
		LIMIT %d
	",
		$now_gmt,
		$grunion_delete_limit
	);
	$post_ids = $wpdb->get_col( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

	foreach ( (array) $post_ids as $post_id ) {
		// force a full delete, skip the trash
		wp_delete_post( $post_id, true );
	}

	if (
		/**
		 * Filter if the module run OPTIMIZE TABLE on the core WP tables.
		 *
		 * @module contact-form
		 *
		 * @since 1.3.1
		 * @since 6.4.0 Set to false by default.
		 *
		 * @param bool $filter Should Jetpack optimize the table, defaults to false.
		 */
		apply_filters( 'grunion_optimize_table', false )
	) {
		$wpdb->query( "OPTIMIZE TABLE $wpdb->posts" );
	}

	// if we hit the max then schedule another run
	if ( count( $post_ids ) >= $grunion_delete_limit ) {
		wp_schedule_single_event( time() + 700, 'grunion_scheduled_delete' );
	}
}

/**
 * Send an event to Tracks on form submission.
 *
 * @param int $post_id - the post_id for the CPT that is created.
 *
 * @return null|void
 */
function jetpack_tracks_record_grunion_pre_message_sent( $post_id ) {
	$post = get_post( $post_id );
	if ( $post ) {
		$extra = gmdate( 'Y-W', strtotime( $post->post_date_gmt ) );
	} else {
		$extra = 'no-post';
	}

	/** This action is documented in modules/widgets/social-media-icons.php */
	do_action( 'jetpack_bump_stats_extras', 'jetpack_forms_message_sent', $extra );
}
add_action( 'grunion_pre_message_sent', 'jetpack_tracks_record_grunion_pre_message_sent', 12 );
