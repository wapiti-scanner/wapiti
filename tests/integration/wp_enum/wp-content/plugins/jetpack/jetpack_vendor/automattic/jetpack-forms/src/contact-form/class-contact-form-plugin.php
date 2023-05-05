<?php
/**
 * Contact_Form_Plugin class.
 *
 * @package automattic/jetpack-forms
 */

namespace Automattic\Jetpack\Forms\ContactForm;

use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Blocks;
use Automattic\Jetpack\Forms\Jetpack_Forms;
use Automattic\Jetpack\Forms\Service\Post_To_Url;

/**
 * Sets up various actions, filters, post types, post statuses, shortcodes.
 */
class Contact_Form_Plugin {

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
			$instance = new Contact_Form_Plugin();

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

		$feedback_ids = $wpdb->get_col( "SELECT p.ID FROM {$wpdb->posts} as p INNER JOIN {$wpdb->postmeta} as m on m.post_id = p.ID WHERE p.post_type = 'feedback' AND m.meta_key = '_feedback_akismet_values' AND DATE_SUB(NOW(), INTERVAL 15 DAY) > p.post_date_gmt LIMIT 10000" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching

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

		add_action( 'loop_start', array( '\Automattic\Jetpack\Forms\ContactForm\Contact_Form', 'style_on' ) );
		add_action( 'pre_amp_render_post', array( '\Automattic\Jetpack\Forms\ContactForm\Contact_Form', 'style_on' ) );

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
					'name'               => __( 'Form Responses', 'jetpack-forms' ),
					'singular_name'      => __( 'Form Responses', 'jetpack-forms' ),
					'search_items'       => __( 'Search Responses', 'jetpack-forms' ),
					'not_found'          => __( 'No responses found', 'jetpack-forms' ),
					'not_found_in_trash' => __( 'No responses found', 'jetpack-forms' ),
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
				'rest_controller_class' => '\Automattic\Jetpack\Forms\ContactForm\Contact_Form_Endpoint',
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
				'label_count'            => _n_noop( 'Spam <span class="count">(%s)</span>', 'Spam <span class="count">(%s)</span>', 'jetpack-forms' ),
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
		wp_register_style( 'grunion.css', Jetpack_Forms::plugin_url() . 'contact-form/css/grunion.css', array(), \JETPACK__VERSION );
		wp_style_add_data( 'grunion.css', 'rtl', 'replace' );

		add_action( 'enqueue_block_editor_assets', array( $this, 'load_editor_scripts' ) );
		add_filter( 'js_do_concat', array( __CLASS__, 'disable_forms_view_script_concat' ), 10, 3 );

		self::register_contact_form_blocks();
	}

	/**
	 * Loads the Form blocks scripts.
	 */
	public static function load_editor_scripts() {
		Assets::register_script(
			'jp-forms-blocks',
			'../../dist/blocks/editor.js',
			__FILE__,
			array(
				'in_footer'  => true,
				'textdomain' => 'jetpack-forms',
				'enqueue'    => true,
			)
		);
	}

	/**
	 * Enqueue scripts responsible for handling contact form view scripts.
	 */
	private static function load_view_scripts() {
		if ( is_admin() ) {
			// A block's view assets will not be required in wp-admin.
			return;
		}

		Assets::register_script(
			'jp-forms-view',
			'../../dist/blocks/view.js',
			__FILE__,
			array(
				'in_footer'  => true,
				'textdomain' => 'jetpack-forms',
				'enqueue'    => true,
			)
		);
	}

	/**
	 * Prevent 'jp-forms-view' script from being concatenated.
	 *
	 * @param array  $do_concat - the concatenation flag.
	 * @param string $handle - script name.
	 */
	public static function disable_forms_view_script_concat( $do_concat, $handle ) {
		if ( 'jp-forms-view' === $handle ) {
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
				esc_html__( 'Submit a form.', 'jetpack-forms' )
			);
		}

		self::load_view_scripts();

		return Contact_Form::parse( $atts, do_blocks( $content ) );
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
		return Contact_Form::parse_contact_field( $atts, $content );
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
		return Contact_Form::parse_contact_field( $atts, $content );
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
		return Contact_Form::parse_contact_field( $atts, $content );
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
		return Contact_Form::parse_contact_field( $atts, $content );
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
		return Contact_Form::parse_contact_field( $atts, $content );
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
		return Contact_Form::parse_contact_field( $atts, $content );
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
		return Contact_Form::parse_contact_field( $atts, $content );
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
		return Contact_Form::parse_contact_field( $atts, $content );
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
		return Contact_Form::parse_contact_field( $atts, $content );
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
		return Contact_Form::parse_contact_field( $atts, $content );
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
		return Contact_Form::parse_contact_field( $atts, $content );
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
		return Contact_Form::parse_contact_field( $atts, $content );
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
			$atts['implicitConsentMessage'] = __( "By submitting your information, you're giving us permission to email you. You may unsubscribe at any time.", 'jetpack-forms' );
		}

		if ( ! isset( $atts['explicitConsentMessage'] ) ) {
			$atts['explicitConsentMessage'] = __( 'Can we send you an email from time to time?', 'jetpack-forms' );
		}

		return Contact_Form::parse_contact_field( $atts, $content );
	}

	/**
	 * Add the 'Form Responses' menu item as a submenu of Feedback.
	 */
	public function admin_menu() {
		$slug = 'feedback';

		add_menu_page(
			__( 'Feedback', 'jetpack-forms' ),
			__( 'Feedback', 'jetpack-forms' ),
			'edit_pages',
			$slug,
			null,
			'dashicons-feedback',
			45
		);

		add_submenu_page(
			$slug,
			__( 'Form Responses', 'jetpack-forms' ),
			__( 'Form Responses', 'jetpack-forms' ),
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
			$template = Util::grunion_contact_form_set_block_template_attribute( $template );

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

		$form = isset( Contact_Form::$forms[ $hash ] ) ? Contact_Form::$forms[ $hash ] : null;

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
				$form = Contact_Form::$last;
			}
		}

		if ( ! $form ) {
			return false;
		}

		if ( is_wp_error( $form->errors ) && $form->errors->get_error_codes() ) {
			return $form->errors;
		}

		if ( ! empty( $form->attributes['salesforceData'] ) || ! empty( $form->attributes['postToUrl'] ) ) {
			Post_To_Url::init();
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
			esc_html_e( 'An error occurred. Please try again later.', 'jetpack-forms' );
			echo '</li></ul></div>';
		} elseif ( is_wp_error( $submission_result ) ) {
			header( 'HTTP/1.1 400 Bad Request', 403, true );
			echo '<div class="form-error"><ul class="form-errors"><li class="form-error-message">';
			echo esc_html( $submission_result->get_error_message() );
			echo '</li></ul></div>';
		} else {
			echo '<h4>' . esc_html__( 'Your message has been sent', 'jetpack-forms' ) . '</h4>' . wp_kses(
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
		add_shortcode( 'contact-form', array( '\Automattic\Jetpack\Forms\ContactForm\Contact_Form', 'parse' ) );
		add_shortcode( 'contact-field', array( '\Automattic\Jetpack\Forms\ContactForm\Contact_Form', 'parse_contact_field' ) );

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
		$wrapped_labels = array_map( array( '\Automattic\Jetpack\Forms\ContactForm\Contact_Form_Plugin', 'tokenize_label' ), array_keys( $field_values ) );
		// Sanitize all values
		$sanitized_values = array_map( array( '\Automattic\Jetpack\Forms\ContactForm\Contact_Form_Plugin', 'sanitize_value' ), array_values( $field_values ) );

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
		Contact_Form::style( true );

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
			} elseif ( substr( $key, 0, 5 ) === 'HTTP_' ) {
				// Any other HTTP header indicators.
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
			$response = \Akismet::http_post( $query_string, 'comment-check' );
		} else {
			$response = akismet_http_post( $query_string, $akismet_api_host, '/1.1/comment-check', $akismet_api_port );
		}

		$result = false;

		if ( isset( $response[0]['x-akismet-pro-tip'] ) && 'discard' === trim( $response[0]['x-akismet-pro-tip'] ) && get_option( 'akismet_strictness' ) === '1' ) {
			$result = new \WP_Error( 'feedback-discarded', __( 'Feedback discarded.', 'jetpack-forms' ) );
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
			$response = \Akismet::http_post( $query_string, "submit-{$as}" );
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
			<option value="all"><?php esc_html_e( 'All sources', 'jetpack-forms' ); ?></option>
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
			if ( ! empty( $all_fields['entry_permalink'] ) ) {
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
			// '_feedback_subject'      => __( 'Contact Form', 'jetpack-forms' ),
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
			'exporter_friendly_name' => __( 'Feedback', 'jetpack-forms' ),
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
			'eraser_friendly_name' => __( 'Feedback', 'jetpack-forms' ),
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
				'group_label' => __( 'Feedback', 'jetpack-forms' ),
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
						__( 'Feedback ID %d could not be removed at this time.', 'jetpack-forms' ),
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
					__( 'Feedback ID %d could not be removed at this time.', 'jetpack-forms' ),
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
			'-9_title'         => __( 'Title', 'jetpack-forms' ),
			'-6_source'        => __( 'Source', 'jetpack-forms' ),
			'-3_response_date' => __( 'Response Date', 'jetpack-forms' ),
			'90_consent'       => _x( 'Consent', 'noun', 'jetpack-forms' ),
			'93_ip_address'    => __( 'IP Address', 'jetpack-forms' ),
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
			'post_status'      => array( 'publish', 'draft' ),
			'order'            => 'ASC',
			'fields'           => 'ids',
			'suppress_filters' => false,
			'date_query'       => array(),
		);

		// Check if we want to download all the feedbacks or just a certain contact form
		if ( ! empty( $_POST['post'] ) && $_POST['post'] !== 'all' ) {
			$args['post_parent'] = (int) $_POST['post'];
		}

		if ( ! empty( $_POST['status'] ) && in_array( $_POST['status'], array( 'spam', 'trash' ), true ) ) {
			$args['post_status'] = sanitize_text_field( wp_unslash( $_POST['status'] ) );
		}

		if ( ! empty( $_POST['search'] ) ) {
			$args['s'] = sanitize_text_field( wp_unslash( $_POST['search'] ) );
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
				Admin::init()->get_export_filename( get_the_title( (int) $post_data['post'] ) ),
				gmdate( 'Y-m-d H:i' )
			);
		} else {
			$filename = sprintf(
				'%s - %s.csv',
				Admin::init()->get_export_filename(),
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

		fclose( $output ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose

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
	 * Returns an array of parent post IDs for the user.
	 * The parent posts are those posts where forms have been published.
	 *
	 * @param array $query_args A WP_Query compatible array of query args.
	 *
	 * @return array The array of post IDs
	 */
	public static function get_all_parent_post_ids( $query_args = array() ) {
		$default_query_args = array(
			'fields'           => 'id=>parent',
			'posts_per_page'   => 100000, // phpcs:ignore WordPress.WP.PostsPerPage.posts_per_page_posts_per_page
			'post_type'        => 'feedback',
			'post_status'      => 'publish',
			'suppress_filters' => false,
		);
		$args               = array_merge( $default_query_args, $query_args );
		// Get the feedbacks' parents' post IDs
		$feedbacks = get_posts( $args );
		return array_values( array_unique( array_values( $feedbacks ) ) );
	}

	/**
	 * Returns a string of HTML <option> items from an array of posts
	 *
	 * @param int $selected_id Currently selected post ID.
	 * @return string a string of HTML <option> items
	 */
	protected static function get_feedbacks_as_options( $selected_id = 0 ) {
		$options    = '';
		$parent_ids = self::get_all_parent_post_ids();

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
		$fields['all_fields']           = $all_values;

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
			if ( $field === __( 'Contact Form', 'jetpack-forms' ) ) { // the first field will ever be the contact form, so we can continue
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
