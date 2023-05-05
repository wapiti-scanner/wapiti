<?php

namespace WPForms\Frontend;

use WP_Post;

/**
 * Form front-end rendering.
 *
 * @since 1.8.1
 */
class Frontend {

	/**
	 * Render engine setting value.
	 *
	 * @since 1.8.1
	 *
	 * @var string
	 */
	protected $render_engine;

	/**
	 * Render engine class instance.
	 *
	 * @since 1.8.1
	 *
	 * @var Classic|Modern
	 */
	private $render_obj;

	/**
	 * AMP class instance.
	 *
	 * @since 1.8.1
	 *
	 * @var Amp
	 */
	protected $amp_obj;

	/**
	 * Store form data to be referenced later.
	 *
	 * @since 1.8.1
	 *
	 * @var array
	 */
	public $forms;

	/**
	 * Store information for multi-page forms.
	 *
	 * Forms that do not contain pages return false, otherwise returns an array
	 * that contains the number of total pages and page counter used when
	 * displaying pagebreak fields.
	 *
	 * @since 1.8.1
	 *
	 * @var array|bool
	 */
	public $pages = false;

	/**
	 * If the active form confirmation should auto scroll.
	 *
	 * @since 1.8.1
	 *
	 * @var bool
	 */
	public $confirmation_message_scroll = false;

	/**
	 * Whether ChoiceJS library has already been enqueued on the front end.
	 * This lib is used in different fields that can enqueue it separately,
	 * and we use this property to avoid config duplication.
	 *
	 * @since 1.8.1
	 *
	 * @var bool
	 */
	public $is_choicesjs_enqueued = false;

	/**
	 * Form action.
	 *
	 * @since 1.8.1
	 *
	 * @var string
	 */
	private $action;

	/**
	 * Initialize class.
	 *
	 * @since 1.8.1
	 */
	public function init() {

		$this->forms   = [];
		$this->amp_obj = wpforms()->get( 'amp' );

		$this->init_render_engine( wpforms_get_render_engine() );
		$this->hooks();

		// Register shortcode.
		add_shortcode( 'wpforms', [ $this, 'shortcode' ] );
	}

	/**
	 * Register hooks.
	 *
	 * @since 1.8.1
	 */
	private function hooks() {

		// Actions.
		add_action( 'init', [ $this, 'init_style_settings' ] );
		add_action( 'wpforms_frontend_output_success', [ $this, 'confirmation' ], 10, 3 );
		add_action( 'wpforms_frontend_output', [ $this, 'head' ], 5, 5 );
		add_action( 'wpforms_frontend_output', [ $this, 'fields' ], 10, 5 );
		add_action( 'wpforms_display_field_before', [ $this, 'field_container_open' ], 5, 2 );
		add_action( 'wpforms_display_field_before', [ $this, 'field_fieldset_open' ], 10, 2 );
		add_action( 'wpforms_display_field_before', [ $this, 'field_label' ], 15, 2 );
		add_action( 'wpforms_display_field_before', [ $this, 'field_description' ], 20, 2 );
		add_action( 'wpforms_display_field_after', [ $this, 'field_error' ], 3, 2 );
		add_action( 'wpforms_display_field_after', [ $this, 'field_description' ], 5, 2 );
		add_action( 'wpforms_display_field_after', [ $this, 'field_fieldset_close' ], 10, 2 );
		add_action( 'wpforms_display_field_after', [ $this, 'field_container_close' ], 15, 2 );
		add_action( 'wpforms_frontend_output', [ $this, 'foot' ], 25, 5 );
		add_action( 'wp_enqueue_scripts', [ $this, 'assets_header' ] );
		add_action( 'wp_footer', [ $this, 'assets_footer' ], 15 );
		add_action( 'wp_footer', [ $this, 'missing_assets_error_js' ], 20 );
		add_action( 'wp_footer', [ $this, 'footer_end' ], 99 );
	}

	/**
	 * Initialize render engine.
	 *
	 * @since 1.8.1
	 *
	 * @param string $engine Render engine slug, `classic` or `modern`.
	 */
	public function init_render_engine( $engine ) {

		$this->render_engine = $engine;
		$this->render_obj    = wpforms()->get( "frontend_{$this->render_engine}" );

		$this->render_obj->hooks();
	}

	/**
	 * Initialize form styling settings.
	 *
	 * @since 1.8.1
	 */
	public function init_style_settings() {

		// Skip if modern markup settings is already set.
		$modern_markup_is_set = wpforms_setting( 'modern-markup-is-set' );

		if ( $modern_markup_is_set ) {
			return;
		}

		$settings    = (array) get_option( 'wpforms_settings', [] );
		$count_posts = wp_count_posts( 'wpforms' );

		// Set the Modern markup checkbox to the checked state for all new users.
		$settings['modern-markup']        = ( $count_posts->publish + $count_posts->trash ) === 0 ? '1' : '0';
		$settings['modern-markup-is-set'] = true;

		// Hide the Modern markup checkbox for all new users.
		if ( $settings['modern-markup'] ) {
			$settings['modern-markup-hide-setting'] = true;
		}

		update_option( 'wpforms_settings', $settings );
	}

	/**
	 * Primary function to render a form on the frontend.
	 *
	 * @since 1.8.1
	 *
	 * @param int  $id          Form ID.
	 * @param bool $title       Whether to display form title.
	 * @param bool $description Whether to display form description.
	 */
	public function output( $id, $title = false, $description = false ) { // phpcs:ignore Generic.Metrics.CyclomaticComplexity.TooHigh

		if ( empty( $id ) ) {
			return;
		}

		// Grab the form data, if not found then we bail.
		$form = $this->get_form( $id );

		if ( $form === null ) {
			return;
		}

		// We should display only the published form.
		if ( ! empty( $form->post_status ) && $form->post_status !== 'publish' ) {
			return;
		}

		// Basic information.
		/**
		 * Filter frontend form data.
		 *
		 * @since 1.4.3
		 *
		 * @param array $form_data Form data.
		 */
		$form_data    = apply_filters( 'wpforms_frontend_form_data', wpforms_decode( $form->post_content ) );
		$form_id      = absint( $form->ID );
		$this->action = esc_url_raw( remove_query_arg( 'wpforms' ) );
		$errors       = empty( wpforms()->process->errors[ $form_id ] ) ? [] : wpforms()->process->errors[ $form_id ];
		$title        = filter_var( $title, FILTER_VALIDATE_BOOLEAN );
		$description  = filter_var( $description, FILTER_VALIDATE_BOOLEAN );

		// Pass the current form data to the render object.
		$this->render_obj->form_data = $form_data;

		if ( $this->stop_output( $form, $form_data ) ) {
			return;
		}

		// All checks have passed, so calculate multi-page details for the form.
		$this->pages = $this->get_pages( $form_data );

		/**
		 * Allow modifying a form action attribute.
		 *
		 * @since 1.1.2
		 *
		 * @param string $action     Action attribute.
		 * @param array  $form_data  Form data and settings.
		 * @param null   $deprecated A deprecated argument.
		 */
		$this->action = apply_filters( 'wpforms_frontend_form_action', $this->action, $form_data, null );

		$form_classes = [ 'wpforms-validate', 'wpforms-form' ];

		if ( ! empty( $form_data['settings']['ajax_submit'] ) && ! $this->amp_obj->is_amp() ) {
			$form_classes[] = 'wpforms-ajax-form';
		}

		$form_atts = [
			'id'    => sprintf( 'wpforms-form-%d', absint( $form_id ) ),
			'class' => $form_classes,
			'data'  => [
				'formid' => absint( $form_id ),
			],
			'atts'  => [
				'method'  => 'post',
				'enctype' => 'multipart/form-data',
				'action'  => esc_url( $this->action ),
			],
		];

		/**
		 * Allow modifying form attributes.
		 *
		 * @since 1.4.5
		 *
		 * @param array $form_atts Form attributes.
		 * @param array $form_data Form data and settings.
		 */
		$form_atts = apply_filters( 'wpforms_frontend_form_atts', $form_atts, $form_data );

		$this->form_container_open( $form_data, $form );

		/**
		 * Fires before form output.
		 *
		 * @since 1.5.4.2
		 *
		 * @param array   $form_data Form data.
		 * @param WP_Post $form      Form.
		 */
		do_action( 'wpforms_frontend_output_form_before', $form_data, $form );

		echo '<form ' . wpforms_html_attributes( $form_atts['id'], $form_atts['class'], $form_atts['data'], $form_atts['atts'] ) . '>';

		/**
		 * Fires before closing the form.
		 *
		 * @since 1.0.0
		 *
		 * @param array $form_data   Form data.
		 * @param null  $deprecated  Null.
		 * @param bool  $title       Whether to display form title.
		 * @param bool  $description Whether to display form description.
		 * @param array $errors      Form processing errors.
		 */
		do_action( 'wpforms_frontend_output', $form_data, null, $title, $description, $errors );

		echo '</form>';

		/**
		 * Allow adding content after a form.
		 *
		 * @since 1.5.4.2
		 *
		 * @param array   $form_data Form data and settings.
		 * @param WP_Post $form      Form post type.
		 */
		do_action( 'wpforms_frontend_output_form_after', $form_data, $form );

		$this->form_container_close( $form_data, $form );

		// Add form to class property that tracks all forms in a page.
		$this->forms[ $form_id ] = $form_data;

		// Optional debug information if WPFORMS_DEBUG is defined.
		wpforms_debug_data( $_POST ); // phpcs:ignore WordPress.Security.NonceVerification.Missing

		/**
		 * Fires after frontend output.
		 *
		 * @since 1.0.0
		 *
		 * @param array   $form_data Form data and settings.
		 * @param WP_Post $form      Form post type.
		 */
		do_action( 'wpforms_frontend_output_after', $form_data, $form );
	}

	/**
	 * Get form.
	 *
	 * @since 1.8.1
	 *
	 * @param int $id Form id.
	 *
	 * @return array|WP_Post|null
	 * @noinspection NullPointerExceptionInspection
	 */
	private function get_form( $id ) {

		if ( empty( $id ) ) {
			return null;
		}

		// Grab the form data, if not found then we bail.
		$form = wpforms()->get( 'form' )->get( (int) $id );

		if ( empty( $form ) ) {
			return null;
		}

		// We should display only the published form.
		if ( ! empty( $form->post_status ) && $form->post_status !== 'publish' ) {
			return null;
		}

		return $form;
	}

	/**
	 * Check whether we should stop the output.
	 *
	 * @since 1.8.1
	 *
	 * @param WP_Post $form      Form.
	 * @param array   $form_data Form data.
	 *
	 * @return bool
	 */
	private function stop_output( $form, $form_data ) {

		$form_id = absint( $form->ID );

		/**
		 * Is the form is empty?
		 * Check before output the form on the frontend.
		 *
		 * @since 1.7.7
		 *
		 * @param bool  $form_is_empty Is the form is empty?
		 * @param array $form_data     Form data.
		 */
		$form_is_empty = apply_filters( 'wpforms_frontend_output_form_is_empty', empty( $form_data['fields'] ), $form_data );

		// If the form does not contain any fields - do not proceed.
		if ( $form_is_empty ) {
			$this->render_obj->form_is_empty();

			return true;
		}

		// We need to stop output processing in case we are on AMP page.
		if ( $this->amp_obj->stop_output( $form_data ) ) {
			return true;
		}

		// Add url query var wpforms_form_id to track post_max_size overflows.
		if ( in_array( 'file-upload', wp_list_pluck( $form_data['fields'], 'type' ), true ) ) {
			$this->action = add_query_arg( 'wpforms_form_id', $form_id, $this->action );
		}

		/**
		 * Fires before form data output.
		 *
		 * @since 1.0.0
		 *
		 * @param array   $form_data Form data.
		 * @param WP_Post $form      Form.
		 */
		do_action( 'wpforms_frontend_output_before', $form_data, $form );

		if ( $this->output_success( $form, $form_data ) ) {
			return true;
		}

		/**
		 * Allow filter to return early if some condition is not met.
		 *
		 * @since 1.0.0
		 *
		 * @param bool  $load       Load frontend flag.
		 * @param array $form_data  Form data.
		 * @param null  $deprecated Deprecated.
		 */
		if ( ! apply_filters( 'wpforms_frontend_load', true, $form_data, null ) ) {

			$this->form_container_open( $form_data, $form );

			/**
			 * Fires when frontend is not loaded.
			 *
			 * @since 1.4.8
			 *
			 * @param array   $form_data Form data.
			 * @param WP_Post $form      Form.
			 */
			do_action( 'wpforms_frontend_not_loaded', $form_data, $form );

			$this->form_container_close( $form_data, $form );

			return true;
		}

		return false;
	}

	/**
	 * Get pages.
	 *
	 * @since 1.8.1
	 *
	 * @param array $form_data Form data.
	 *
	 * @return array|false
	 * @noinspection PhpTernaryExpressionCanBeReducedToShortVersionInspection
	 * @noinspection ElvisOperatorCanBeUsedInspection
	 */
	private function get_pages( $form_data ) {

		$pages = wpforms_get_pagebreak_details( $form_data );

		return $pages ? $pages : false;
	}

	/**
	 * Check whether output was successful.
	 *
	 * @since 1.8.1
	 *
	 * @param WP_Post $form      Form.
	 * @param array   $form_data Form data.
	 *
	 * @return bool
	 */
	private function output_success( $form, $form_data ) {

		$form_id = absint( $form->ID );
		$process = wpforms()->get( 'process' );
		$errors  = empty( $process->errors[ $form_id ] ) ? [] : $process->errors[ $form_id ];

		// Check for return hash.
		if (
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			! empty( $_GET['wpforms_return'] ) &&
			$process->valid_hash &&
			(int) $process->form_data['id'] === $form_id
		) {
			$this->form_container_open( $form_data, $form );

			/**
			 * Fires at successful output.
			 *
			 * @since 1.4.5
			 *
			 * @param array $form_data Form data.
			 * @param array $fields    Form fields.
			 * @param int   $entry_id  Form ID.
			 */
			do_action( 'wpforms_frontend_output_success', $process->form_data, $process->fields, $process->entry_id );

			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			wpforms_debug_data( $_POST );

			$this->form_container_close( $form_data, $form );

			return true;
		}

		// Check for error-free completed form.
		if (
			// phpcs:disable WordPress.Security.NonceVerification.Missing
			empty( $errors ) &&
			! empty( $form_data ) &&
			! empty( $_POST['wpforms']['id'] ) &&
			(int) $_POST['wpforms']['id'] === $form_id
			// phpcs:enable WordPress.Security.NonceVerification.Missing
		) {
			$is_ajax = wp_doing_ajax();

			// There is no need for a container wrapper when a form is submitted through AJAX.
			if ( ! $is_ajax ) {
				$this->form_container_open( $form_data, $form );
			}

			/** This action is documented in the same method, several lines above. */
			do_action( 'wpforms_frontend_output_success', $form_data, false, false );

			if ( ! $is_ajax ) {
				$this->form_container_close( $form_data, $form );
			}

			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			wpforms_debug_data( $_POST );

			return true;
		}

		return false;
	}

	/**
	 * Display form confirmation message.
	 *
	 * @since 1.8.1
	 *
	 * @param array $form_data Form data and settings.
	 * @param array $fields    Sanitized field data.
	 * @param int   $entry_id  Entry id.
	 */
	public function confirmation( $form_data, $fields = [], $entry_id = 0 ) {

		// In AMP, just print template.
		if ( $this->amp_obj->output_success_template( $form_data ) ) {
			return;
		}

		list( $fields, $entry_id ) = $this->prepare_confirmation_args( $fields, $entry_id );

		$process              = wpforms()->get( 'process' );
		$confirmation         = $process->get_current_confirmation();
		$confirmation_message = $process->get_confirmation_message( $form_data, $fields, $entry_id );

		// Only display if a confirmation message has been configured.
		if ( empty( $confirmation ) || empty( $confirmation_message ) ) {
			return;
		}

		// Load confirmation specific assets.
		$this->assets_confirmation( $form_data );

		/**
		 * Fires once before the confirmation message.
		 *
		 * @since 1.6.9
		 *
		 * @param array $confirmation Current confirmation data.
		 * @param array $form_data    Form data and settings.
		 * @param array $fields       Sanitized field data.
		 * @param int   $entry_id     Entry id.
		 */
		do_action( 'wpforms_frontend_confirmation_message_before', $confirmation, $form_data, $fields, $entry_id );

		$class = (int) wpforms_setting( 'disable-css', '1' ) === 1 ?
			'wpforms-confirmation-container-full' :
			'wpforms-confirmation-container';

		$class .= $this->confirmation_message_scroll ? ' wpforms-confirmation-scroll' : '';

		$this->render_obj->confirmation( $confirmation_message, $class, $form_data );

		/**
		 * Fires once after the confirmation message.
		 *
		 * @since 1.6.9
		 *
		 * @param array $confirmation Current confirmation data.
		 * @param array $form_data    Form data and settings.
		 * @param array $fields       Sanitized field data.
		 * @param int   $entry_id     Entry id.
		 */
		do_action( 'wpforms_frontend_confirmation_message_after', $confirmation, $form_data, $fields, $entry_id );
	}

	/**
	 * Prepare confirmation arguments.
	 *
	 * @since 1.8.1
	 *
	 * @param array $fields   Sanitized field data.
	 * @param int   $entry_id Entry id.
	 */
	private function prepare_confirmation_args( $fields = [], $entry_id = 0 ) {

		// phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash

		if ( empty( $fields ) ) {
			$fields = ! empty( $_POST['wpforms']['complete'] ) ? $_POST['wpforms']['complete'] : [];
		}

		if ( empty( $entry_id ) ) {
			$entry_id = ! empty( $_POST['wpforms']['entry_id'] ) ? $_POST['wpforms']['entry_id'] : 0;
		}

		// phpcs:enable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash

		return [ $fields, $entry_id ];
	}

	/**
	 * Form container classes.
	 *
	 * @since 1.7.9
	 *
	 * @param array $form_data Form data and settings.
	 *
	 * @return array
	 */
	private function get_container_classes( $form_data ) {

		$classes = (int) wpforms_setting( 'disable-css', '1' ) === 1 ? [ 'wpforms-container-full' ] : [];

		/**
		 * Allow form container classes to be filtered and user defined classes.
		 *
		 * @since 1.0.0
		 *
		 * @param array $classes   Classes.
		 * @param array $form_data Form data and settings.
		 */
		$classes = apply_filters( 'wpforms_frontend_container_class', $classes, $form_data );

		if ( ! empty( $form_data['settings']['form_class'] ) ) {
			$classes = array_merge( $classes, explode( ' ', $form_data['settings']['form_class'] ) );
		}

		return $classes;
	}

	/**
	 * Display the opening container markup for a form.
	 *
	 * @since 1.7.9
	 *
	 * @param array   $form_data Form data and settings.
	 * @param WP_Post $form      Form post type.
	 */
	private function form_container_open( $form_data, $form ) {

		/**
		 * Fires before container open tag.
		 *
		 * @since 1.5.4.2
		 *
		 * @param array   $form_data Form data and settings.
		 * @param WP_Post $form      Form post type.
		 */
		do_action( 'wpforms_frontend_output_container_before', $form_data, $form );

		$classes = $this->get_container_classes( $form_data );

		$this->render_obj->form_container_open( $classes, $form_data );
	}

	/**
	 * Display the closing container markup for a form.
	 *
	 * @since 1.7.9
	 *
	 * @param array   $form_data Form data and settings.
	 * @param WP_Post $form      Form post type.
	 */
	private function form_container_close( $form_data, $form ) {

		$this->render_obj->form_container_close();

		/**
		 * Fires after container close tag.
		 *
		 * @since 1.5.4.2
		 *
		 * @param array   $form_data Form data and settings.
		 * @param WP_Post $form      Form post type.
		 */
		do_action( 'wpforms_frontend_output_container_after', $form_data, $form );
	}

	/**
	 * Form head area, for displaying form title and description if enabled.
	 *
	 * @since 1.8.1
	 *
	 * @param array $form_data   Form data and settings.
	 * @param null  $deprecated  Deprecated in v1.3.7, previously was $form object.
	 * @param bool  $title       Whether to display form title.
	 * @param bool  $description Whether to display form description.
	 * @param array $errors      List of all errors filled in WPForms_Process::process().
	 *
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function head( $form_data, $deprecated, $title, $description, $errors ) {

		// Output title and/or description.
		if ( $title === true || $description === true ) {
			$this->render_obj->form_head_container( $title, $description, $form_data );
		}

		/**
		 * Filters <noscript> error message.
		 *
		 * @since 1.5.7
		 *
		 * @param string $message   Message.
		 * @param array  $form_data Form data.
		 */
		$noscript_msg = apply_filters(
			'wpforms_frontend_noscript_error_message',
			__( 'Please enable JavaScript in your browser to complete this form.', 'wpforms-lite' ),
			$form_data
		);

		if ( ! empty( $noscript_msg ) && ! empty( $form_data['fields'] ) && ! $this->amp_obj->is_amp() ) {
			$this->render_obj->noscript( $noscript_msg );
		}

		// Output header errors if they exist.
		if ( ! empty( $errors['header'] ) ) {
			$this->form_error( 'header', $errors['header'] );
		}
	}

	/**
	 * Form field area.
	 *
	 * @since 1.8.1
	 *
	 * @param array $form_data   Form data and settings.
	 * @param null  $deprecated  Deprecated in v1.3.7, previously was $form object.
	 * @param bool  $title       Whether to display form title.
	 * @param bool  $description Whether to display form description.
	 * @param array $errors      List of all errors filled in WPForms_Process::process().
	 *
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function fields( $form_data, $deprecated, $title, $description, $errors ) {

		// Obviously we need to have form fields to proceed.
		if ( empty( $form_data['fields'] ) ) {
			return;
		}

		/**
		 * Filters the base level fields on the frontend.
		 *
		 * @since 1.7.7
		 *
		 * @param array $fields_data Form fields data.
		 */
		$fields = (array) apply_filters( 'wpforms_frontend_fields_base_level', $form_data['fields'] );

		// Form fields area.
		$this->render_obj->fields_area_open();

			/**
			 * Core actions on this hook:
			 * Priority / Description
			 * 20         Pagebreak markup (open first page).
			 *
			 * @since 1.3.7
			 *
			 * @param array $form_data Form data.
			 */
			do_action( 'wpforms_display_fields_before', $form_data ); // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName

			// Loop through all the fields we have.
			foreach ( $fields as $field ) {
				$this->render_field( $form_data, $field );
			}

			/**
			 * Core actions on this hook:
			 * Priority / Description
			 * 5          Pagebreak markup (close last page).
			 *
			 * @since 1.3.7
			 *
			 * @param array $form_data Form data.
			 */
			do_action( 'wpforms_display_fields_after', $form_data ); // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName

		$this->render_obj->fields_area_close();
	}

	/**
	 * Return base attributes for a specific field. This is deprecated and
	 * exists for backwards-compatibility purposes. Use field properties instead.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field     Field data and settings.
	 * @param array $form_data Form data and settings.
	 *
	 * @return array
	 */
	public function get_field_attributes( $field, $form_data ) {

		$form_id    = absint( $form_data['id'] );
		$field_id   = absint( $field['id'] );
		$attributes = [
			'field_class'       => [ 'wpforms-field', 'wpforms-field-' . sanitize_html_class( $field['type'] ) ],
			'field_id'          => [ sprintf( 'wpforms-%d-field_%d-container', $form_id, $field_id ) ],
			'field_style'       => '',
			'label_class'       => [ 'wpforms-field-label' ],
			'label_id'          => '',
			'description_class' => [ 'wpforms-field-description' ],
			'description_id'    => [],
			'input_id'          => [ sprintf( 'wpforms-%d-field_%d', $form_id, $field_id ) ],
			'input_class'       => [],
			'input_data'        => [],
		];

		// Check user field defined classes.
		if ( ! empty( $field['css'] ) ) {
			$attributes['field_class'] = array_merge( $attributes['field_class'], wpforms_sanitize_classes( $field['css'], true ) );
		}

		// Check for input column layouts.
		$attributes = $this->check_input_columns( $field, $attributes );

		// Check label visibility.
		if ( ! empty( $field['label_hide'] ) ) {
			$attributes['label_class'][] = 'wpforms-label-hide';
		}

		// Check size.
		if ( ! empty( $field['size'] ) ) {
			$attributes['input_class'][] = 'wpforms-field-' . sanitize_html_class( $field['size'] );
		}

		// Check if required.
		if ( ! empty( $field['required'] ) ) {
			$attributes['input_class'][] = 'wpforms-field-required';
		}

		// Check if there are errors.
		if ( ! empty( wpforms()->process->errors[ $form_id ][ $field_id ] ) ) {
			$attributes['input_class'][] = 'wpforms-error';
		}

		/**
		 * Filters field attributes.
		 * This filter is deprecated, filter the properties (below) instead.
		 *
		 * @since 1.0.0
		 *
		 * @param array $attributes Field attributes.
		 * @param array $field      Field data and settings.
		 * @param array $form_data  Form data and settings.
		 */
		return apply_filters( 'wpforms_field_atts', $attributes, $field, $form_data ); // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName
	}

	/**
	 * Check input column layouts and set relevant attributes.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field      Field data and settings.
	 * @param array $attributes Attributes.
	 *
	 * @return array
	 */
	private function check_input_columns( $field, $attributes ) {

		if ( ! empty( $field['input_columns'] ) ) {
			if ( $field['input_columns'] === '2' ) {
				$attributes['field_class'][] = 'wpforms-list-2-columns';
			} elseif ( $field['input_columns'] === '3' ) {
				$attributes['field_class'][] = 'wpforms-list-3-columns';
			} elseif ( $field['input_columns'] === 'inline' ) {
				$attributes['field_class'][] = 'wpforms-list-inline';
			}
		}

		return $attributes;
	}

	/**
	 * Return base properties for a specific field.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field      Field data and settings.
	 * @param array $form_data  Form data and settings.
	 * @param array $attributes List of field attributes.
	 *
	 * @return array
	 */
	public function get_field_properties( $field, $form_data, $attributes = [] ) {

		list( $field, $attributes, $error ) = $this->prepare_get_field_properties( $field, $form_data, $attributes );

		$form_id  = absint( $form_data['id'] );
		$field_id = absint( $field['id'] );

		$properties = [
			'container'   => [
				'attr'  => [
					'style' => $attributes['field_style'],
				],
				'class' => $attributes['field_class'],
				'data'  => [],
				'id'    => implode( '', array_slice( $attributes['field_id'], 0 ) ),
			],
			'label'       => [
				'attr'     => [
					'for' => sprintf( 'wpforms-%d-field_%d', $form_id, $field_id ),
				],
				'class'    => $attributes['label_class'],
				'data'     => [],
				'disabled' => ! empty( $field['label_disable'] ),
				'hidden'   => ! empty( $field['label_hide'] ),
				'id'       => $attributes['label_id'],
				'required' => ! empty( $field['required'] ),
				'value'    => ! empty( $field['label'] ) ? $field['label'] : '',
			],
			'inputs'      => [
				'primary' => [
					'attr'     => [
						'name'        => "wpforms[fields][{$field_id}]",
						'value'       => isset( $field['default_value'] ) ? wpforms_process_smart_tags( $field['default_value'], $form_data ) : '',
						'placeholder' => isset( $field['placeholder'] ) ? $field['placeholder'] : '',
					],
					'class'    => $attributes['input_class'],
					'data'     => $attributes['input_data'],
					'id'       => implode( array_slice( $attributes['input_id'], 0 ) ),
					'required' => ! empty( $field['required'] ) ? 'required' : '',
				],
			],
			'error'       => [
				'attr'  => [
					'for' => sprintf( 'wpforms-%d-field_%d', $form_id, $field_id ),
				],
				'class' => [ 'wpforms-error' ],
				'data'  => [],
				'id'    => '',
				'value' => $error,
			],
			'description' => [
				'attr'     => [],
				'class'    => $attributes['description_class'],
				'data'     => [],
				'id'       => implode( '', array_slice( $attributes['description_id'], 0 ) ),
				'position' => 'after',
				'value'    => ! empty( $field['description'] ) ? wpforms_process_smart_tags( $field['description'], $form_data ) : '',
			],
		];

		// phpcs:disable WPForms.PHP.ValidateHooks.InvalidHookName
		/**
		 * Filters field properties.
		 *
		 * @since 1.3.6.2
		 *
		 * @param array $properties Field properties.
		 * @param array $field      Field data and settings.
		 * @param array $form_data  Form data and settings.
		 */
		$properties = apply_filters( "wpforms_field_properties_{$field['type']}", $properties, $field, $form_data );

		/**
		 * Filters properties.
		 *
		 * @since 1.3.6.2
		 *
		 * @param array $properties Field properties.
		 * @param array $field      Field data and settings.
		 * @param array $form_data  Form data and settings.
		 */
		return apply_filters( 'wpforms_field_properties', $properties, $field, $form_data );
		// phpcs:enable WPForms.PHP.ValidateHooks.InvalidHookName
	}

	/**
	 * Prepare get_field_properties.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field      Field data and settings.
	 * @param array $form_data  Form data and settings.
	 * @param array $attributes List of field attributes.
	 *
	 * @return array
	 */
	private function prepare_get_field_properties( $field, $form_data, $attributes ) {

		$attributes = empty( $attributes ) ? $this->get_field_attributes( $field, $form_data ) : $attributes;
		$field      = $this->filter_field( $field, $form_data, $attributes );
		$form_id    = absint( $form_data['id'] );
		$field_id   = absint( $field['id'] );
		$error      = ! empty( wpforms()->process->errors[ $form_id ][ $field_id ] ) ? wpforms()->process->errors[ $form_id ][ $field_id ] : '';

		return [ $field, $attributes, $error ];
	}

	/**
	 * Filter field.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field      Field data and settings.
	 * @param array $form_data  Form data and settings.
	 * @param array $attributes Field attributes.
	 *
	 * @return array
	 */
	private function filter_field( $field, $form_data, $attributes ) {

		// This filter is for backwards compatibility purposes.
		$types = [ 'text', 'textarea', 'name', 'number', 'email', 'hidden', 'url', 'html', 'divider', 'password', 'phone', 'address', 'select', 'checkbox', 'radio' ];

		if ( in_array( $field['type'], $types, true ) ) {
			// phpcs:disable WPForms.PHP.ValidateHooks.InvalidHookName

			/**
			 * Filters field.
			 *
			 * @since 1.3.6.2
			 *
			 * @param array $field      Field data and settings.
			 * @param array $attributes Field attributes.
			 * @param array $form_data  Form data and settings.
			 */
			$filtered_field = apply_filters( "wpforms_{$field['type']}_field_display", $field, $attributes, $form_data );
			$field          = wpforms_list_intersect_key( (array) $filtered_field, $field );
		} elseif ( $field['type'] === 'credit-card' ) {

			/**
			 * Filters credit card field.
			 *
			 * @since 1.3.6.2
			 *
			 * @param array $field      Field data and settings.
			 * @param array $attributes Field attributes.
			 * @param array $form_data  Form data and settings.
			 */
			$filtered_field = apply_filters( 'wpforms_creditcard_field_display', $field, $attributes, $form_data );
			$field          = wpforms_list_intersect_key( (array) $filtered_field, $field );
		} elseif ( in_array( $field['type'], [ 'payment-multiple', 'payment-single', 'payment-checkbox' ], true ) ) {
			$filter_field_type = str_replace( '-', '_', $field['type'] );

			/**
			 * Filters payment field.
			 *
			 * @since 1.3.6.2
			 *
			 * @param array $field      Field data and settings.
			 * @param array $attributes Field attributes.
			 * @param array $form_data  Form data and settings.
			 */
			$filtered_field = apply_filters( 'wpforms_' . $filter_field_type . '_field_display', $field, $attributes, $form_data );
			$field          = wpforms_list_intersect_key( (array) $filtered_field, $field );
			// phpcs:enable WPForms.PHP.ValidateHooks.InvalidHookName
		}

		return $field;
	}

	/**
	 * Field container open.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field     Field data and settings.
	 * @param array $form_data Form data and settings.
	 */
	public function field_container_open( $field, $form_data ) {

		$this->render_obj->field_container_open( $field, $form_data );
	}

	/**
	 * Field container close.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field     Field data and settings.
	 * @param array $form_data Form data and settings.
	 */
	public function field_container_close( $field, $form_data ) {

		$this->render_obj->field_container_close( $field, $form_data );
	}

	/**
	 * Field fieldset open.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field     Field data and settings.
	 * @param array $form_data Form data and settings.
	 */
	public function field_fieldset_open( $field, $form_data ) {

		$this->render_obj->field_fieldset_open( $field, $form_data );
	}

	/**
	 * Field fieldset close.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field     Field data and settings.
	 * @param array $form_data Form data and settings.
	 */
	public function field_fieldset_close( $field, $form_data ) {

		$this->render_obj->field_fieldset_close( $field, $form_data );
	}

	/**
	 * Display the label for each field.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field     Field data and settings.
	 * @param array $form_data Form data and settings.
	 */
	public function field_label( $field, $form_data ) {

		$label = $field['properties']['label'];

		// If the label is empty or disabled don't proceed.
		if ( empty( $label['value'] ) || $label['disabled'] ) {
			return;
		}

		$this->render_obj->field_label( $field, $form_data );
	}

	/**
	 * Display any errors for each field.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field     Field data and settings.
	 * @param array $form_data Form data and settings.
	 */
	public function field_error( $field, $form_data ) {

		$error = $field['properties']['error'];

		// If there are no errors don't proceed.
		// Advanced fields with multiple inputs (address, name, etc.) errors
		// will be an array and are handled within the respective field class.
		if ( empty( $error['value'] ) || is_array( $error['value'] ) ) {
			return;
		}

		$this->render_obj->field_error( $field, $form_data );
	}

	/**
	 * Display the description for each field.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field     Field data and settings.
	 * @param array $form_data Form data and settings.
	 *
	 * @noinspection HtmlUnknownAttribute
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function field_description( $field, $form_data ) {

		$action      = current_action();
		$description = $field['properties']['description'];

		// If the description is empty don't proceed.
		if ( empty( $description['value'] ) ) {
			return;
		}

		// Determine positioning.
		if ( $action === 'wpforms_display_field_before' && $description['position'] !== 'before' ) {
			return;
		}

		if ( $action === 'wpforms_display_field_after' && $description['position'] !== 'after' ) {
			return;
		}

		if ( $description['position'] === 'before' ) {
			$description['class'][] = 'before';
		}

		$this->render_obj->field_description( $field, $form_data );
	}

	/**
	 * Anti-spam honeypot output if configured.
	 *
	 * @since 1.8.1
	 *
	 * @param array $form_data   Form data and settings.
	 * @param null  $deprecated  Deprecated in v1.3.7, previously was $form object.
	 * @param bool  $title       Whether to display form title.
	 * @param bool  $description Whether to display form description.
	 * @param array $errors      List of all errors filled in WPForms_Process::process().
	 *
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function honeypot( $form_data, $deprecated, $title, $description, $errors ) {

		if (
			empty( $form_data['settings']['honeypot'] ) ||
			$form_data['settings']['honeypot'] !== '1'
		) {
			return;
		}

		$names = [ 'Name', 'Phone', 'Comment', 'Message', 'Email', 'Website' ];

		echo '<div class="wpforms-field wpforms-field-hp">';

			// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped
			echo '<label for="wpforms-' . $form_data['id'] . '-field-hp" class="wpforms-field-label">' . $names[ array_rand( $names ) ] . '</label>';

			echo '<input type="text" name="wpforms[hp]" id="wpforms-' . $form_data['id'] . '-field-hp" class="wpforms-field-medium">';
			// phpcs:enable WordPress.Security.EscapeOutput.OutputNotEscaped

		echo '</div>';
	}

	/**
	 * Form footer area.
	 *
	 * @since 1.8.1
	 *
	 * @param array $form_data   Form data and settings.
	 * @param null  $deprecated  Deprecated in v1.3.7, previously was $form object.
	 * @param bool  $title       Whether to display form title.
	 * @param bool  $description Whether to display form description.
	 * @param array $errors      List of all errors filled in WPForms_Process::process().
	 *
	 * @noinspection HtmlUnknownTarget
	 * @noinspection HtmlUnknownAttribute
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function foot( $form_data, $deprecated, $title, $description, $errors ) {

		$form_id  = absint( $form_data['id'] );
		$settings = $form_data['settings'];

		/**
		 * Filter form submit button text.
		 *
		 * @since 1.0.0
		 *
		 * @param string $submit_text Submit button text.
		 * @param array  $form_data   Form data.
		 */
		$submit = apply_filters( 'wpforms_field_submit', $settings['submit_text'], $form_data ); // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName

		$attrs      = [
			'aria-live' => 'assertive',
			'value'     => 'wpforms-submit',
		];
		$data_attrs = [];

		/**
		 * Filter form submit button classes.
		 *
		 * @since 1.7.5.3
		 *
		 * @param array $classes   Button classes.
		 * @param array $form_data Form data.
		 */
		$classes = (array) apply_filters( 'wpforms_frontend_foot_submit_classes', [], $form_data );

		// A lot of our frontend logic is dependent on this class, so we need to make sure it's present.
		$classes = array_merge( $classes, [ 'wpforms-submit' ] );

		list( $attrs, $data_attrs, $classes ) = $this->check_submit_settings( $settings, $form_id, $submit, $attrs, $data_attrs, $classes );

		// AMP submit error template.
		$this->amp_obj->output_error_template();

		// Output footer errors if they exist.
		if ( ! empty( $errors['footer'] ) ) {
			$this->form_error( 'footer', $errors['footer'] );
		}

		// Submit button area.
		$this->render_obj->submit_container_open( $this->pages, $form_data );

		echo '<input type="hidden" name="wpforms[id]" value="' . absint( $form_id ) . '">';

		if ( is_user_logged_in() ) {
			?>
			<input
				type="hidden"
				name="wpforms[nonce]"
				value="<?php echo esc_attr( wp_create_nonce( "wpforms::form_{$form_id}" ) ); ?>"
			/>
			<?php
		}

		echo '<input type="hidden" name="wpforms[author]" value="' . absint( get_the_author_meta( 'ID' ) ) . '">';

		if ( is_singular() ) {
			echo '<input type="hidden" name="wpforms[post_id]" value="' . absint( get_the_ID() ) . '">';
		}

		/**
		 * Fires before submit button.
		 *
		 * @since 1.3.6.2
		 *
		 * @param array $form_data  Form data and settings.
		 */
		do_action( 'wpforms_display_submit_before', $form_data ); // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName

		$this->render_obj->submit_button( $form_id, $submit, $classes, $data_attrs, $attrs, $form_data );

		if ( ! empty( $settings['ajax_submit'] ) && ! $this->amp_obj->is_amp() ) {

			/**
			 * Filter submit spinner image src attribute.
			 *
			 * @since      1.5.4.1
			 * @deprecated 1.6.7.3
			 *
			 * @see This filter is documented in wp-includes/plugin.php
			 */
			$src = apply_filters_deprecated(
				'wpforms_display_sumbit_spinner_src',
				[
					WPFORMS_PLUGIN_URL . 'assets/images/submit-spin.svg',
					$form_data,
				],
				'1.6.7.3',
				'wpforms_display_submit_spinner_src'
			);

			/**
			 * Filter submit spinner image src attribute.
			 *
			 * @since 1.6.7.3
			 *
			 * @param string $src       Spinner image source.
			 * @param array  $form_data Form data and settings.
			 */
			$src = apply_filters( // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName
				'wpforms_display_submit_spinner_src',
				$src,
				$form_data
			);

			$this->render_obj->submit_spinner( $src, $form_data );
		}

		/**
		 * Runs right after form Submit button rendering.
		 *
		 * @since 1.5.0
		 * @since 1.7.5 Added new parameter for detecting button type.
		 *
		 * @param array  $form_data Form data.
		 * @param string $button    Button type, e.g. `submit`, `next`.
		 */
		do_action( 'wpforms_display_submit_after', $form_data, 'submit' ); // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName

		$this->render_obj->submit_container_close( $form_data );

		// Load the success template in AMP.
		$this->amp_obj->output_success_template( $form_data );
	}

	/**
	 * Check submit settings and adjust attributes and classes.
	 *
	 * @since 1.8.1
	 *
	 * @param array  $settings   Settings.
	 * @param int    $form_id    Form id.
	 * @param string $submit     Submit button text.
	 * @param array  $attrs      Attributes.
	 * @param array  $data_attrs Data attributes.
	 * @param array  $classes    Classes.
	 *
	 * @return array
	 */
	private function check_submit_settings( $settings, $form_id, $submit, $attrs, $data_attrs, $classes ) {

		// Check for submit button alt-text.
		if ( ! empty( $settings['submit_text_processing'] ) ) {
			if ( $this->amp_obj->is_amp() ) {
				$attrs['[text]'] = $this->amp_obj->get_text_attr( $form_id, $settings, $submit );
			} else {
				$data_attrs['alt-text']    = $settings['submit_text_processing'];
				$data_attrs['submit-text'] = $submit;
			}
		}

		// Check user defined submit button classes.
		if ( ! empty( $settings['submit_class'] ) ) {
			$submit_classes = is_array( $settings['submit_class'] ) ?
				$settings['submit_class'] :
				array_filter( explode( ' ', $settings['submit_class'] ) );
			$classes        = array_merge( $classes, $submit_classes );
		}

		return [ $attrs, $data_attrs, $classes ];
	}

	/**
	 * Display form error.
	 *
	 * @since 1.5.3
	 * @since 1.8.1 Added $form_data optional parameter.
	 *
	 * @param string $type      Error type.
	 * @param string $error     Error text.
	 * @param array  $form_data Form data. Defaults to null.
	 *                          Added to pass the form data in the case of
	 *                          the method is called inside the ajax callback.
	 */
	public function form_error( $type, $error, $form_data = null ) {

		if ( ! empty( $form_data ) ) {
			$this->render_obj->form_data = $form_data;
		}

		$this->render_obj->form_error( $type, $error );
	}

	/**
	 * Determine if we should load assets globally.
	 * If false assets will load conditionally (default).
	 *
	 * @since 1.2.4
	 *
	 * @return bool
	 */
	public function assets_global() {

		/**
		 * Filters global assets.
		 *
		 * @since 1.2.4
		 *
		 * @param bool $are_assets_global Global assets.
		 */
		return apply_filters( 'wpforms_global_assets', wpforms_setting( 'global-assets', false ) ); // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName
	}

	/**
	 * Load the necessary CSS for single pages/posts earlier if possible.
	 *
	 * If we are viewing a singular page, then we can check the content early
	 * to see if the shortcode was used. If not, we fall back and load the assets
	 * later on during the page (widgets, archives, etc).
	 *
	 * @since 1.0.0
	 */
	public function assets_header() {

		/**
		 * Allow loading assets in header on various pages.
		 *
		 * By default, assets are loaded only on singular pages if WPForms shortcode or editor block is present.
		 * However, if a form is added as a sidebar widget, in a template or somewhere else outside the Loop,
		 * we will discover that too late for assets to be included in the header. In this case we will
		 * include all required assets in the footer instead. This may lead to a brief FOUC (Flash
		 * Of Unstyled Content).
		 *
		 * Returning `true` from this filter on a particular page that matches your criteria
		 * is useful if you need to load assets in header on archive pages or any other
		 * pages that you know have a form - as a sidebar widget, dynamically inserted
		 * on form preview page, on category pages, etc.
		 *
		 * @since 1.8.1
		 *
		 * @param bool $force_load Force loading assets in header, default `false`.
		 */
		$force_load = (bool) apply_filters( 'wpforms_frontend_assets_header_force_load', false );

		if ( $force_load ) {
			$this->assets_css();

			return;
		}

		if ( ! is_singular() ) {
			return;
		}

		global $post;

		if (
			has_shortcode( $post->post_content, 'wpforms' ) ||
			( function_exists( 'has_block' ) && has_block( 'wpforms/form-selector' ) )
		) {
			$this->assets_css();
		}
	}

	/**
	 * Load the CSS assets for frontend output.
	 *
	 * @since 1.0.0
	 */
	public function assets_css() {

		/**
		 * Fires before enqueueing frontend CSS.
		 *
		 * @since 1.0.0
		 *
		 * @param array $forms Array of forms on the page.
		 */
		do_action( 'wpforms_frontend_css', $this->forms ); // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName

		$min         = wpforms_get_min_suffix();
		$disable_css = (int) wpforms_setting( 'disable-css', '1' );

		if ( $disable_css === 3 ) {
			return;
		}

		$style_name = $disable_css === 1 ? 'full' : 'base';

		wp_enqueue_style(
			"wpforms-{$this->render_engine}-{$style_name}",
			WPFORMS_PLUGIN_URL . "assets/css/frontend/{$this->render_engine}/wpforms-{$style_name}{$min}.css",
			[],
			WPFORMS_VERSION
		);
	}

	/**
	 * Load the JS assets for frontend output.
	 *
	 * @since 1.0.0
	 */
	public function assets_js() {

		if ( $this->amp_obj->is_amp() ) {
			return;
		}

		/**
		 * Fire before frontend JS assets are loaded.
		 *
		 * @since 1.0.0
		 *
		 * @param array $forms Forms on the current page.
		 */
		do_action( 'wpforms_frontend_js', $this->forms );

		$min = wpforms_get_min_suffix();

		// Load jQuery validation library - https://jqueryvalidation.org/.
		wp_enqueue_script(
			'wpforms-validation',
			WPFORMS_PLUGIN_URL . 'assets/lib/jquery.validate.min.js',
			[ 'jquery' ],
			'1.19.5',
			true
		);

		// Load jQuery input mask library - https://github.com/RobinHerbots/jquery.inputmask.
		if (
			$this->assets_global() ||
			wpforms_has_field_type( [ 'phone', 'address' ], $this->forms, true ) ||
			wpforms_has_field_setting( 'input_mask', $this->forms, true )
		) {
			wp_enqueue_script(
				'wpforms-maskedinput',
				WPFORMS_PLUGIN_URL . 'assets/lib/jquery.inputmask.min.js',
				[ 'jquery' ],
				'5.0.7-beta.29',
				true
			);
		}

		// Load mailcheck <https://github.com/mailcheck/mailcheck> and punycode libraries.
		if (
			$this->assets_global() ||
			wpforms_has_field_type( [ 'email' ], $this->forms, true )
		) {
			wp_enqueue_script(
				'wpforms-mailcheck',
				WPFORMS_PLUGIN_URL . 'assets/lib/mailcheck.min.js',
				false,
				'1.1.2',
				true
			);

			wp_enqueue_script(
				'wpforms-punycode',
				WPFORMS_PLUGIN_URL . 'assets/lib/punycode.min.js',
				[],
				'1.0.0',
				true
			);
		}

		wp_enqueue_script(
			'wpforms-generic-utils',
			WPFORMS_PLUGIN_URL . "assets/js/utils{$min}.js",
			[ 'jquery' ],
			WPFORMS_VERSION,
			true
		);

		// Load base JS.
		wp_enqueue_script(
			'wpforms',
			WPFORMS_PLUGIN_URL . "assets/js/wpforms{$min}.js",
			[ 'jquery' ],
			WPFORMS_VERSION,
			true
		);

		// Load JS additions needed in the Modern Markup mode.
		if ( $this->render_engine === 'modern' ) {
			wp_enqueue_script(
				'wpforms-modern',
				WPFORMS_PLUGIN_URL . "assets/js/wpforms-modern{$min}.js",
				[ 'wpforms' ],
				WPFORMS_VERSION,
				true
			);
		}
	}

	/**
	 * Retrieve the string containing the CAPTCHA inline javascript.
	 *
	 * @since 1.6.4
	 *
	 * @param array $captcha_settings The CAPTCHA settings.
	 *
	 * @return string
	 */
	protected function get_captcha_inline_script( $captcha_settings ) {

		// IE11 polyfills for native `matches()` and `closest()` methods.
		$polyfills = /** @lang JavaScript */
			'if (!Element.prototype.matches) {
				Element.prototype.matches = Element.prototype.msMatchesSelector || Element.prototype.webkitMatchesSelector;
			}
			if (!Element.prototype.closest) {
				Element.prototype.closest = function (s) {
					var el = this;
					do {
						if (Element.prototype.matches.call(el, s)) { return el; }
						el = el.parentElement || el.parentNode;
					} while (el !== null && el.nodeType === 1);
					return null;
				};
			}
		';

		// Native equivalent for jQuery's `trigger()` method.
		$dispatch = /** @lang JavaScript */
			'var wpformsDispatchEvent = function (el, ev, custom) {
				var e = document.createEvent(custom ? "CustomEvent" : "HTMLEvents");
				custom ? e.initCustomEvent(ev, true, true, false) : e.initEvent(ev, true, true);
				el.dispatchEvent(e);
			};
		';

		// Update container class after changing Turnstile type.
		$turnstile_update_class = /** @lang JavaScript */
			'var turnstileUpdateContainer = function (el) {
				let form = el.closest( "form" ),
				iframeHeight = el.getElementsByTagName("iframe")[0].style.height;
				
				parseInt(iframeHeight) === 0 ? 
					form.querySelector(".wpforms-is-turnstile").classList.add( "wpforms-is-turnstile-invisible" ) :
					form.querySelector(".wpforms-is-turnstile").classList.remove( "wpforms-is-turnstile-invisible" );
			};
		';

		// Captcha callback, used by hCaptcha and checkbox reCaptcha v2.
		$callback = /** @lang JavaScript */
			'var wpformsRecaptchaCallback = function (el) {
				var hdn = el.parentNode.querySelector(".wpforms-recaptcha-hidden");
				var err = el.parentNode.querySelector("#g-recaptcha-hidden-error");
				hdn.value = "1";
				wpformsDispatchEvent(hdn, "change", false);
				hdn.classList.remove("wpforms-error");
				err && hdn.parentNode.removeChild(err);
			};
		';

		if ( $captcha_settings['provider'] === 'hcaptcha' ) {

			$data  = $dispatch;
			$data .= $callback;

			$data .= /** @lang JavaScript */
				'var wpformsRecaptchaLoad = function () {
					Array.prototype.forEach.call(document.querySelectorAll(".g-recaptcha"), function (el) {
						var captchaID = hcaptcha.render(el, {
							callback: function () {
								wpformsRecaptchaCallback(el);
							}
						});
						el.setAttribute("data-recaptcha-id", captchaID);
					});
					wpformsDispatchEvent(document, "wpformsRecaptchaLoaded", true);
				};
			';

			return $data;
		}

		if ( $captcha_settings['recaptcha_type'] === 'v3' ) {

			$data = $dispatch;

			$data .= /** @lang JavaScript */
				'var wpformsRecaptchaV3Execute = function ( callback ) {
					grecaptcha.execute( "' . $captcha_settings['site_key'] . '", { action: "wpforms" } ).then( function ( token ) {
						Array.prototype.forEach.call( document.getElementsByName( "wpforms[recaptcha]" ), function ( el ) {
							el.value = token;
						} );
						if ( typeof callback === "function" ) {
							return callback();
						}
					} );
				}
				grecaptcha.ready( function () {
					wpformsDispatchEvent( document, "wpformsRecaptchaLoaded", true );
				} );
			';

		} elseif ( $captcha_settings['recaptcha_type'] === 'invisible' ) {

			$data  = $polyfills;
			$data .= $dispatch;

			$data .= /** @lang JavaScript */
				'var wpformsRecaptchaLoad = function () {
					Array.prototype.forEach.call(document.querySelectorAll(".g-recaptcha"), function (el) {
						try {
							var recaptchaID = grecaptcha.render(el, {
								callback: function () {
									wpformsRecaptchaCallback(el);
								}
							}, true);
							el.closest("form").querySelector("button[type=submit]").recaptchaID = recaptchaID;
						} catch (error) {}
					});
					wpformsDispatchEvent(document, "wpformsRecaptchaLoaded", true);
				};
				var wpformsRecaptchaCallback = function (el) {
					var $form = el.closest("form");
					if (typeof wpforms.formSubmit === "function") {
						wpforms.formSubmit($form);
					} else {
						$form.querySelector("button[type=submit]").recaptchaID = false;
						$form.submit();
					}
				};
			';

		} else {

			$data  = $dispatch;
			$data .= $callback;

			$data .= /** @lang JavaScript */
				'var wpformsRecaptchaLoad = function () {
					Array.prototype.forEach.call(document.querySelectorAll(".g-recaptcha"), function (el) {
						try {
							var recaptchaID = grecaptcha.render(el, {
								callback: function () {
									wpformsRecaptchaCallback(el);
								}
							});
							el.setAttribute("data-recaptcha-id", recaptchaID);
						} catch (error) {}
					});
					wpformsDispatchEvent(document, "wpformsRecaptchaLoaded", true);
				};
			';

		}

		return $data;
	}

	/**
	 * Cloudflare Turnstile captcha requires defer attribute.
	 *
	 * @since 1.8.0
	 *
	 * @param string $tag    HTML for the script tag.
	 * @param string $handle Handle of script.
	 * @param string $src    Src of script.
	 *
	 * @return string
	 */
	public function set_defer_attribute( $tag, $handle, $src ) {

		$captcha_settings = wpforms_get_captcha_settings();

		if ( $captcha_settings['provider'] !== 'turnstile' ) {
			return $tag;
		}

		if ( $handle !== 'wpforms-recaptcha' ) {
			return $tag;
		}

		return str_replace( ' src', ' defer src', $tag );
	}

	/**
	 * Load the necessary assets for the confirmation message.
	 *
	 * @since 1.1.2
	 * @since 1.7.9 Added $form_data argument.
	 *
	 * @param array $form_data Form data and settings.
	 */
	public function assets_confirmation( $form_data = [] ) {

		$form_data = (array) $form_data;
		$min       = wpforms_get_min_suffix();

		// Base CSS only.
		if ( (int) wpforms_setting( 'disable-css', '1' ) === 1 ) {
			wp_enqueue_style(
				'wpforms-full',
				WPFORMS_PLUGIN_URL . "assets/css/frontend/{$this->render_engine}/wpforms-full{$min}.css",
				[],
				WPFORMS_VERSION
			);
		}

		// Special confirmation JS.
		if ( ! $this->amp_obj->is_amp() ) {
			wp_enqueue_script(
				'wpforms-confirmation',
				WPFORMS_PLUGIN_URL . "assets/js/wpforms-confirmation{$min}.js",
				[ 'jquery' ],
				WPFORMS_VERSION,
				true
			);
		}

		/**
		 * Fires after enqueueing assets on confirmation page have been enqueued.
		 *
		 * @since 1.1.2
		 * @since 1.7.9 Added $form_data argument.
		 *
		 * @param array $form_data Form data and settings.
		 */
		do_action( 'wpforms_frontend_confirmation', $form_data );
	}

	/**
	 * Load the assets in footer if needed (archives, widgets, etc).
	 *
	 * @since 1.0.0
	 */
	public function assets_footer() {

		if ( empty( $this->forms ) && ! $this->assets_global() ) {
			return;
		}

		$this->assets_css();
		$this->assets_js();

		/**
		 * Fires after enqueueing footer assets.
		 *
		 * @since 1.0.0
		 *
		 * @param array $forms Forms being shown.
		 */
		do_action( 'wpforms_wp_footer', $this->forms ); // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName
	}

	/**
	 * Get strings to localize.
	 *
	 * @since 1.6.0
	 *
	 * @return array Array of strings to localize.
	 */
	public function get_strings() {

		// Define base strings.
		$strings = [
			'val_required'               => wpforms_setting( 'validation-required', esc_html__( 'This field is required.', 'wpforms-lite' ) ),
			'val_email'                  => wpforms_setting( 'validation-email', esc_html__( 'Please enter a valid email address.', 'wpforms-lite' ) ),
			'val_email_suggestion'       => wpforms_setting(
				'validation-email-suggestion',
				sprintf( /* translators: %s - suggested email address. */
					esc_html__( 'Did you mean %s?', 'wpforms-lite' ),
					'{suggestion}'
				)
			),
			'val_email_suggestion_title' => esc_attr__( 'Click to accept this suggestion.', 'wpforms-lite' ),
			'val_email_restricted'       => wpforms_setting( 'validation-email-restricted', esc_html__( 'This email address is not allowed.', 'wpforms-lite' ) ),
			'val_number'                 => wpforms_setting( 'validation-number', esc_html__( 'Please enter a valid number.', 'wpforms-lite' ) ),
			'val_number_positive'        => wpforms_setting( 'validation-number-positive', esc_html__( 'Please enter a valid positive number.', 'wpforms-lite' ) ),
			'val_confirm'                => wpforms_setting( 'validation-confirm', esc_html__( 'Field values do not match.', 'wpforms-lite' ) ),
			'val_checklimit'             => wpforms_setting( 'validation-check-limit', esc_html__( 'You have exceeded the number of allowed selections: {#}.', 'wpforms-lite' ) ),
			'val_limit_characters'       => wpforms_setting(
				'validation-character-limit',
				sprintf( /* translators: %1$s - characters count, %2$s - characters limit. */
					esc_html__( '%1$s of %2$s max characters.', 'wpforms-lite' ),
					'{count}',
					'{limit}'
				)
			),
			'val_limit_words'            => wpforms_setting(
				'validation-word-limit',
				sprintf( /* translators: %1$s - words count, %2$s - words limit. */
					esc_html__( '%1$s of %2$s max words.', 'wpforms-lite' ),
					'{count}',
					'{limit}'
				)
			),
			'val_recaptcha_fail_msg'     => wpforms_setting( 'recaptcha-fail-msg', esc_html__( 'Google reCAPTCHA verification failed, please try again later.', 'wpforms-lite' ) ),
			'val_turnstile_fail_msg'     => wpforms_setting( 'turnstile-fail-msg', esc_html__( 'Cloudflare Turnstile verification failed, please try again later.', 'wpforms-lite' ) ),
			'val_inputmask_incomplete'   => wpforms_setting( 'validation-inputmask-incomplete', esc_html__( 'Please fill out the field in required format.', 'wpforms-lite' ) ),
			'uuid_cookie'                => false,
			'locale'                     => wpforms_get_language_code(),
			'wpforms_plugin_url'         => WPFORMS_PLUGIN_URL,
			'gdpr'                       => wpforms_setting( 'gdpr' ),
			'ajaxurl'                    => admin_url( 'admin-ajax.php' ),
			/**
			 * Filters mail check enabled flag.
			 *
			 * @since 1.5.4.2
			 *
			 * @param bool $flag Enabled flag.
			 */
			'mailcheck_enabled'          => (bool) apply_filters( 'wpforms_mailcheck_enabled', true ), // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName
			/**
			 * Filters mail check domains.
			 *
			 * @since 1.5.4.2
			 *
			 * @param array $domains Domains to check.
			 */
			'mailcheck_domains'          => array_map( 'sanitize_text_field', (array) apply_filters( 'wpforms_mailcheck_domains', [] ) ), // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName
			/**
			 * Filters mail check toplevel domains.
			 *
			 * @since 1.5.4.2
			 *
			 * @param array $toplevel_domains Toplevel domains to check.
			 */
			'mailcheck_toplevel_domains' => array_map( 'sanitize_text_field', (array) apply_filters( 'wpforms_mailcheck_toplevel_domains', [ 'dev' ] ) ), // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName
			'is_ssl'                     => is_ssl(),
			'page_title'                 => wpforms_process_smart_tags( '{page_title}', [], [], '' ),
			'page_id'                    => wpforms_process_smart_tags( '{page_id}', [], [], '' ),
		];

		// Include payment related strings if needed.
		$strings = $this->get_payment_strings( $strings );

		// Include CSS variables list.
		$strings = $this->get_css_vars_strings( $strings );

		/**
		 * Filters frontend strings.
		 *
		 * @since 1.3.7.3
		 *
		 * @param array $strings Frontend strings.
		 */
		$strings = apply_filters( 'wpforms_frontend_strings', $strings );

		foreach ( (array) $strings as $key => $value ) {

			if ( ! is_scalar( $value ) ) {
				continue;
			}

			$strings[ $key ] = html_entity_decode( (string) $value, ENT_QUOTES, 'UTF-8' );
		}

		return $strings;
	}

	/**
	 * Get payment strings.
	 *
	 * @since 1.8.1
	 *
	 * @param array $strings Strings.
	 *
	 * @return array
	 */
	private function get_payment_strings( $strings ) {

		if ( function_exists( 'wpforms_get_currencies' ) ) {
			$currency                       = wpforms_get_currency();
			$currencies                     = wpforms_get_currencies();
			$strings['currency_code']       = $currency;
			$strings['currency_thousands']  = isset( $currencies[ $currency ]['thousands_separator'] ) ? $currencies[ $currency ]['thousands_separator'] : ',';
			$strings['currency_decimals']   = wpforms_get_currency_decimals( $currencies[ $currency ] );
			$strings['currency_decimal']    = isset( $currencies[ $currency ]['decimal_separator'] ) ? $currencies[ $currency ]['decimal_separator'] : '.';
			$strings['currency_symbol']     = isset( $currencies[ $currency ]['symbol'] ) ? $currencies[ $currency ]['symbol'] : '$';
			$strings['currency_symbol_pos'] = isset( $currencies[ $currency ]['symbol_pos'] ) ? $currencies[ $currency ]['symbol_pos'] : 'left';
		}

		return $strings;
	}

	/**
	 * Get CSS variables data.
	 *
	 * @since 1.8.1
	 *
	 * @param array $strings Strings.
	 *
	 * @return array
	 */
	private function get_css_vars_strings( $strings ) {

		if ( wpforms_get_render_engine() !== 'modern' ) {
			return $strings;
		}

		$css_vars_obj = wpforms()->get( 'css_vars' );

		if ( empty( $css_vars_obj ) ) {
			return $strings;
		}

		$strings['css_vars'] = array_keys( $css_vars_obj->get_vars( ':root' ) );

		return $strings;
	}

	/**
	 * Hook at fires at a later priority in wp_footer.
	 *
	 * @since 1.0.5
	 * @since 1.7.0 Load wpforms_settings on the confirmation page for a non-ajax form.
	 */
	public function footer_end() {

		if (
			( empty( $this->forms ) && empty( $_POST['wpforms'] ) && ! $this->assets_global() ) || // phpcs:ignore WordPress.Security.NonceVerification.Missing
			$this->amp_obj->is_amp()
		) {
			return;
		}

		$strings = $this->get_strings();

		/*
		 * Below we do our own implementation of wp_localize_script in an effort
		 * to be better compatible with caching plugins which were causing
		 * conflicts.
		 */
		echo "<script type='text/javascript'>\n";
		echo "/* <![CDATA[ */\n";
		echo 'var wpforms_settings = ' . wp_json_encode( $strings ) . "\n";
		echo "/* ]]> */\n";
		echo "</script>\n";

		/**
		 * Fires after the end of the footer.
		 *
		 * @since 1.0.6
		 *
		 * @param array $forms Forms being shown.
		 */
		do_action( 'wpforms_wp_footer_end', $this->forms ); // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName
	}

	/**
	 * Shortcode wrapper for the outputting a form.
	 *
	 * @since 1.0.0
	 *
	 * @param array $atts Shortcode attributes provided by a user.
	 *
	 * @return string
	 */
	public function shortcode( $atts ) {

		$defaults = [
			'id'          => false,
			'title'       => false,
			'description' => false,
		];

		$atts = shortcode_atts( $defaults, shortcode_atts( $defaults, $atts, 'output' ), 'wpforms' );

		ob_start();

		$this->output( $atts['id'], $atts['title'], $atts['description'] );

		return ob_get_clean();
	}

	/**
	 * Inline a script to check if our main js is loaded and display a warning message otherwise.
	 *
	 * @since 1.6.4.1
	 */
	public function missing_assets_error_js() {

		/**
		 * Disable missing assets error js checking.
		 *
		 * @since 1.6.6
		 *
		 * @param bool $skip False by default, set to True to disable checking.
		 */
		$skip = (bool) apply_filters( 'wpforms_frontend_missing_assets_error_js_disable', false );

		if ( $skip || ! wpforms_current_user_can() ) {
			return;
		}

		if ( empty( $this->forms ) && ! $this->assets_global() ) {
			return;
		}

		if ( $this->amp_obj->is_amp() ) {
			return;
		}

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		printf( $this->get_missing_assets_error_script(), $this->get_missing_assets_error_message() );
	}

	/**
	 * Get missing assets error script.
	 *
	 * @since 1.6.4.1
	 *
	 * @return string
	 */
	private function get_missing_assets_error_script() {

		return "<script>
				( function() {
					function wpforms_js_error_loading() {

						if ( typeof window.wpforms !== 'undefined' ) {
							return;
						}

						const forms = document.querySelectorAll( '.wpforms-form' );

						if ( ! forms.length ) {
							return;
						}

						const error = document.createElement( 'div' );

						error.classList.add( 'wpforms-error-container' );
						error.setAttribute( 'role', 'alert' );
						error.innerHTML = '%s';

						forms.forEach( function( form ) {

							if ( form.querySelector( '.wpforms-error-container' ) ) {
								return;
							}
							
							const formError = error.cloneNode( true ),
								formErrorId = form.id + '-error';
							
							formError.setAttribute( 'id', formErrorId );
							
							form.insertBefore( formError, form.firstChild );
							form.setAttribute( 'aria-invalid', 'true' );
							form.setAttribute( 'aria-errormessage', formErrorId );
						} );
					}

					if ( document.readyState === 'loading' ) {
						document.addEventListener( 'DOMContentLoaded', wpforms_js_error_loading );
					} else {
						wpforms_js_error_loading();
					}
				}() );
			</script>";
	}

	/**
	 * Get missing assets error message.
	 *
	 * @since 1.6.4.1
	 *
	 * @return string
	 * @noinspection HtmlUnknownTarget
	 */
	private function get_missing_assets_error_message() {

		$message = sprintf(
			wp_kses( /* translators: %s - URL to the troubleshooting guide. */
				__( 'Heads up! WPForms has detected an issue with JavaScript on this page. JavaScript is required for this form to work properly, so this form may not work as expected. See our <a href="%s" target="_blank" rel="noopener noreferrer">troubleshooting guide</a> to learn more or contact support.', 'wpforms-lite' ),
				[
					'a' => [
						'href'   => [],
						'target' => [],
						'rel'    => [],
					],
				]
			),
			'https://wpforms.com/docs/getting-support-wpforms/'
		);

		$message .= '<p>';
		$message .= esc_html__( 'This message is only displayed to site administrators.', 'wpforms-lite' );
		$message .= '</p>';

		return $message;
	}


	/**
	 * Render the single field.
	 *
	 * @since 1.7.7
	 *
	 * @param array $form_data Form data.
	 * @param array $field     Field data.
	 */
	public function render_field( $form_data, $field ) {

		if ( ! has_action( "wpforms_display_field_{$field['type']}" ) ) {
			return;
		}

		/**
		 * Modify Field before render.
		 *
		 * @since 1.4.0
		 *
		 * @param array $field     Current field.
		 * @param array $form_data Form data and settings.
		 */
		$field = (array) apply_filters( 'wpforms_field_data', $field, $form_data ); // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName

		if ( empty( $field ) ) {
			return;
		}

		// Get field attributes. Deprecated; Customizations should use
		// field properties instead.
		$attributes = $this->get_field_attributes( $field, $form_data );

		// Add properties to the field, so it's available everywhere.
		$field['properties'] = $this->get_field_properties( $field, $form_data, $attributes );

		/**
		 * Core actions on this hook:
		 * Priority / Description
		 * 5          Field opening container markup.
		 * 15         Field label.
		 * 20         Field description (depending on position).
		 *
		 * @since 1.3.7
		 *
		 * @param array $field     Field.
		 * @param array $form_data Form data.
		 */
		do_action( 'wpforms_display_field_before', $field, $form_data ); // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName

		/**
		 * Individual field classes use this hook to display the actual
		 * field form elements.
		 * See `field_display` methods in /includes/fields.
		 *
		 * @since 1.3.7
		 *
		 * @param array $field      Field.
		 * @param array $attributes Field attributes.
		 * @param array $form_data  Form data.
		 */
		do_action( "wpforms_display_field_{$field['type']}", $field, $attributes, $form_data ); // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName

		/**
		 * Core actions on this hook:
		 * Priority / Description
		 * 3          Field error messages.
		 * 5          Field description (depending on position).
		 * 15         Field closing container markup.
		 * 20         Pagebreak markup (close previous page, open next).
		 *
		 * @since 1.3.7
		 *
		 * @param array $field     Field.
		 * @param array $form_data Form data.
		 */
		do_action( 'wpforms_display_field_after', $field, $form_data ); // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName
	}
}
