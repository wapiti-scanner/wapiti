<?php

namespace WPForms\Integrations\Gutenberg;

use WPForms\Frontend\CSSVars;
use WPForms\Integrations\IntegrationInterface;

/**
 * Form Selector Gutenberg block with live preview.
 *
 * @since 1.4.8
 */
class FormSelector implements IntegrationInterface {

	/**
	 * Default attributes.
	 *
	 * @since 1.8.1
	 *
	 * @var array
	 */
	const DEFAULT_ATTRIBUTES = [
		'formId'                => '',
		'displayTitle'          => false,
		'displayDesc'           => false,
		'fieldSize'             => 'medium',
		'fieldBorderRadius'     => CSSVars::ROOT_VARS['field-border-radius'],
		'fieldBackgroundColor'  => CSSVars::ROOT_VARS['field-background-color'],
		'fieldBorderColor'      => CSSVars::ROOT_VARS['field-border-color'],
		'fieldTextColor'        => CSSVars::ROOT_VARS['field-text-color'],
		'labelSize'             => 'medium',
		'labelColor'            => CSSVars::ROOT_VARS['label-color'],
		'labelSublabelColor'    => CSSVars::ROOT_VARS['label-sublabel-color'],
		'labelErrorColor'       => CSSVars::ROOT_VARS['label-error-color'],
		'buttonSize'            => 'medium',
		'buttonBorderRadius'    => CSSVars::ROOT_VARS['button-border-radius'],
		'buttonBackgroundColor' => CSSVars::ROOT_VARS['button-background-color'],
		'buttonTextColor'       => CSSVars::ROOT_VARS['button-text-color'],
		'copyPasteValue'        => '',
	];

	/**
	 * Render engine.
	 *
	 * @since 1.8.1
	 *
	 * @var string
	 */
	protected $render_engine;

	/**
	 * Disabled CSS setting.
	 *
	 * @since 1.8.1
	 *
	 * @var integer
	 */
	protected $disable_css_setting;

	/**
	 * Instance of CSSVars class.
	 *
	 * @since 1.8.1
	 *
	 * @var CSSVars
	 */
	private $css_vars_obj;

	/**
	 * Callbacks registered for wpforms_frontend_container_class filter.
	 *
	 * @since 1.7.5
	 *
	 * @var array
	 */
	private $callbacks = [];

	/**
	 * Indicate if current integration is allowed to load.
	 *
	 * @since 1.4.8
	 *
	 * @return bool
	 */
	public function allow_load() {

		return function_exists( 'register_block_type' );
	}

	/**
	 * Load an integration.
	 *
	 * @since 1.4.8
	 */
	public function load() {

		$this->render_engine       = wpforms_get_render_engine();
		$this->disable_css_setting = (int) wpforms_setting( 'disable-css', '1' );
		$this->css_vars_obj        = wpforms()->get( 'css_vars' );

		$this->hooks();
	}

	/**
	 * Integration hooks.
	 *
	 * @since 1.4.8
	 */
	protected function hooks() {

		add_action( 'init', [ $this, 'register_block' ] );
		add_action( 'enqueue_block_editor_assets', [ $this, 'enqueue_block_editor_assets' ] );
		add_action( 'wpforms_frontend_output_container_after', [ $this, 'replace_wpforms_frontend_container_class_filter' ] );
	}

	/**
	 * Replace the filter registered for wpforms_frontend_container_class.
	 *
	 * @since 1.7.5
	 *
	 * @param array $form_data Form data.
	 *
	 * @return void
	 */
	public function replace_wpforms_frontend_container_class_filter( $form_data ) { // phpcs:ignore WPForms.PHP.HooksMethod.InvalidPlaceForAddingHooks

		if ( empty( $this->callbacks[ $form_data['id'] ] ) ) {
			return;
		}

		$callback = array_shift( $this->callbacks[ $form_data['id'] ] );

		remove_filter( 'wpforms_frontend_container_class', $callback );

		if ( ! empty( $this->callbacks[ $form_data['id'] ] ) ) {
			add_filter( 'wpforms_frontend_container_class', reset( $this->callbacks[ $form_data['id'] ] ), 10, 2 );
		}
	}

	/**
	 * Register WPForms Gutenberg block on the backend.
	 *
	 * @since 1.4.8
	 */
	public function register_block() {

		$attributes = [
			'clientId'              => [
				'type' => 'string',
			],
			'formId'                => [
				'type' => 'string',
			],
			'displayTitle'          => [
				'type' => 'boolean',
			],
			'displayDesc'           => [
				'type' => 'boolean',
			],
			'className'             => [
				'type' => 'string',
			],
			'fieldSize'             => [
				'type' => 'string',
			],
			'fieldBorderRadius'     => [
				'type' => 'string',
			],
			'fieldBackgroundColor'  => [
				'type' => 'string',
			],
			'fieldBorderColor'      => [
				'type' => 'string',
			],
			'fieldTextColor'        => [
				'type' => 'string',
			],
			'labelSize'             => [
				'type' => 'string',
			],
			'labelColor'            => [
				'type' => 'string',
			],
			'labelSublabelColor'    => [
				'type' => 'string',
			],
			'labelErrorColor'       => [
				'type' => 'string',
			],
			'buttonSize'            => [
				'type' => 'string',
			],
			'buttonBorderRadius'    => [
				'type' => 'string',
			],
			'buttonBackgroundColor' => [
				'type' => 'string',
			],
			'buttonTextColor'       => [
				'type' => 'string',
			],
			'copyPasteValue'        => [
				'type' => 'string',
			],
		];

		$this->register_styles();

		register_block_type(
			'wpforms/form-selector',
			[
				/**
				 * Modify WPForms block attributes.
				 *
				 * @since 1.5.8.2
				 *
				 * @param array $attributes Attributes.
				 */
				'attributes'      => apply_filters( 'wpforms_gutenberg_form_selector_attributes', $attributes ), // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName
				'style'           => 'wpforms-gutenberg-form-selector',
				'editor_style'    => 'wpforms-integrations',
				'render_callback' => [ $this, 'get_form_html' ],
			]
		);
	}

	/**
	 * Register WPForms Gutenberg block styles.
	 *
	 * @since 1.7.4.2
	 */
	protected function register_styles() {

		if ( ! is_admin() ) {
			return;
		}

		$min = wpforms_get_min_suffix();

		wp_register_style(
			'wpforms-integrations',
			WPFORMS_PLUGIN_URL . "assets/css/admin-integrations{$min}.css",
			[],
			WPFORMS_VERSION
		);

		if ( $this->disable_css_setting === 3 ) {
			return;
		}

		$css_file = $this->disable_css_setting === 2 ? 'base' : 'full';

		wp_register_style(
			'wpforms-gutenberg-form-selector',
			WPFORMS_PLUGIN_URL . "assets/css/frontend/{$this->render_engine}/wpforms-{$css_file}{$min}.css",
			[ 'wp-edit-blocks', 'wpforms-integrations' ],
			WPFORMS_VERSION
		);
	}

	/**
	 * Load WPForms Gutenberg block scripts.
	 *
	 * @since 1.4.8
	 */
	public function enqueue_block_editor_assets() {

		$min = wpforms_get_min_suffix();

		wp_enqueue_style( 'wpforms-integrations' );

		$script = version_compare( $GLOBALS['wp_version'], '6.0', '>=' ) ? "formselector.es5{$min}.js" : "formselector-legacy.es5{$min}.js";

		wp_enqueue_script(
			'wpforms-gutenberg-form-selector',
			WPFORMS_PLUGIN_URL . 'assets/js/components/admin/gutenberg/' . $script,
			[ 'wp-blocks', 'wp-i18n', 'wp-element' ],
			WPFORMS_VERSION,
			true
		);

		wp_localize_script(
			'wpforms-gutenberg-form-selector',
			'wpforms_gutenberg_form_selector',
			$this->get_localize_data()
		);

		if ( $this->render_engine === 'modern' ) {
			wp_enqueue_script(
				'wpforms-modern',
				WPFORMS_PLUGIN_URL . "assets/js/wpforms-modern{$min}.js",
				[ 'wpforms-gutenberg-form-selector' ],
				WPFORMS_VERSION,
				true
			);
		}
	}

	/**
	 * Get localize data.
	 *
	 * @since 1.8.1
	 *
	 * @return array
	 */
	private function get_localize_data() {

		$strings = [
			'title'                        => esc_html__( 'WPForms', 'wpforms-lite' ),
			'description'                  => esc_html__( 'Select and display one of your forms.', 'wpforms-lite' ),
			'form_keywords'                => [
				esc_html__( 'form', 'wpforms-lite' ),
				esc_html__( 'contact', 'wpforms-lite' ),
				esc_html__( 'survey', 'wpforms-lite' ),
				'the dude',
			],
			'form_select'                  => esc_html__( 'Select a Form', 'wpforms-lite' ),
			'form_settings'                => esc_html__( 'Form Settings', 'wpforms-lite' ),
			'field_styles'                 => esc_html__( 'Field Styles', 'wpforms-lite' ),
			'label_styles'                 => esc_html__( 'Label Styles', 'wpforms-lite' ),
			'button_styles'                => esc_html__( 'Button Styles', 'wpforms-lite' ),
			'button_color_notice'          => esc_html__( 'Also used for other fields like Multiple Choice, Checkboxes, Rating, and NPS Survey.', 'wpforms-lite' ),
			'advanced'                     => esc_html__( 'Advanced', 'wpforms-lite' ),
			'additional_css_classes'       => esc_html__( 'Additional CSS Classes', 'wpforms-lite' ),
			'form_selected'                => esc_html__( 'Form', 'wpforms-lite' ),
			'show_title'                   => esc_html__( 'Show Title', 'wpforms-lite' ),
			'show_description'             => esc_html__( 'Show Description', 'wpforms-lite' ),
			'panel_notice_head'            => esc_html__( 'Heads up!', 'wpforms-lite' ),
			'panel_notice_text'            => esc_html__( 'Do not forget to test your form.', 'wpforms-lite' ),
			'panel_notice_link'            => esc_url( wpforms_utm_link( 'https://wpforms.com/docs/how-to-properly-test-your-wordpress-forms-before-launching-checklist/', 'gutenberg' ) ),
			'panel_notice_link_text'       => esc_html__( 'Check out our complete guide!', 'wpforms-lite' ),
			'update_wp_notice_head'        => esc_html__( 'Want to customize your form styles without editing CSS?', 'wpforms-lite' ),
			'update_wp_notice_text'        => esc_html__( 'Update WordPress to the latest version to use our modern markup and unlock the controls below.', 'wpforms-lite' ),
			'update_wp_notice_link'        => esc_url( wpforms_utm_link( 'https://wpforms.com/docs/styling-your-forms/', 'Block Settings', 'Form Styles Documentation' ) ),
			'learn_more'                   => esc_html__( 'Learn more', 'wpforms-lite' ),
			'use_modern_notice_head'       => esc_html__( 'Want to customize your form styles without editing CSS?', 'wpforms-lite' ),
			'use_modern_notice_text'       => esc_html__( 'Enable modern markup in your WPForms settings to unlock the controls below.', 'wpforms-lite' ),
			'use_modern_notice_link'       => esc_url( wpforms_utm_link( 'https://wpforms.com/docs/styling-your-forms/', 'Block Settings', 'Form Styles Documentation' ) ),
			'lead_forms_panel_notice_head' => esc_html__( 'Form Styles are disabled because Lead Form Mode is turned on.', 'wpforms-lite' ),
			'lead_forms_panel_notice_text' => esc_html__( 'To change the styling for this form, open it in the form builder and edit the options in the Lead Forms settings.', 'wpforms-lite' ),
			'size'                         => esc_html__( 'Size', 'wpforms-lite' ),
			'background'                   => esc_html__( 'Background', 'wpforms-lite' ),
			'border'                       => esc_html__( 'Border', 'wpforms-lite' ),
			'text'                         => esc_html__( 'Text', 'wpforms-lite' ),
			'border_radius'                => esc_html__( 'Border Radius', 'wpforms-lite' ),
			'colors'                       => esc_html__( 'Colors', 'wpforms-lite' ),
			'label'                        => esc_html__( 'Label', 'wpforms-lite' ),
			'sublabel_hints'               => esc_html__( 'Sublabel & Hint', 'wpforms-lite' ),
			'error_message'                => esc_html__( 'Error Message', 'wpforms-lite' ),
			'small'                        => esc_html__( 'Small', 'wpforms-lite' ),
			'medium'                       => esc_html__( 'Medium', 'wpforms-lite' ),
			'large'                        => esc_html__( 'Large', 'wpforms-lite' ),
			'reset_style_settings'         => esc_html__( 'Reset Style Settings', 'wpforms-lite' ),
			'reset_settings_confirm_text'  => esc_html__( 'Are you sure you want to reset the style settings for this form? All your current styling will be removed and canʼt be recovered.', 'wpforms-lite' ),
			'btn_yes_reset'                => esc_html__( 'Yes, Reset', 'wpforms-lite' ),
			'btn_no'                       => esc_html__( 'No', 'wpforms-lite' ),
			'copy_paste_settings'          => esc_html__( 'Copy / Paste Style Settings', 'wpforms-lite' ),
			'copy_paste_error'             => esc_html__( 'There was an error parsing your JSON code. Please check your code and try again.', 'wpforms-lite' ),
			'copy_paste_notice'            => esc_html__( 'If you\'ve copied style settings from another form, you can paste them here to add the same styling to this form. Any current style settings will be overwritten.', 'wpforms-lite' ),
		];

		if ( version_compare( $GLOBALS['wp_version'], '5.1.1', '<=' ) ) {
			array_pop( $strings['form_keywords'] );
		}

		$forms = wpforms()->get( 'form' )->get( '', [ 'order' => 'DESC' ] );
		$forms = ! empty( $forms ) ? $forms : [];
		$forms = array_map(
			static function( $form ) {

				$form->post_title = htmlspecialchars_decode( $form->post_title, ENT_QUOTES );

				return $form;
			},
			$forms
		);

		return [
			'logo_url'          => WPFORMS_PLUGIN_URL . 'assets/images/sullie-alt.png',
			'block_preview_url' => WPFORMS_PLUGIN_URL . 'assets/images/integrations/gutenberg/block-preview.png',
			'wpnonce'           => wp_create_nonce( 'wpforms-gutenberg-form-selector' ),
			'forms'             => $forms,
			'strings'           => $strings,
			'defaults'          => self::DEFAULT_ATTRIBUTES,
			'is_modern_markup'  => $this->render_engine === 'modern',
			'is_full_styling'   => $this->disable_css_setting === 1,
			'sizes'             => [
				'field-size'  => CSSVars::FIELD_SIZE,
				'label-size'  => CSSVars::LABEL_SIZE,
				'button-size' => CSSVars::BUTTON_SIZE,
			],
		];
	}

	/**
	 * Get form HTML to display in a WPForms Gutenberg block.
	 *
	 * @since 1.4.8
	 *
	 * @param array $attr Attributes passed by WPForms Gutenberg block.
	 *
	 * @return string
	 */
	public function get_form_html( $attr ) {

		$id = ! empty( $attr['formId'] ) ? absint( $attr['formId'] ) : 0;

		if ( empty( $id ) ) {
			return '';
		}

		$title        = ! empty( $attr['displayTitle'] );
		$desc         = ! empty( $attr['displayDesc'] );
		$is_gb_editor = $this->is_gb_editor();

		if ( $is_gb_editor ) {
			$this->disable_fields_in_gb_editor();
		}

		$this->add_class_callback( $id, $attr );

		$content = $this->get_content( $id, $title, $desc, $attr );

		// phpcs:disable WPForms.PHP.ValidateHooks.InvalidHookName

		/**
		 * Filter Gutenberg block content.
		 *
		 * @since 1.5.8.2
		 *
		 * @param string $content Block content.
		 * @param int    $id      Form id.
		 */
		return apply_filters( 'wpforms_gutenberg_block_form_content', $content, $id );

		// phpcs:enable WPForms.PHP.ValidateHooks.InvalidHookName
	}

	/**
	 * Add class callback.
	 *
	 * @since 1.8.1
	 *
	 * @param int   $id   Form id.
	 * @param array $attr Form attributes.
	 *
	 * @return void
	 */
	private function add_class_callback( $id, $attr ) { // phpcs:ignore WPForms.PHP.HooksMethod.InvalidPlaceForAddingHooks

		$class_callback = static function ( $classes, $form_data ) use ( $id, $attr ) {

			if ( (int) $form_data['id'] !== $id ) {
				return $classes;
			}

			$cls = [];

			// Add custom class to form container.
			if ( ! empty( $attr['className'] ) ) {
				$cls = array_map( 'esc_attr', explode( ' ', $attr['className'] ) );
			}

			// Add classes to identify that the form displays inside the block.
			$cls[] = 'wpforms-block';

			if ( ! empty( $attr['clientId'] ) ) {
				$cls[] = 'wpforms-block-' . $attr['clientId'];
			}

			return array_unique( array_merge( $classes, $cls ) );
		};

		if ( empty( $this->callbacks[ $id ] ) ) {
			add_filter( 'wpforms_frontend_container_class', $class_callback, 10, 2 );
		}

		$this->callbacks[ $id ][] = $class_callback;
	}

	/**
	 * Get content.
	 *
	 * @since 1.8.1
	 *
	 * @param int   $id    Form id.
	 * @param bool  $title Form title is not empty.
	 * @param bool  $desc  Form desc is not empty.
	 * @param array $attr  Form attributes.
	 *
	 * @return string
	 */
	private function get_content( $id, $title, $desc, $attr ) {

		ob_start();

		// phpcs:disable WPForms.PHP.ValidateHooks.InvalidHookName

		/**
		 * Fires before Gutenberg block output.
		 *
		 * @since 1.5.8.2
		 */
		do_action( 'wpforms_gutenberg_block_before' );

		/**
		 * Filter block title display flag.
		 *
		 * @since 1.5.8.2
		 *
		 * @param bool $title Title display flag.
		 * @param int  $id    Form id.
		 */
		$title = apply_filters( 'wpforms_gutenberg_block_form_title', $title, $id );

		/**
		 * Filter block description display flag.
		 *
		 * @since 1.5.8.2
		 *
		 * @param bool $desc Description display flag.
		 * @param int  $id   Form id.
		 */
		$desc = apply_filters( 'wpforms_gutenberg_block_form_desc', $desc, $id );

		$this->output_css_vars( $attr );

		$is_gb_editor = $this->is_gb_editor();

		if ( $is_gb_editor ) {
			wpforms_display(
				$id,
				$title,
				$desc
			);
		} else {
			printf(
				'[wpforms id="%s" title="%d" description="%d"]',
				(int) $id,
				(bool) $title,
				(bool) $desc
			);
		}

		/**
		 * Fires after Gutenberg block output.
		 *
		 * @since 1.5.8.2
		 */
		do_action( 'wpforms_gutenberg_block_after' );

		// phpcs:enable WPForms.PHP.ValidateHooks.InvalidHookName

		$content = ob_get_clean();

		if ( ! $is_gb_editor ) {
			return $content;
		}

		if ( empty( $content ) ) {
			return '<div class="components-placeholder"><div class="components-placeholder__label"></div>' .
			           '<div class="components-placeholder__fieldset">' .
			           esc_html__( 'The form cannot be displayed.', 'wpforms-lite' ) .
			           '</div></div>';
		}

		// phpcs:disable WordPress.PHP.DevelopmentFunctions.error_log_var_export
		// Unfortunately, the inline <script> tag doesn't execute in GB editor.
		// This is the hacky way to trigger custom event on form loaded in the Block Editor / GB / FSE.
		$content .= sprintf(
			'<img src="data:image/gif;base64,R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==" onLoad="
				window.top.dispatchEvent( 
                    new CustomEvent(
						\'wpformsFormSelectorFormLoaded\',
						{
							detail: {
								formId: %1$s,
								title: %2$s,
								desc: %3$s,
								block: this.closest( \'.wp-block\' )
							}
						}
					)
				);
			" class="wpforms-pix-trigger" alt="">',
			absint( $id ),
			var_export( (bool) $title, true ),
			var_export( (bool) $desc, true )
		);

		// phpcs:enable WordPress.PHP.DevelopmentFunctions.error_log_var_export

		return $content;
	}

	/**
	 * Checking if is Gutenberg REST API call.
	 *
	 * @since 1.5.7
	 *
	 * @return bool True if is Gutenberg REST API call.
	 */
	public function is_gb_editor() {

		// TODO: Find a better way to check if is GB editor API call.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return defined( 'REST_REQUEST' ) && REST_REQUEST && ! empty( $_REQUEST['context'] ) && $_REQUEST['context'] === 'edit';
	}

	/**
	 * Disable form fields if called from the Gutenberg editor.
	 *
	 * @since 1.7.5
	 *
	 * @return void
	 */
	private function disable_fields_in_gb_editor() { // phpcs:ignore WPForms.PHP.HooksMethod.InvalidPlaceForAddingHooks

		add_filter(
			'wpforms_frontend_container_class',
			static function ( $classes ) {

				$classes[] = 'wpforms-gutenberg-form-selector';

				return $classes;
			}
		);
		add_action(
			'wpforms_frontend_output',
			static function () {

				echo '<fieldset disabled>';
			},
			3
		);
		add_action(
			'wpforms_frontend_output',
			static function () {

				echo '</fieldset>';
			},
			30
		);
	}

	/**
	 * Output CSS variables for the particular form.
	 *
	 * @since 1.8.1
	 *
	 * @param array $attr Attributes passed by WPForms Gutenberg block.
	 */
	private function output_css_vars( $attr ) {

		if ( empty( $this->css_vars_obj ) || ! method_exists( $this->css_vars_obj, 'get_vars' ) ) {
			return;
		}

		$this->css_vars_obj->output_root();

		if ( $this->render_engine === 'classic' || $this->disable_css_setting !== 1 ) {
			return;
		}

		$css_vars = $this->get_customized_css_vars( $attr );

		if ( empty( $css_vars ) ) {
			return;
		}

		$style_id = "#wpforms-css-vars-{$attr['formId']}-block-{$attr['clientId']}";

		/**
		 * Filter the CSS selector for output CSS variables for styling the GB block form.
		 *
		 * @since 1.8.1
		 *
		 * @param string $selector The CSS selector for output CSS variables for styling the GB block form.
		 * @param array  $attr     Attributes passed by WPForms Gutenberg block.
		 * @param array  $css_vars CSS variables data.
		 */
		$vars_selector = apply_filters(
			'wpforms_integrations_gutenberg_form_selector_output_css_vars_selector',
			"#wpforms-{$attr['formId']}.wpforms-block-{$attr['clientId']}",
			$attr,
			$css_vars
		);

		$this->css_vars_obj->output_selector_vars( $vars_selector, $css_vars, $style_id );
	}

	/**
	 * Get customized CSS vars.
	 *
	 * @since 1.8.1
	 *
	 * @param array $attr Attributes passed by WPForms Gutenberg block.
	 *
	 * @return array
	 */
	private function get_customized_css_vars( $attr ) { // phpcs:ignore Generic.Metrics.CyclomaticComplexity.TooHigh

		if ( empty( $this->css_vars_obj ) || ! method_exists( $this->css_vars_obj, 'get_vars' ) ) {
			return [];
		}

		$root_css_vars = $this->css_vars_obj->get_vars( ':root' );
		$css_vars      = [];

		foreach ( $attr as $key => $value ) {

			$var_name = strtolower( preg_replace( '/[A-Z]/', '-$0', $key ) );

			// Skip attribute that is not the CSS var.
			if ( empty( $root_css_vars[ $var_name ] ) ) {
				continue;
			}

			// We do not need to output variable that has the default value.
			if ( $root_css_vars[ $var_name ] === $value ) {
				continue;
			}

			$css_vars[ $var_name ] = $value;
		}

		if ( ! empty( $attr['fieldSize'] ) && $attr['fieldSize'] !== 'medium' ) {
			$css_vars = array_merge(
				$css_vars,
				$this->css_vars_obj->get_complex_vars( 'field-size', CSSVars::FIELD_SIZE[ $attr['fieldSize'] ] )
			);
		}

		if ( ! empty( $attr['labelSize'] ) && $attr['labelSize'] !== 'medium' ) {
			$css_vars = array_merge(
				$css_vars,
				$this->css_vars_obj->get_complex_vars( 'label-size', CSSVars::LABEL_SIZE[ $attr['labelSize'] ] )
			);
		}

		if ( ! empty( $attr['buttonSize'] ) && $attr['buttonSize'] !== 'medium' ) {
			$css_vars = array_merge(
				$css_vars,
				$this->css_vars_obj->get_complex_vars( 'button-size', CSSVars::BUTTON_SIZE[ $attr['buttonSize'] ] )
			);
		}

		return $css_vars;
	}
}
