<?php

namespace WPForms\Integrations\Elementor;

use Elementor\Plugin;
use Elementor\Widget_Base;
use Elementor\Controls_Manager;

/**
 * WPForms widget for Elementor page builder.
 *
 * @since 1.6.2
 */
class Widget extends Widget_Base {

	/**
	 * Get widget name.
	 *
	 * Retrieve shortcode widget name.
	 *
	 * @since 1.6.2
	 *
	 * @return string Widget name.
	 */
	public function get_name() {

		return 'wpforms';
	}

	/**
	 * Get widget title.
	 *
	 * Retrieve shortcode widget title.
	 *
	 * @since 1.6.2
	 *
	 * @return string Widget title.
	 */
	public function get_title() {

		return __( 'WPForms', 'wpforms-lite' );
	}

	/**
	 * Get widget icon.
	 *
	 * Retrieve shortcode widget icon.
	 *
	 * @since 1.6.2
	 *
	 * @return string Widget icon.
	 */
	public function get_icon() {

		return 'icon-wpforms';
	}

	/**
	 * Get widget keywords.
	 *
	 * Retrieve the list of keywords the widget belongs to.
	 *
	 * @since 1.6.2
	 *
	 * @return array Widget keywords.
	 */
	public function get_keywords() {

		return [
			'form',
			'forms',
			'wpforms',
			'contact form',
			'sullie',
			'the dude',
		];
	}

	/**
	 * Get widget categories.
	 *
	 * @since 1.6.2
	 *
	 * @return array Widget categories.
	 */
	public function get_categories() {

		return [
			'basic',
		];
	}

	/**
	 * Register widget controls.
	 *
	 * Adds different input fields to allow the user to change and customize the widget settings.
	 *
	 * @since 1.6.2
	 */
	protected function register_controls() { // phpcs:ignore PSR2.Methods.MethodDeclaration.Underscore

		$this->content_controls();
	}

	/**
	 * Register content tab controls.
	 *
	 * @since 1.6.2
	 */
	protected function content_controls() {

		$this->start_controls_section(
			'section_form',
			[
				'label' => esc_html__( 'Form', 'wpforms-lite' ),
				'tab'   => Controls_Manager::TAB_CONTENT,
			]
		);

		$forms = $this->get_forms();

		if ( empty( $forms ) ) {
			$this->add_control(
				'add_form_notice',
				[
					'show_label'      => false,
					'type'            => Controls_Manager::RAW_HTML,
					'raw'             => wp_kses(
						__( '<b>You haven\'t created a form yet.</b><br> What are you waiting for?', 'wpforms-lite' ),
						[
							'b'  => [],
							'br' => [],
						]
					),
					'content_classes' => 'elementor-panel-alert elementor-panel-alert-info',
				]
			);
		}

		$this->add_control(
			'form_id',
			[
				'label'       => esc_html__( 'Form', 'wpforms-lite' ),
				'type'        => Controls_Manager::SELECT,
				'label_block' => true,
				'options'     => $forms,
				'default'     => '0',
			]
		);

		$this->add_control(
			'edit_form',
			[
				'show_label' => false,
				'type'       => Controls_Manager::RAW_HTML,
				'raw'        => wp_kses( /* translators: %s - WPForms documentation link. */
					__( 'Need to make changes? <a href="#">Edit the selected form.</a>', 'wpforms-lite' ),
					[ 'a' => [] ]
				),
				'condition'  => [
					'form_id!' => '0',
				],
			]
		);

		$this->add_control(
			'test_form_notice',
			[
				'show_label'      => false,
				'type'            => Controls_Manager::RAW_HTML,
				'raw'             => sprintf(
					wp_kses( /* translators: %s - WPForms documentation link. */
						__( '<b>Heads up!</b> Don\'t forget to test your form. <a href="%s" target="_blank" rel="noopener noreferrer">Check out our complete guide!</a>', 'wpforms-lite' ),
						[
							'b'  => [],
							'br' => [],
							'a'  => [
								'href'   => [],
								'rel'    => [],
								'target' => [],
							],
						]
					),
					'https://wpforms.com/docs/how-to-properly-test-your-wordpress-forms-before-launching-checklist/'
				),
				'condition'       => [
					'form_id!' => '0',
				],
				'content_classes' => 'elementor-panel-alert elementor-panel-alert-info',
			]
		);

		$this->add_control(
			'add_form_btn',
			[
				'show_label'  => false,
				'label_block' => false,
				'type'        => Controls_Manager::BUTTON,
				'button_type' => 'default',
				'separator'   => 'before',
				'text'        => '<b>+</b>' . esc_html__( 'New form', 'wpforms-lite' ),
				'event'       => 'elementorWPFormsAddFormBtnClick',
			]
		);

		$this->end_controls_section();

		$this->start_controls_section(
			'section_display',
			[
				'label'     => esc_html__( 'Display Options', 'wpforms-lite' ),
				'tab'       => Controls_Manager::TAB_CONTENT,
				'condition' => [
					'form_id!' => '0',
				],
			]
		);

		$this->add_control(
			'display_form_name',
			[
				'label'        => esc_html__( 'Form Name', 'wpforms-lite' ),
				'type'         => Controls_Manager::SWITCHER,
				'label_on'     => esc_html__( 'Show', 'wpforms-lite' ),
				'label_off'    => esc_html__( 'Hide', 'wpforms-lite' ),
				'return_value' => 'yes',
				'condition'    => [
					'form_id!' => '0',
				],
			]
		);

		$this->add_control(
			'display_form_description',
			[
				'label'        => esc_html__( 'Form Description', 'wpforms-lite' ),
				'type'         => Controls_Manager::SWITCHER,
				'label_on'     => esc_html__( 'Show', 'wpforms-lite' ),
				'label_off'    => esc_html__( 'Hide', 'wpforms-lite' ),
				'separator'    => 'after',
				'return_value' => 'yes',
				'condition'    => [
					'form_id!' => '0',
				],
			]
		);

		$this->end_controls_section();
	}

	/**
	 * Render widget output.
	 *
	 * @since 1.6.2
	 */
	protected function render() {

		if ( Plugin::$instance->editor->is_edit_mode() ) {
			$this->render_edit_mode();
		} else {
			$this->render_frontend();
		}
	}

	/**
	 * Render widget output in edit mode.
	 *
	 * @since 1.6.3.1
	 */
	protected function render_edit_mode() {

		$form_id = $this->get_settings_for_display( 'form_id' );

		// Popup markup template.
		echo wpforms_render( 'integrations/elementor/popup' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		if ( count( $this->get_forms() ) < 2 ) {

			// No forms block.
			echo wpforms_render( 'integrations/elementor/no-forms' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

			return;
		}

		if ( empty( $form_id ) ) {

			// Render form selector.
			echo wpforms_render( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				'integrations/elementor/form-selector',
				[
					'forms' => $this->get_form_selector_options(),
				],
				true
			);

			return;
		}

		// Finally, render selected form.
		$this->render_frontend();
	}

	/**
	 * Render widget output on the frontend.
	 *
	 * @since 1.6.3.1
	 */
	protected function render_frontend() {

		static $is_root_vars_displayed = false;

		$css_vars_obj = wpforms()->get( 'css_vars' );

		if ( ! empty( $css_vars_obj ) && wpforms_get_render_engine() === 'modern' && ! $is_root_vars_displayed ) {
			$css_vars_obj->output_root( true );

			$is_root_vars_displayed = true;
		}

		// Render selected form.
		echo do_shortcode( $this->render_shortcode() );
	}

	/**
	 * Render widget as plain content.
	 *
	 * @since 1.6.2
	 */
	public function render_plain_content() {

		echo $this->render_shortcode(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}

	/**
	 * Render shortcode.
	 *
	 * @since 1.6.2
	 */
	public function render_shortcode() {

		return sprintf(
			'[wpforms id="%1$d" title="%2$s" description="%3$s"]',
			absint( $this->get_settings_for_display( 'form_id' ) ),
			sanitize_key( $this->get_settings_for_display( 'display_form_name' ) === 'yes' ? 'true' : 'false' ),
			sanitize_key( $this->get_settings_for_display( 'display_form_description' ) === 'yes' ? 'true' : 'false' )
		);
	}

	/**
	 * Get forms list.
	 *
	 * @since 1.6.2
	 *
	 * @returns array Array of forms.
	 */
	public function get_forms() {

		static $forms_list = [];

		if ( empty( $forms_list ) ) {
			$forms = wpforms()->form->get();

			if ( ! empty( $forms ) ) {
				$forms_list[0] = esc_html__( 'Select a form', 'wpforms-lite' );
				foreach ( $forms as $form ) {
					$forms_list[ $form->ID ] = mb_strlen( $form->post_title ) > 100 ? mb_substr( $form->post_title, 0, 97 ) . '...' : $form->post_title;
				}
			}
		}

		return $forms_list;
	}

	/**
	 * Get form selector options.
	 *
	 * @since 1.6.2
	 *
	 * @returns string Rendered options for the select tag.
	 */
	public function get_form_selector_options() {

		$forms   = $this->get_forms();
		$options = '';

		foreach ( $forms as $form_id => $form ) {
			$options .= sprintf(
				'<option value="%d">%s</option>',
				(int) $form_id,
				esc_html( $form )
			);
		}

		return $options;
	}
}
