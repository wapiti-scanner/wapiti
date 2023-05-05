<?php

namespace WPForms\Frontend;

/**
 * Modern render engine class.
 *
 * @since 1.8.1
 */
class Modern extends Classic {

	/**
	 * Hooks.
	 *
	 * @since 1.8.1
	 */
	public function hooks() {

		add_filter( 'wpforms_field_properties', [ $this, 'field_properties' ], 10, 3 );
		add_filter( 'wpforms_get_field_required_label', [ $this, 'get_field_required_label' ], 10 );
		add_filter( 'wpforms_frontend_strings', [ $this, 'frontend_strings' ], 10 );
	}

	/**
	 * Open form container.
	 *
	 * @since 1.8.1
	 *
	 * @param string $classes   Form container classes.
	 * @param array  $form_data Form data.
	 */
	public function form_container_open( $classes, $form_data ) {

		$classes[] = 'wpforms-render-modern';

		parent::form_container_open( $classes, $form_data );
	}

	/**
	 * Noscript message.
	 *
	 * @since 1.8.1
	 *
	 * @param string $msg Noscript message.
	 */
	public function noscript( $msg ) {

		printf(
			'<noscript class="wpforms-error-noscript">%1$s</noscript><div class="wpforms-hidden" id="wpforms-error-noscript">%1$s</div>',
			esc_html( $msg )
		);
	}

	/**
	 * Display form error.
	 *
	 * @since 1.8.1
	 *
	 * @param string $type  Error type.
	 * @param string $error Error text.
	 */
	public function form_error( $type, $error ) {

		switch ( $type ) {
			case 'header':
			case 'footer':
				printf(
					'<div id="wpforms-%1$s-%2$s-error" class="wpforms-error-container" role="alert">
						<span class="wpforms-hidden" aria-hidden="false">%3$s</span>%4$s
					</div>',
					esc_attr( $this->form_data['id'] ),
					esc_attr( $type ),
					esc_html__( 'Form error message', 'wpforms-lite' ),
					wpautop( wpforms_sanitize_error( $error ) ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				);
				break;

			case 'recaptcha':
				printf(
					'<em id="wpforms-field_recaptcha-error" class="wpforms-error" role="alert">
						<span class="wpforms-hidden" aria-hidden="false">%1$s</span>%2$s
					</em>',
					esc_attr__( 'Recaptcha error message', 'wpforms-lite' ),
					wpforms_sanitize_error( $error ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				);
				break;
		}
	}

	/**
	 * Field label markup.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field     Field data and settings.
	 * @param array $form_data Form data and settings.
	 */
	public function field_label( $field, $form_data ) {

		// Do not need to output label if the field requires fieldset.
		if ( $this->is_field_requires_fieldset( $field ) ) {
			return;
		}

		if ( ! empty( $field['label_hide'] ) ) {
			$field['properties']['label']['attr']['aria-hidden'] = 'false';
		}

		parent::field_label( $field, $form_data );
	}

	/**
	 * Open fieldset markup.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field     Field data and settings.
	 * @param array $form_data Form data and settings.
	 */
	public function field_fieldset_open( $field, $form_data ) {

		if ( ! $this->is_field_requires_fieldset( $field ) ) {
			return;
		}

		if ( ! empty( $field['label_hide'] ) ) {
			$field['properties']['label']['attr']['aria-hidden'] = 'false';
		}

		$label    = $field['properties']['label'];
		$required = $label['required'] ? wpforms_get_field_required_label() : '';

		unset( $label['attr']['for'] );

		printf(
			'<fieldset><legend %s>%s%s</legend>',
			wpforms_html_attributes( $label['id'], $label['class'], $label['data'], $label['attr'] ),
			esc_html( $label['value'] ),
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			$required
		);
	}

	/**
	 * Close fieldset markup.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field     Field data and settings.
	 * @param array $form_data Form data and settings.
	 */
	public function field_fieldset_close( $field, $form_data ) {

		if ( ! $this->is_field_requires_fieldset( $field ) ) {
			return;
		}

		echo '</fieldset>';
	}

	/**
	 * Whether the field requires fieldset markup.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field Field data and settings.
	 */
	private function is_field_requires_fieldset( $field ) {

		if ( empty( $field['type'] ) ) {
			return false;
		}

		/**
		 * Determine whether the field is requires fieldset+legend markup on the frontend.
		 *
		 * @since 1.8.1
		 *
		 * @param bool  $requires_fieldset True if requires. Defaults to false.
		 * @param array $field             Field data.
		 */
		return (bool) apply_filters( "wpforms_frontend_modern_is_field_requires_fieldset_{$field['type']}", false, $field );
	}

	/**
	 * Field error.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field     Field data and settings.
	 * @param array $form_data Form data and settings.
	 *
	 * @noinspection HtmlUnknownAttribute
	 */
	public function field_error( $field, $form_data ) {

		if ( empty( $field['properties']['error'] ) ) {
			return;
		}

		$error = $field['properties']['error'];

		printf(
			'<em %1$s>%2$s</em>',
			wpforms_html_attributes( $error['id'], $error['class'], $error['data'], $error['attr'] ),
			esc_html( $error['value'] )
		);
	}

	/**
	 * Define additional field properties.
	 *
	 * @since 1.8.1
	 *
	 * @param array $properties Field properties.
	 * @param array $field      Field settings.
	 * @param array $form_data  Form data and settings.
	 *
	 * @return array
	 */
	public function field_properties( $properties, $field, $form_data ) {

		$field_id = "wpforms-{$form_data['id']}-field_{$field['id']}";
		$desc_id  = "{$field_id}-description";

		// Add `id` to field description.
		$properties['description']['id'] = $desc_id;

		// Add attributes to error message.
		$properties['error']['attr']['role']       = 'alert';
		$properties['error']['attr']['aria-label'] = esc_html__( 'Error message', 'wpforms-lite' );
		$properties['error']['attr']['id']         = $properties['error']['attr']['for'] . '-error';
		$properties['error']['attr']['for']        = '';

		foreach ( $properties['inputs'] as $input => $input_data ) {

			// Add `aria-errormessage` to inputs.
			$properties['inputs'][ $input ]['attr']['aria-errormessage'] = "{$input_data['id']}-error";

			// Add `aria-describedby` to inputs.
			if ( ! empty( $field['description'] ) ) {
				$properties['inputs'][ $input ]['attr']['aria-describedby'] = $desc_id;
			}
		}

		return $properties;
	}

	/**
	 * Required label (asterisk) markup.
	 *
	 * @since 1.8.1
	 *
	 * @param string $label_html Required label markup.
	 *
	 * @return string
	 */
	public function get_field_required_label( $label_html ) {

		return ' <span class="wpforms-required-label" aria-hidden="true">*</span>';
	}

	/**
	 * Modify javascript `wpforms_settings` properties on the front end.
	 *
	 * @since 1.8.1
	 *
	 * @param array $strings Array `wpforms_settings` properties.
	 *
	 * @return array
	 */
	public function frontend_strings( $strings ) {

		$strings['isModernMarkupEnabled']  = wpforms_get_render_engine() === 'modern';
		$strings['formErrorMessagePrefix'] = esc_html__( 'Form error message', 'wpforms-lite' );
		$strings['errorMessagePrefix']     = esc_html__( 'Error message', 'wpforms-lite' );
		$strings['submitBtnDisabled']      = esc_html__( 'Submit button is disabled during form submission.', 'wpforms-lite' );

		return $strings;
	}
}
