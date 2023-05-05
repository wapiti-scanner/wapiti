<?php

/**
 * Number Slider field.
 *
 * @since 1.5.7
 */
class WPForms_Field_Number_Slider extends WPForms_Field {

	/**
	 * Default minimum value of the field.
	 *
	 * @since 1.5.7
	 */
	const SLIDER_MIN = 0;

	/**
	 * Default maximum value of the field.
	 *
	 * @since 1.5.7
	 */
	const SLIDER_MAX = 10;

	/**
	 * Default step value of the field.
	 *
	 * @since 1.5.7
	 */
	const SLIDER_STEP = 1;

	/**
	 * Primary class constructor.
	 *
	 * @since 1.5.7
	 */
	public function init() {

		// Define field type information.
		$this->name  = esc_html__( 'Number Slider', 'wpforms-lite' );
		$this->type  = 'number-slider';
		$this->icon  = 'fa-sliders';
		$this->order = 180;

		// Customize value format for HTML emails.
		add_filter( 'wpforms_html_field_value', [ $this, 'html_email_value' ], 10, 4 );

		// Builder strings.
		add_filter( 'wpforms_builder_strings', [ $this, 'add_builder_strings' ] );
	}

	/**
	 * Add Builder strings.
	 *
	 * @since 1.6.2.3
	 *
	 * @param array $strings Form Builder strings.
	 *
	 * @return array Form Builder strings.
	 */
	public function add_builder_strings( $strings ) {

		$strings['error_number_slider_increment'] = esc_html__( 'Increment value should be greater than zero. Decimal fractions allowed.', 'wpforms-lite' );

		return $strings;
	}

	/**
	 * Customize format for HTML email notifications.
	 *
	 * @since 1.5.7
	 *
	 * @param string $val       Field value.
	 * @param array  $field     Field settings.
	 * @param array  $form_data Form data and settings.
	 * @param string $context   Value display context.
	 *
	 * @return string
	 */
	public function html_email_value( $val, $field, $form_data = [], $context = '' ) {

		if ( empty( $field['value_raw'] ) || $field['type'] !== $this->type ) {
			return $val;
		}

		$value = isset( $field['value_raw']['value'] ) ? (float) $field['value_raw']['value'] : 0;
		$min   = isset( $field['value_raw']['min'] ) ? (float) $field['value_raw']['min'] : self::SLIDER_MIN;
		$max   = isset( $field['value_raw']['max'] ) ? (float) $field['value_raw']['max'] : self::SLIDER_MAX;

		$html_value = $value;
		if ( strpos( $field['value_raw']['value_display'], '{value}' ) !== false ) {
			$html_value = str_replace(
				'{value}',
				/* translators: %1$s - Number slider selected value; %2$s - its minimum value; %3$s - its maximum value. */
				sprintf( esc_html__( '%1$s (%2$s min / %3$s max)', 'wpforms-lite' ), $value, $min, $max ),
				$field['value_raw']['value_display']
			);
		}

		return $html_value;
	}

	/**
	 * Field options panel inside the builder.
	 *
	 * @since 1.5.7
	 *
	 * @param array $field Field settings.
	 */
	public function field_options( $field ) {
		/*
		 * Basic field options.
		 */

		// Options open markup.
		$args = [
			'markup' => 'open',
		];

		$this->field_option( 'basic-options', $field, $args );

		// Label.
		$this->field_option( 'label', $field );

		// Description.
		$this->field_option( 'description', $field );

		// Required toggle disabled.
		$this->field_element(
			'text',
			$field,
			[
				'slug'  => 'required',
				'value' => '',
				'type'  => 'hidden',
			]
		);

		// Value: min/max.
		$lbl = $this->field_element(
			'label',
			$field,
			[
				'slug'    => 'value',
				'value'   => esc_html__( 'Value', 'wpforms-lite' ),
				'tooltip' => esc_html__( 'Define the minimum and the maximum values for the slider.', 'wpforms-lite' ),
			],
			false
		);

		$min = $this->field_element(
			'text',
			$field,
			[
				'type'  => 'number',
				'slug'  => 'min',
				'class' => 'wpforms-number-slider-min',
				'value' => ! empty( $field['min'] ) ? (float) $field['min'] : self::SLIDER_MIN,
			],
			false
		);

		$max = $this->field_element(
			'text',
			$field,
			[
				'type'  => 'number',
				'slug'  => 'max',
				'class' => 'wpforms-number-slider-max',
				'value' => ! empty( $field['max'] ) ? (float) $field['max'] : self::SLIDER_MAX,
			],
			false
		);

		$this->field_element(
			'row',
			$field,
			[
				'slug'    => 'min_max',
				'content' => $lbl . wpforms_render(
					'fields/number-slider/builder-option-min-max',
					[
						'label'     => $lbl,
						'input_min' => $min,
						'input_max' => $max,
						'field_id'  => $field['id'],
					],
					true
				),
			]
		);

		// Options close markup.
		$args = [
			'markup' => 'close',
		];

		$this->field_option( 'basic-options', $field, $args );

		/*
		 * Advanced field options.
		 */

		// Options open markup.
		$args = [
			'markup' => 'open',
		];

		$this->field_option( 'advanced-options', $field, $args );

		// Size.
		$this->field_option( 'size', $field );

		// Default value.
		$lbl = $this->field_element(
			'label',
			$field,
			[
				'slug'    => 'default_value',
				'value'   => esc_html__( 'Default Value', 'wpforms-lite' ),
				'tooltip' => esc_html__( 'Enter a default value for this field.', 'wpforms-lite' ),
			],
			false
		);

		$fld = $this->field_element(
			'text',
			$field,
			[
				'type'  => 'number',
				'slug'  => 'default_value',
				'class' => 'wpforms-number-slider-default-value',
				'value' => ! empty( $field['default_value'] ) ? (float) $field['default_value'] : 0,
				'attrs' => [
					'min'  => isset( $field['min'] ) && is_numeric( $field['min'] ) ? (float) $field['min'] : self::SLIDER_MIN,
					'max'  => isset( $field['max'] ) && is_numeric( $field['max'] ) ? (float) $field['max'] : self::SLIDER_MAX,
					'step' => isset( $field['step'] ) && is_numeric( $field['step'] ) ? (float) $field['step'] : self::SLIDER_STEP,
				],
			],
			false
		);

		$this->field_element(
			'row',
			$field,
			[
				'slug'    => 'default_value',
				'content' => $lbl . $fld,
			]
		);

		// Value display.
		$lbl = $this->field_element(
			'label',
			$field,
			[
				'slug'    => 'value_display',
				'value'   => esc_html__( 'Value Display', 'wpforms-lite' ),
				'tooltip' => esc_html__( 'Displays the currently selected value below the slider.', 'wpforms-lite' ),
			],
			false
		);

		$fld = $this->field_element(
			'text',
			$field,
			[
				'slug'  => 'value_display',
				'class' => 'wpforms-number-slider-value-display',
				'value' => isset( $field['value_display'] ) ? $field['value_display'] : $this->get_default_display_value(),
			],
			false
		);

		$this->field_element(
			'row',
			$field,
			[
				'slug'    => 'value_display',
				'content' => $lbl . $fld,
			]
		);

		// Steps.
		$lbl = $this->field_element(
			'label',
			$field,
			[
				'slug'    => 'step',
				'value'   => esc_html__( 'Increment', 'wpforms-lite' ),
				'tooltip' => esc_html__( 'Determines the increment between selectable values on the slider.', 'wpforms-lite' ),
			],
			false
		);

		$fld = $this->field_element(
			'text',
			$field,
			[
				'type'  => 'number',
				'slug'  => 'step',
				'class' => 'wpforms-number-slider-step',
				'value' => ! empty( $field['step'] ) ? abs( $field['step'] ) : self::SLIDER_STEP,
				'attrs' => [
					'min' => 0,
					'max' => isset( $field['max'] ) && is_numeric( $field['max'] ) ? abs( (float) $field['max'] ) : self::SLIDER_MAX,
				],
			],
			false
		);

		$this->field_element(
			'row',
			$field,
			[
				'slug'    => 'step',
				'content' => $lbl . $fld,
			]
		);

		// Custom CSS classes.
		$this->field_option( 'css', $field );

		// Hide label.
		$this->field_option( 'label_hide', $field );

		// Options close markup.
		$args = [
			'markup' => 'close',
		];

		$this->field_option( 'advanced-options', $field, $args );
	}

	/**
	 * Get default display value.
	 *
	 * @since 1.7.1
	 *
	 * @return string
	 */
	private function get_default_display_value() {

		return sprintf( /* translators: %s - value. */
			esc_html__( 'Selected Value: %s', 'wpforms-lite' ),
			'{value}'
		);
	}

	/**
	 * Field preview inside the builder.
	 *
	 * @since 1.5.7
	 *
	 * @param array $field Field data.
	 */
	public function field_preview( $field ) {

		// Label.
		$this->field_preview_option( 'label', $field );

		$value_display = isset( $field['value_display'] ) ? esc_attr( $field['value_display'] ) : $this->get_default_display_value();
		$default_value = ! empty( $field['default_value'] ) ? (float) $field['default_value'] : 0;

		echo wpforms_render( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			'fields/number-slider/builder-preview',
			[
				'min'           => isset( $field['min'] ) && is_numeric( $field['min'] ) ? (float) $field['min'] : self::SLIDER_MIN,
				'max'           => isset( $field['max'] ) && is_numeric( $field['max'] ) ? (float) $field['max'] : self::SLIDER_MAX,
				'step'          => isset( $field['step'] ) && is_numeric( $field['step'] ) ? (float) $field['step'] : self::SLIDER_STEP,
				'value_display' => $value_display,
				'default_value' => $default_value,
				'value_hint'    => str_replace( '{value}', '<b>' . $default_value . '</b>', wp_kses( $value_display, wpforms_builder_preview_get_allowed_tags() ) ),
				'field_id'      => $field['id'],
			],
			true
		);

		// Description.
		$this->field_preview_option( 'description', $field );
	}

	/**
	 * Field display on the form front-end.
	 *
	 * @since 1.5.7
	 *
	 * @param array $field      Field data and settings.
	 * @param array $deprecated Deprecated field attributes. Use $field['properties'] instead.
	 * @param array $form_data  Form data and settings.
	 */
	public function field_display( $field, $deprecated, $form_data ) {

		// Define data.
		$primary = $field['properties']['inputs']['primary'];

		$value_display = isset( $field['value_display'] ) ? esc_attr( $field['value_display'] ) : esc_html__( 'Selected Value: {value}', 'wpforms-lite' );
		$default_value = ! empty( $field['default_value'] ) ? (float) $field['default_value'] : 0;
		$hint_value    = ! empty( $primary['attr']['value'] ) ? (float) $primary['attr']['value'] : $default_value;

		$hint = str_replace( '{value}', '<b>' . $hint_value . '</b>', $value_display );

		// phpcs:ignore
		echo wpforms_render(
			'fields/number-slider/frontend',
			[
				'atts'          => $primary['attr'],
				'class'         => $primary['class'],
				'datas'         => $primary['data'],
				'default_value' => $default_value,
				'id'            => $primary['id'],
				'max'           => isset( $field['max'] ) && is_numeric( $field['max'] ) ? (float) $field['max'] : self::SLIDER_MAX,
				'min'           => isset( $field['min'] ) && is_numeric( $field['min'] ) ? (float) $field['min'] : self::SLIDER_MIN,
				'required'      => $primary['required'],
				'step'          => isset( $field['step'] ) && is_numeric( $field['step'] ) ? (float) $field['step'] : self::SLIDER_STEP,
				'value_display' => $value_display,
				'value_hint'    => $hint,
			],
			true
		);
	}

	/**
	 * Validate field on form submit.
	 *
	 * @since 1.5.7
	 *
	 * @param int              $field_id     Field ID.
	 * @param int|float|string $field_submit Submitted field value.
	 * @param array            $form_data    Form data and settings.
	 */
	public function validate( $field_id, $field_submit, $form_data ) {

		$form_id = $form_data['id'];

		$field_submit = (float) $this->sanitize_value( $field_submit );

		// Basic required check - if field is marked as required, check for entry data.
		if (
			! empty( $form_data['fields'][ $field_id ]['required'] ) &&
			empty( $field_submit ) &&
			(string) $field_submit !== '0'
		) {
			wpforms()->process->errors[ $form_id ][ $field_id ] = wpforms_get_required_label();
		}

		// Check if value is numeric.
		if ( ! empty( $field_submit ) && ! is_numeric( $field_submit ) ) {
			wpforms()->process->errors[ $form_id ][ $field_id ] = apply_filters( 'wpforms_valid_number_label', esc_html__( 'Please provide a valid value.', 'wpforms-lite' ) );
		}
	}

	/**
	 * Format and sanitize field.
	 *
	 * @since 1.5.7
	 *
	 * @param int              $field_id     Field ID.
	 * @param int|string|float $field_submit Submitted field value.
	 * @param array            $form_data    Form data and settings.
	 */
	public function format( $field_id, $field_submit, $form_data ) {

		// Define data.
		$name  = ! empty( $form_data['fields'][ $field_id ]['label'] ) ? $form_data['fields'][ $field_id ]['label'] : '';
		$value = (float) $this->sanitize_value( $field_submit );

		$value_raw = [
			'value'         => $value,
			'min'           => (float) $form_data['fields'][ $field_id ]['min'],
			'max'           => (float) $form_data['fields'][ $field_id ]['max'],
			'value_display' => wp_kses_post( $form_data['fields'][ $field_id ]['value_display'] ),
		];

		// Set final field details.
		wpforms()->process->fields[ $field_id ] = [
			'name'      => sanitize_text_field( $name ),
			'value'     => $value,
			'value_raw' => $value_raw,
			'id'        => absint( $field_id ),
			'type'      => $this->type,
		];
	}

	/**
	 * Sanitize the value.
	 *
	 * @since 1.5.7
	 *
	 * @param string $value The number field submitted value.
	 *
	 * @return float|int|string
	 */
	private function sanitize_value( $value ) {

		// Some browsers allow other non-digit/decimal characters to be submitted
		// with the num input, which then trips the is_numeric validation below.
		// To get around this we remove all chars that are not expected.
		$signed_value = preg_replace( '/[^-0-9.]/', '', $value );
		$abs_value    = abs( $signed_value );
		$value        = strpos( $signed_value, '-' ) === 0 ? '-' . $abs_value : $abs_value;

		return $value;
	}
}

new WPForms_Field_Number_Slider();
