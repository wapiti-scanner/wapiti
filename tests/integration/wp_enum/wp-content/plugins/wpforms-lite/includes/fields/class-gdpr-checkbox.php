<?php

/**
 * GDPR Checkbox field.
 *
 * @since 1.4.6
 */
class WPForms_Field_GDPR_Checkbox extends WPForms_Field {

	/**
	 * Primary class constructor.
	 *
	 * @since 1.4.6
	 */
	public function init() {

		// Define field type information.
		$this->name     = esc_html__( 'GDPR Agreement', 'wpforms-lite' );
		$this->type     = 'gdpr-checkbox';
		$this->icon     = 'fa-check-square-o';
		$this->order    = 500;
		$this->defaults = [
			1 => [
				'label'   => esc_html__( 'I consent to having this website store my submitted information so they can respond to my inquiry.', 'wpforms-lite' ),
				'value'   => '',
				'image'   => '',
				'default' => '',
			],
		];

		// Set field to default to required.
		add_filter( 'wpforms_field_new_required', [ $this, 'field_default_required' ], 10, 2 );

		// Define additional field properties.
		add_filter( 'wpforms_field_properties_gdpr-checkbox', [ $this, 'field_properties' ], 5, 3 );
	}

	/**
	 * Field should default to being required.
	 *
	 * @since 1.4.6
	 *
	 * @param bool  $required Required status, true is required.
	 * @param array $field    Field settings.
	 *
	 * @return bool
	 */
	public function field_default_required( $required, $field ) {

		if ( $this->type === $field['type'] ) {
			return true;
		}

		return $required;
	}

	/**
	 * Define additional field properties.
	 *
	 * @since 1.4.6
	 *
	 * @param array $properties Field properties.
	 * @param array $field      Field settings.
	 * @param array $form_data  Form data and settings.
	 *
	 * @return array
	 */
	public function field_properties( $properties, $field, $form_data ) {

		// Define data.
		$form_id  = absint( $form_data['id'] );
		$field_id = absint( $field['id'] );
		$choices  = ! empty( $field['choices'] ) ? $field['choices'] : [];

		// Remove primary input.
		unset( $properties['inputs']['primary'] );

		// Set input container (ul) properties.
		$properties['input_container'] = [
			'class' => [],
			'data'  => [],
			'attr'  => [],
			'id'    => "wpforms-{$form_id}-field_{$field_id}",
		];

		// Set input properties.
		foreach ( $choices as $key => $choice ) {

			$properties['inputs'][ $key ] = [
				'container' => [
					'attr'  => [],
					'class' => [ "choice-{$key}" ],
					'data'  => [],
					'id'    => '',
				],
				'label'     => [
					'attr'  => [
						'for' => "wpforms-{$form_id}-field_{$field_id}_{$key}",
					],
					'class' => [ 'wpforms-field-label-inline' ],
					'data'  => [],
					'id'    => '',
					'text'  => $choice['label'],
				],
				'attr'      => [
					'name'  => "wpforms[fields][{$field_id}][]",
					'value' => $choice['label'],
				],
				'class'     => [],
				'data'      => [],
				'id'        => "wpforms-{$form_id}-field_{$field_id}_{$key}",
				'image'     => '',
				'required'  => ! empty( $field['required'] ) ? 'required' : '',
				'default'   => '',
			];
		}

		// Required class for pagebreak validation.
		if ( ! empty( $field['required'] ) ) {
			$properties['input_container']['class'][] = 'wpforms-field-required';
		}

		return $properties;
	}

	/**
	 * @inheritdoc
	 */
	public function is_dynamic_population_allowed( $properties, $field ) {

		return false;
	}

	/**
	 * Field options panel inside the builder.
	 *
	 * @since 1.4.6
	 *
	 * @param array $field Field settings.
	 */
	public function field_options( $field ) {

		// Field is always required.
		$this->field_element(
			'text',
			$field,
			[
				'type'  => 'hidden',
				'slug'  => 'required',
				'value' => '1',
			]
		);

		// -------------------------------------------------------------------//
		// Basic field options
		// -------------------------------------------------------------------//

		// Options open markup.
		$this->field_option(
			'basic-options',
			$field,
			[
				'markup' => 'open',
			]
		);

		// Label.
		$this->field_option( 'label', $field );

		// Choices.
		$this->field_option(
			'choices',
			$field,
			[
				'label' => esc_html__( 'Agreement', 'wpforms-lite' ),
			]
		);

		// Description.
		$this->field_option( 'description', $field );

		// Options close markup.
		$this->field_option(
			'basic-options',
			$field,
			[
				'markup' => 'close',
			]
		);

		// -------------------------------------------------------------------//
		// Advanced field options
		// -------------------------------------------------------------------//

		// Options open markup.
		$this->field_option(
			'advanced-options',
			$field,
			[
				'markup' => 'open',
			]
		);

		// Custom CSS classes.
		$this->field_option( 'css', $field );

		// Hide label.
		$this->field_option( 'label_hide', $field );

		// Options close markup.
		$this->field_option(
			'advanced-options',
			$field,
			[
				'markup' => 'close',
			]
		);
	}

	/**
	 * Field preview inside the builder.
	 *
	 * @since 1.4.6
	 *
	 * @param array $field Field settings.
	 */
	public function field_preview( $field ) {

		// Label.
		$this->field_preview_option( 'label', $field );

		// Choices.
		$this->field_preview_option( 'choices', $field );

		// Description.
		$this->field_preview_option( 'description', $field );
	}

	/**
	 * Field display on the form front-end.
	 *
	 * @since 1.4.6
	 *
	 * @param array $field      Field settings.
	 * @param array $deprecated Deprecated array.
	 * @param array $form_data  Form data and settings.
	 */
	public function field_display( $field, $deprecated, $form_data ) {

		// Define data.
		$container = $field['properties']['input_container'];
		$choices   = $field['properties']['inputs'];

		printf(
			'<ul %s>',
			wpforms_html_attributes( $container['id'], $container['class'], $container['data'], $container['attr'] )
		);

			foreach ( $choices as $key => $choice ) {

				$required = '';
				if ( ! empty( $choice['required'] ) && ! empty( $field['label_hide'] ) ) {
					$required = wpforms_get_field_required_label();
				}

				printf(
					'<li %s>',
					wpforms_html_attributes( $choice['container']['id'], $choice['container']['class'], $choice['container']['data'], $choice['container']['attr'] )
				);
					// Normal display.
					printf(
						'<input type="checkbox" %s %s %s>',
						wpforms_html_attributes( $choice['id'], $choice['class'], $choice['data'], $choice['attr'] ),
						esc_attr( $choice['required'] ),
						checked( '1', $choice['default'], false )
					);

					printf(
						'<label %s>%s%s</label>',
						wpforms_html_attributes( $choice['label']['id'], $choice['label']['class'], $choice['label']['data'], $choice['label']['attr'] ),
						wp_kses_post( $choice['label']['text'] ),
						$required
					); // WPCS: XSS ok.

				echo '</li>';
			}

		echo '</ul>';
	}

	/**
	 * Format and sanitize field.
	 *
	 * @since 1.4.6
	 *
	 * @param int   $field_id     Field ID.
	 * @param array $field_submit Submitted form data.
	 * @param array $form_data    Form data and settings.
	 */
	public function format( $field_id, $field_submit, $form_data ) {

		wpforms()->process->fields[ $field_id ] = [
			'name'  => ! empty( $form_data['fields'][ $field_id ]['label'] ) ? sanitize_text_field( $form_data['fields'][ $field_id ]['label'] ) : '',
			'value' => $form_data['fields'][ $field_id ]['choices'][1]['label'],
			'id'    => absint( $field_id ),
			'type'  => $this->type,
		];
	}
}

new WPForms_Field_GDPR_Checkbox();
