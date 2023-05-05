<?php

/**
 * Paragraph text field.
 *
 * @since 1.0.0
 */
class WPForms_Field_Textarea extends WPForms_Field {

	/**
	 * Primary class constructor.
	 *
	 * @since 1.0.0
	 */
	public function init() {

		// Define field type information.
		$this->name  = esc_html__( 'Paragraph Text', 'wpforms-lite' );
		$this->type  = 'textarea';
		$this->icon  = 'fa-paragraph';
		$this->order = 50;
		add_action( 'wpforms_frontend_js', [ $this, 'frontend_js' ] );
	}

	/**
	 * Get the value, that is used to prefill via dynamic or fallback population.
	 * Based on field data and current properties.
	 *
	 * @since 1.6.4
	 *
	 * @param string $raw_value  Value from a GET param, always a string.
	 * @param string $input      Represent a subfield inside the field. May be empty.
	 * @param array  $properties Field properties.
	 * @param array  $field      Current field specific data.
	 *
	 * @return array Modified field properties.
	 */
	protected function get_field_populated_single_property_value( $raw_value, $input, $properties, $field ) {

		if ( ! is_string( $raw_value ) ) {
			return $properties;
		}

		if (
			! empty( $input ) &&
			isset( $properties['inputs'][ $input ] )
		) {
			$properties['inputs'][ $input ]['attr']['value'] = wpforms_sanitize_textarea_field( wp_unslash( $raw_value ) );
		}

		return $properties;
	}

	/**
	 * Field options panel inside the builder.
	 *
	 * @since 1.0.0
	 *
	 * @param array $field Field data and settings.
	 */
	public function field_options( $field ) {
		/*
		 * Basic field options.
		 */

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

		// Description.
		$this->field_option( 'description', $field );

		// Required toggle.
		$this->field_option( 'required', $field );

		// Options close markup.
		$this->field_option(
			'basic-options',
			$field,
			[
				'markup' => 'close',
			]
		);

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

		// Placeholder.
		$this->field_option( 'placeholder', $field );

		// Limit length.
		$args = [
			'slug'    => 'limit_enabled',
			'content' => $this->field_element(
				'toggle',
				$field,
				[
					'slug'    => 'limit_enabled',
					'value'   => isset( $field['limit_enabled'] ) ? '1' : '0',
					'desc'    => esc_html__( 'Limit Length', 'wpforms-lite' ),
					'tooltip' => esc_html__( 'Check this option to limit text length by characters or words count.', 'wpforms-lite' ),
				],
				false
			),
		];

		$this->field_element( 'row', $field, $args );

		$count = $this->field_element(
			'text',
			$field,
			[
				'type'  => 'number',
				'slug'  => 'limit_count',
				'attrs' => [
					'min'     => 1,
					'step'    => 1,
					'pattern' => '[0-9]',
				],
				'value' => ! empty( $field['limit_count'] ) ? $field['limit_count'] : 1,
			],
			false
		);

		$mode = $this->field_element(
			'select',
			$field,
			[
				'slug'    => 'limit_mode',
				'value'   => ! empty( $field['limit_mode'] ) ? esc_attr( $field['limit_mode'] ) : 'characters',
				'options' => [
					'characters' => esc_html__( 'Characters', 'wpforms-lite' ),
					'words'      => esc_html__( 'Words', 'wpforms-lite' ),
				],
			],
			false
		);

		$args = [
			'slug'    => 'limit_controls',
			'class'   => ! isset( $field['limit_enabled'] ) ? 'wpforms-hide' : '',
			'content' => $count . $mode,
		];

		$this->field_element( 'row', $field, $args );

		// Default value.
		$this->field_option( 'default_value', $field );

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
	 * @since 1.0.0
	 *
	 * @param array $field Field data and settings.
	 */
	public function field_preview( $field ) {

		// Label.
		$this->field_preview_option( 'label', $field );

		// Primary input.
		$placeholder   = ! empty( $field['placeholder'] ) ? $field['placeholder'] : '';
		$default_value = ! empty( $field['default_value'] ) ? $field['default_value'] : '';

		echo '<textarea placeholder="' . esc_attr( $placeholder ) . '" class="primary-input" readonly>' . esc_textarea( $default_value ) . '</textarea>';

		// Description.
		$this->field_preview_option( 'description', $field );
	}

	/**
	 * Field display on the form front-end.
	 *
	 * @since 1.0.0
	 *
	 * @param array $field      Field data and settings.
	 * @param array $deprecated Deprecated.
	 * @param array $form_data  Form data and settings.
	 */
	public function field_display( $field, $deprecated, $form_data ) {

		// Define data.
		$primary = $field['properties']['inputs']['primary'];
		$value   = '';

		if ( isset( $primary['attr']['value'] ) ) {
			$value = esc_textarea( $primary['attr']['value'] );

			unset( $primary['attr']['value'] );
		}

		if ( isset( $field['limit_enabled'] ) ) {
			$limit_count = isset( $field['limit_count'] ) ? absint( $field['limit_count'] ) : 0;
			$limit_mode  = isset( $field['limit_mode'] ) ? sanitize_key( $field['limit_mode'] ) : 'characters';

			$primary['data']['form-id']  = $form_data['id'];
			$primary['data']['field-id'] = $field['id'];

			if ( 'characters' === $limit_mode ) {
				$primary['class'][]            = 'wpforms-limit-characters-enabled';
				$primary['attr']['maxlength']  = $limit_count;
				$primary['data']['text-limit'] = $limit_count;
			} else {
				$primary['class'][]            = 'wpforms-limit-words-enabled';
				$primary['data']['text-limit'] = $limit_count;
			}
		}

		// Primary field.
		printf(
			'<textarea %s %s>%s</textarea>',
			wpforms_html_attributes( $primary['id'], $primary['class'], $primary['data'], $primary['attr'] ),
			$primary['required'], // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			$value // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		);
	}

	/**
	 * Enqueue frontend limit option js.
	 *
	 * @since 1.5.6
	 *
	 * @param array $forms Forms on the current page.
	 */
	public function frontend_js( $forms ) {

		// Get fields.
		$fields = array_map(
			function( $form ) {
				return empty( $form['fields'] ) ? [] : $form['fields'];
			},
			(array) $forms
		);

		// Make fields flat.
		$fields = array_reduce(
			$fields,
			function( $accumulator, $current ) {
				return array_merge( $accumulator, $current );
			},
			[]
		);

		// Leave only fields with limit.
		$fields = array_filter(
			$fields,
			function( $field ) {
				return $field['type'] === $this->type && isset( $field['limit_enabled'] );
			}
		);

		if ( count( $fields ) ) {
			$min = wpforms_get_min_suffix();

			wp_enqueue_script( 'wpforms-text-limit', WPFORMS_PLUGIN_URL . "assets/js/text-limit.es5{$min}.js", [], WPFORMS_VERSION, true );
		}
	}

	/**
	 * Format and sanitize field.
	 *
	 * @since 1.5.6
	 *
	 * @param int   $field_id     Field ID.
	 * @param mixed $field_submit Field value that was submitted.
	 * @param array $form_data    Form data and settings.
	 */
	public function format( $field_id, $field_submit, $form_data ) {

		$field = $form_data['fields'][ $field_id ];
		if ( is_array( $field_submit ) ) {
			$field_submit = implode( "\r\n", array_filter( $field_submit ) );
		}

		$name = ! empty( $field['label'] ) ? sanitize_text_field( $field['label'] ) : '';

		// Sanitize but keep line breaks.
		$value = wpforms_sanitize_textarea_field( $field_submit );

		wpforms()->process->fields[ $field_id ] = [
			'name'  => $name,
			'value' => $value,
			'id'    => absint( $field_id ),
			'type'  => $this->type,
		];
	}

	/**
	 * Validate field on form submit.
	 *
	 * @since 1.6.2
	 *
	 * @param int   $field_id     Field ID.
	 * @param mixed $field_submit Field value that was submitted.
	 * @param array $form_data    Form data and settings.
	 */
	public function validate( $field_id, $field_submit, $form_data ) {

		parent::validate( $field_id, $field_submit, $form_data );

		if ( empty( $form_data['fields'][ $field_id ] ) || empty( $form_data['fields'][ $field_id ]['limit_enabled'] ) ) {
			return;
		}

		if ( is_array( $field_submit ) ) {
			$field_submit = implode( "\r\n", array_filter( $field_submit ) );
		}

		$field = $form_data['fields'][ $field_id ];
		$limit = absint( $field['limit_count'] );
		$mode  = ! empty( $field['limit_mode'] ) ? sanitize_key( $field['limit_mode'] ) : 'characters';
		$value = wpforms_sanitize_textarea_field( $field_submit );

		if ( 'characters' === $mode ) {
			if ( mb_strlen( str_replace( "\r\n", "\n", $value ) ) > $limit ) {
				/* translators: %s - limit characters number. */
				wpforms()->process->errors[ $form_data['id'] ][ $field_id ] = sprintf( _n( 'Text can\'t exceed %d character.', 'Text can\'t exceed %d characters.', $limit, 'wpforms-lite' ), $limit );
				return;
			}
		} else {
			if ( wpforms_count_words( $value ) > $limit ) {
				/* translators: %s - limit words number. */
				wpforms()->process->errors[ $form_data['id'] ][ $field_id ] = sprintf( _n( 'Text can\'t exceed %d word.', 'Text can\'t exceed %d words.', $limit, 'wpforms-lite' ), $limit );
				return;
			}
		}
	}
}

new WPForms_Field_Textarea();
