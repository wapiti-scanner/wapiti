<?php

/**
 * Single line text field.
 *
 * @since 1.0.0
 */
class WPForms_Field_Text extends WPForms_Field {

	/**
	 * Primary class constructor.
	 *
	 * @since 1.0.0
	 */
	public function init() {

		// Define field type information.
		$this->name  = esc_html__( 'Single Line Text', 'wpforms-lite' );
		$this->type  = 'text';
		$this->icon  = 'fa-text-width';
		$this->order = 30;

		// Define additional field properties.
		add_filter( 'wpforms_field_properties_text', [ $this, 'field_properties' ], 5, 3 );
		add_action( 'wpforms_frontend_js', [ $this, 'frontend_js' ] );
	}

	/**
	 * Convert mask formatted for jquery.inputmask into  the format used by amp-inputmask.
	 *
	 * Note that amp-inputmask does not yet support all of the options that jquery.inputmask provides.
	 * In particular, amp-inputmask doesn't provides:
	 *  - Upper-alphabetical mask.
	 *  - Upper-alphanumeric mask.
	 *  - Advanced Input Masks with arbitrary repeating groups.
	 *
	 * @link https://amp.dev/documentation/components/amp-inputmask
	 * @link https://wpforms.com/docs/how-to-use-custom-input-masks/
	 *
	 * @param string $mask Mask formatted for jquery.inputmask.
	 * @return array {
	 *     Mask and placeholder.
	 *
	 *     @type string $mask        Mask for amp-inputmask.
	 *     @type string $placeholder Placeholder derived from mask if one is not supplied.
	 * }
	 */
	protected function convert_mask_to_amp_inputmask( $mask ) {
		$placeholder = '';

		// Convert jquery.inputmask format into amp-inputmask format.
		$amp_mask            = '';
		$req_mask_mapping    = [
			'9' => '0', // Numeric.
			'a' => 'L', // Alphabetical (a-z or A-Z).
			'A' => 'L', // Upper-alphabetical (A-Z). Note: AMP does not have an uppercase-alphabetical mask type, so same as previous.
			'*' => 'A', // Alphanumeric (0-9, a-z, A-Z).
			'&' => 'A', // Upper-alphanumeric (A-Z, 0-9). Note: AMP does not have an uppercase-alphanumeric mask type, so same as previous.
			' ' => '_', // Automatically insert spaces.
		];
		$opt_mask_mapping    = [
			'9' => '9', // The user may optionally add a numeric character.
			'a' => 'l', // The user may optionally add an alphabetical character.
			'A' => 'l', // The user may optionally add an alphabetical character.
			'*' => 'a', // The user may optionally add an alphanumeric character.
			'&' => 'a', // The user may optionally add an alphanumeric character.
		];
		$placeholder_mapping = [
			'9' => '0',
			'a' => 'a',
			'A' => 'a',
			'*' => '_',
			'&' => '_',
		];
		$is_inside_optional  = false;
		$last_mask_token     = null;
		for ( $i = 0, $len = strlen( $mask ); $i < $len; $i++ ) {
			if ( '[' === $mask[ $i ] ) {
				$is_inside_optional = true;
				$placeholder       .= $mask[ $i ];
				continue;
			} elseif ( ']' === $mask[ $i ] ) {
				$is_inside_optional = false;
				$placeholder       .= $mask[ $i ];
				continue;
			} elseif ( isset( $last_mask_token ) && preg_match( '/^\{(?P<n>\d+)(?:,(?P<m>\d+))?\}/', substr( $mask, $i ), $matches ) ) {
				$amp_mask    .= str_repeat( $req_mask_mapping[ $last_mask_token ], $matches['n'] );
				$placeholder .= str_repeat( $placeholder_mapping[ $last_mask_token ], $matches['n'] );
				if ( isset( $matches['m'] ) ) {
					$amp_mask    .= str_repeat( $opt_mask_mapping[ $last_mask_token ], $matches['m'] );
					$placeholder .= str_repeat( $placeholder_mapping[ $last_mask_token ], $matches['m'] );
				}
				$i += strlen( $matches[0] ) - 1;

				$last_mask_token = null; // Reset.
				continue;
			}

			if ( '\\' === $mask[ $i ] ) {
				$amp_mask .= '\\';
				$i++;
				if ( ! isset( $mask[ $i ] ) ) {
					continue;
				}
				$amp_mask .= $mask[ $i ];
			} else {
				// Remember this token in case it is a mask.
				if ( isset( $opt_mask_mapping[ $mask[ $i ] ] ) ) {
					$last_mask_token = $mask[ $i ];
				}

				if ( $is_inside_optional && isset( $opt_mask_mapping[ $mask[ $i ] ] ) ) {
					$amp_mask .= $opt_mask_mapping[ $mask[ $i ] ];
				} elseif ( isset( $req_mask_mapping[ $mask[ $i ] ] ) ) {
					$amp_mask .= $req_mask_mapping[ $mask[ $i ] ];
				} else {
					$amp_mask .= '\\' . $mask[ $i ];
				}
			}

			if ( isset( $placeholder_mapping[ $mask[ $i ] ] ) ) {
				$placeholder .= $placeholder_mapping[ $mask[ $i ] ];
			} else {
				$placeholder .= $mask[ $i ];
			}
		}

		return [ $amp_mask, $placeholder ];
	}

	/**
	 * Define additional field properties.
	 *
	 * @since 1.4.5
	 *
	 * @param array $properties Field properties.
	 * @param array $field      Field settings.
	 * @param array $form_data  Form data and settings.
	 *
	 * @return array
	 */
	public function field_properties( $properties, $field, $form_data ) {

		// Input primary: Detect custom input mask.
		if ( empty( $field['input_mask'] ) ) {
			return $properties;
		}

		// Add class that will trigger custom mask.
		$properties['inputs']['primary']['class'][] = 'wpforms-masked-input';

		if ( wpforms_is_amp() ) {
			return $this->get_amp_input_mask_properties( $properties, $field );
		}

		$properties['inputs']['primary']['data']['rule-inputmask-incomplete'] = true;

		if ( strpos( $field['input_mask'], 'alias:' ) !== false ) {
			$mask = str_replace( 'alias:', '', $field['input_mask'] );
			$properties['inputs']['primary']['data']['inputmask-alias'] = $mask;

			return $properties;
		}

		if ( strpos( $field['input_mask'], 'regex:' ) !== false ) {
			$mask = str_replace( 'regex:', '', $field['input_mask'] );
			$properties['inputs']['primary']['data']['inputmask-regex'] = $mask;

			return $properties;
		}

		if ( strpos( $field['input_mask'], 'date:' ) !== false ) {
			$mask = str_replace( 'date:', '', $field['input_mask'] );
			$properties['inputs']['primary']['data']['inputmask-alias']       = 'datetime';
			$properties['inputs']['primary']['data']['inputmask-inputformat'] = $mask;

			return $properties;
		}

		$properties['inputs']['primary']['data']['inputmask-mask'] = $field['input_mask'];

		return $properties;
	}

	/**
	 * Define additional field properties for the inputmask on AMP pages.
	 *
	 * @since 1.7.6
	 *
	 * @param array $properties Field properties.
	 * @param array $field      Field settings.
	 *
	 * @return array
	 */
	private function get_amp_input_mask_properties( $properties, $field ) {

		list( $amp_mask, $placeholder ) = $this->convert_mask_to_amp_inputmask( $field['input_mask'] );

		$properties['inputs']['primary']['attr']['mask'] = $amp_mask;

		if ( empty( $properties['inputs']['primary']['attr']['placeholder'] ) ) {
			$properties['inputs']['primary']['attr']['placeholder'] = $placeholder;
		}

		return $properties;
	}

	/**
	 * Field options panel inside the builder.
	 *
	 * @since 1.0.0
	 *
	 * @param array $field Field settings.
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
		$this->field_option(
			'advanced-options',
			$field,
			[
				'markup' => 'open',
			]
		);

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
					'value'   => isset( $field['limit_enabled'] ),
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
				'value' => ! empty( $field['limit_count'] ) ? absint( $field['limit_count'] ) : 1,
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

		// Input Mask.
		$lbl = $this->field_element(
			'label',
			$field,
			[
				'slug'          => 'input_mask',
				'value'         => esc_html__( 'Input Mask', 'wpforms-lite' ),
				'tooltip'       => esc_html__( 'Enter your custom input mask.', 'wpforms-lite' ),
				'after_tooltip' => '<a href="' . esc_url( wpforms_utm_link( 'https://wpforms.com/docs/how-to-use-custom-input-masks/', 'Field Options', 'Input Mask Documentation' ) ) . '" class="after-label-description" target="_blank" rel="noopener noreferrer">' . esc_html__( 'See Examples & Docs', 'wpforms-lite' ) . '</a>',
			],
			false
		);
		$fld = $this->field_element(
			'text',
			$field,
			[
				'slug'  => 'input_mask',
				'value' => ! empty( $field['input_mask'] ) ? esc_attr( $field['input_mask'] ) : '',
			],
			false
		);

		$this->field_element(
			'row',
			$field,
			[
				'slug'    => 'input_mask',
				'content' => $lbl . $fld,
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
	 * @since 1.0.0
	 *
	 * @param array $field Field settings.
	 */
	public function field_preview( $field ) {

		// Define data.
		$placeholder   = ! empty( $field['placeholder'] ) ? $field['placeholder'] : '';
		$default_value = ! empty( $field['default_value'] ) ? $field['default_value'] : '';

		// Label.
		$this->field_preview_option( 'label', $field );

		// Primary input.
		echo '<input type="text" placeholder="' . esc_attr( $placeholder ) . '" value="' . esc_attr( $default_value ) . '" class="primary-input" readonly>';

		// Description.
		$this->field_preview_option( 'description', $field );
	}

	/**
	 * Field display on the form front-end.
	 *
	 * @since 1.0.0
	 *
	 * @param array $field      Field settings.
	 * @param array $deprecated Deprecated.
	 * @param array $form_data  Form data and settings.
	 */
	public function field_display( $field, $deprecated, $form_data ) {

		// Define data.
		$primary = $field['properties']['inputs']['primary'];

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
			'<input type="text" %s %s>',
			wpforms_html_attributes( $primary['id'], $primary['class'], $primary['data'], $primary['attr'] ),
			$primary['required'] // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
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
				return $field['type'] === $this->type && isset( $field['limit_enabled'] ) && ! empty( $field['limit_count'] );
			}
		);

		if ( count( $fields ) ) {
			$min = wpforms_get_min_suffix();

			wp_enqueue_script(
				'wpforms-text-limit',
				WPFORMS_PLUGIN_URL . "assets/js/text-limit.es5{$min}.js",
				[],
				WPFORMS_VERSION,
				true
			);
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
		$name  = ! empty( $field['label'] ) ? sanitize_text_field( $field['label'] ) : '';

		// Sanitize.
		$value = sanitize_text_field( $field_submit );

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

		$field = $form_data['fields'][ $field_id ];
		$limit = absint( $field['limit_count'] );
		$mode  = ! empty( $field['limit_mode'] ) ? sanitize_key( $field['limit_mode'] ) : 'characters';
		$value = sanitize_text_field( $field_submit );

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

new WPForms_Field_Text();
