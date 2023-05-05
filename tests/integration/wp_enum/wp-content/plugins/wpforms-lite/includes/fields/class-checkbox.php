<?php

/**
 * Checkbox field.
 *
 * @since 1.0.0
 */
class WPForms_Field_Checkbox extends WPForms_Field {

	/**
	 * Primary class constructor.
	 *
	 * @since 1.0.0
	 */
	public function init() {

		// Define field type information.
		$this->name     = esc_html__( 'Checkboxes', 'wpforms-lite' );
		$this->type     = 'checkbox';
		$this->icon     = 'fa-check-square-o';
		$this->order    = 110;
		$this->defaults = [
			1 => [
				'label'      => esc_html__( 'First Choice', 'wpforms-lite' ),
				'value'      => '',
				'image'      => '',
				'icon'       => '',
				'icon_style' => '',
				'default'    => '',
			],
			2 => [
				'label'      => esc_html__( 'Second Choice', 'wpforms-lite' ),
				'value'      => '',
				'image'      => '',
				'icon'       => '',
				'icon_style' => '',
				'default'    => '',
			],
			3 => [
				'label'      => esc_html__( 'Third Choice', 'wpforms-lite' ),
				'value'      => '',
				'image'      => '',
				'icon'       => '',
				'icon_style' => '',
				'default'    => '',
			],
		];

		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.8.1
	 */
	private function hooks() {

		// Customize HTML field values.
		add_filter( 'wpforms_html_field_value', [ $this, 'field_html_value' ], 10, 4 );

		// Define additional field properties.
		add_filter( 'wpforms_field_properties_checkbox', [ $this, 'field_properties' ], 5, 3 );

		// This field requires fieldset+legend instead of the field label.
		add_filter( "wpforms_frontend_modern_is_field_requires_fieldset_{$this->type}", '__return_true', PHP_INT_MAX, 2 );
	}

	/**
	 * Return images, if any, for HTML supported values.
	 *
	 * @since 1.4.5
	 *
	 * @param string $value     Field value.
	 * @param array  $field     Field settings.
	 * @param array  $form_data Form data and settings.
	 * @param string $context   Value display context.
	 *
	 * @return string
	 */
	public function field_html_value( $value, $field, $form_data = [], $context = '' ) {

		// Only use HTML formatting for checkbox fields, with image choices
		// enabled, and exclude the entry table display. Lastly, provides a
		// filter to disable fancy display.
		if (
			! empty( $field['value'] ) &&
			$this->type === $field['type'] &&
			! empty( $field['images'] ) &&
			'entry-table' !== $context &&
			apply_filters( 'wpforms_checkbox_field_html_value_images', true, $context )
		) {

			$items  = [];
			$values = explode( "\n", $field['value'] );

			foreach ( $values as $key => $val ) {

				if ( ! empty( $field['images'][ $key ] ) ) {
					$items[] = sprintf(
						'<span style="max-width:200px;display:block;margin:0 0 5px 0;"><img src="%s" style="max-width:100%%;display:block;margin:0;"></span>%s',
						esc_url( $field['images'][ $key ] ),
						$val
					);
				} else {
					$items[] = $val;
				}
			}

			return implode( '<br><br>', $items );
		}

		return $value;
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

		// Define data.
		$form_id  = absint( $form_data['id'] );
		$field_id = absint( $field['id'] );
		$choices  = $field['choices'];
		$dynamic  = wpforms_get_field_dynamic_choices( $field, $form_id, $form_data );

		if ( $dynamic !== false ) {
			$choices              = $dynamic;
			$field['show_values'] = true;
		}

		// Remove primary input.
		unset( $properties['inputs']['primary'] );

		// Set input container (ul) properties.
		$properties['input_container'] = [
			'class' => [ ! empty( $field['random'] ) ? 'wpforms-randomize' : '' ],
			'data'  => [],
			'attr'  => [],
			'id'    => "wpforms-{$form_id}-field_{$field_id}",
		];

		$field['choice_limit'] = empty( $field['choice_limit'] ) ? 0 : (int) $field['choice_limit'];
		if ( $field['choice_limit'] > 0 ) {
			$properties['input_container']['data']['choice-limit'] = $field['choice_limit'];
		}

		// Set input properties.
		foreach ( $choices as $key => $choice ) {

			// Used for dynamic choices.
			$depth = isset( $choice['depth'] ) ? absint( $choice['depth'] ) : 1;
			$label = isset( $choice['label'] ) ? $choice['label'] : '';

			// Choice labels should not be left blank, but if they are we
			// provide a basic value.
			$value = isset( $field['show_values'] ) ? $choice['value'] : $label;

			if ( '' === $value ) {
				if ( 1 === count( $choices ) ) {
					$value = esc_html__( 'Checked', 'wpforms-lite' );
				} else {
					/* translators: %s - choice number. */
					$value = sprintf( esc_html__( 'Choice %s', 'wpforms-lite' ), $key );
				}
			}

			$properties['inputs'][ $key ] = [
				'container'  => [
					'attr'  => [],
					'class' => [ "choice-{$key}", "depth-{$depth}" ],
					'data'  => [],
					'id'    => '',
				],
				'label'      => [
					'attr'  => [
						'for' => "wpforms-{$form_id}-field_{$field_id}_{$key}",
					],
					'class' => [ 'wpforms-field-label-inline' ],
					'data'  => [],
					'id'    => '',
					'text'  => $label,
				],
				'attr'       => [
					'name'  => "wpforms[fields][{$field_id}][]",
					'value' => $value,
				],
				'class'      => [],
				'data'       => [],
				'id'         => "wpforms-{$form_id}-field_{$field_id}_{$key}",
				'icon'       => isset( $choice['icon'] ) ? $choice['icon'] : '',
				'icon_style' => isset( $choice['icon_style'] ) ? $choice['icon_style'] : '',
				'image'      => isset( $choice['image'] ) ? $choice['image'] : '',
				'required'   => ! empty( $field['required'] ) ? 'required' : '',
				'default'    => isset( $choice['default'] ),
			];

			// Rule for validator only if needed.
			if ( $field['choice_limit'] > 0 ) {
				$properties['inputs'][ $key ]['data']['rule-check-limit'] = 'true';
			}
		}

		// Required class for pagebreak validation.
		if ( ! empty( $field['required'] ) ) {
			$properties['input_container']['class'][] = 'wpforms-field-required';
		}

		// Custom properties if image choices is enabled.
		if ( ! $dynamic && ! empty( $field['choices_images'] ) ) {

			$properties['input_container']['class'][] = 'wpforms-image-choices';
			$properties['input_container']['class'][] = 'wpforms-image-choices-' . sanitize_html_class( $field['choices_images_style'] );

			foreach ( $properties['inputs'] as $key => $inputs ) {
				$properties['inputs'][ $key ]['container']['class'][] = 'wpforms-image-choices-item';

				if ( in_array( $field['choices_images_style'], [ 'modern', 'classic' ], true ) ) {
					$properties['inputs'][ $key ]['class'][] = 'wpforms-screen-reader-element';
				}
			}
		} elseif ( ! $dynamic && ! empty( $field['choices_icons'] ) ) {
			$properties = wpforms()->get( 'icon_choices' )->field_properties( $properties, $field );
		}

		// Custom properties for disclaimer format display.
		if ( ! empty( $field['disclaimer_format'] ) ) {

			$properties['description']['class'][] = 'wpforms-disclaimer-description';
			$properties['description']['value']   = nl2br( $properties['description']['value'] );
		}

		// Add selected class for choices with defaults.
		foreach ( $properties['inputs'] as $key => $inputs ) {
			if ( ! empty( $inputs['default'] ) ) {
				$properties['inputs'][ $key ]['container']['class'][] = 'wpforms-selected';
			}
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

		// Choices.
		$this->field_option( 'choices', $field );

		// Choices Images.
		$this->field_option( 'choices_images', $field );

		// Choices Images Style (theme).
		$this->field_option( 'choices_images_style', $field );

		// Choices Icons.
		$this->field_option( 'choices_icons', $field );

		// Choices Icons Color.
		$this->field_option( 'choices_icons_color', $field );

		// Choices Icons Size.
		$this->field_option( 'choices_icons_size', $field );

		// Choices Icons Style.
		$this->field_option( 'choices_icons_style', $field );

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
		 * Advanced field options
		 */

		// Options open markup.
		$this->field_option(
			'advanced-options',
			$field,
			[
				'markup' => 'open',
			]
		);

		// Randomize order of choices.
		$this->field_element(
			'row',
			$field,
			[
				'slug'    => 'random',
				'content' => $this->field_element(
					'toggle',
					$field,
					[
						'slug'    => 'random',
						'value'   => isset( $field['random'] ) ? '1' : '0',
						'desc'    => esc_html__( 'Randomize Choices', 'wpforms-lite' ),
						'tooltip' => esc_html__( 'Check this option to randomize the order of the choices.', 'wpforms-lite' ),
					],
					false
				),
			]
		);

		// Show Values toggle option. This option will only show if already used
		// or if manually enabled by a filter.
		if ( ! empty( $field['show_values'] ) || wpforms_show_fields_options_setting() ) {
			$this->field_element(
				'row',
				$field,
				[
					'slug'    => 'show_values',
					'content' => $this->field_element(
						'toggle',
						$field,
						[
							'slug'    => 'show_values',
							'value'   => isset( $field['show_values'] ) ? $field['show_values'] : '0',
							'desc'    => esc_html__( 'Show Values', 'wpforms-lite' ),
							'tooltip' => esc_html__( 'Check this option to manually set form field values.', 'wpforms-lite' ),
						],
						false
					),
				]
			);
		}

		// Display format.
		$this->field_option( 'input_columns', $field );

		// Choice Limit.
		$field['choice_limit'] = empty( $field['choice_limit'] ) ? 0 : (int) $field['choice_limit'];
		$this->field_element(
			'row',
			$field,
			[
				'slug'    => 'choice_limit',
				'content' =>
					$this->field_element(
						'label',
						$field,
						[
							'slug'    => 'choice_limit',
							'value'   => esc_html__( 'Choice Limit', 'wpforms-lite' ),
							'tooltip' => esc_html__( 'Limit the number of checkboxes a user can select. Leave empty for unlimited.', 'wpforms-lite' ),
						],
						false
					) . $this->field_element(
						'text',
						$field,
						[
							'slug'  => 'choice_limit',
							'value' => $field['choice_limit'] > 0 ? $field['choice_limit'] : '',
							'type'  => 'number',
						],
						false
					),
			]
		);

			// Dynamic choice auto-populating toggle.
		$this->field_option( 'dynamic_choices', $field );

		// Dynamic choice source.
		$this->field_option( 'dynamic_choices_source', $field );

		// Custom CSS classes.
		$this->field_option( 'css', $field );

		// Hide label.
		$this->field_option( 'label_hide', $field );

		// Enable Disclaimer formatting.
		$this->field_element(
			'row',
			$field,
			[
				'slug'    => 'disclaimer_format',
				'content' => $this->field_element(
					'toggle',
					$field,
					[
						'slug'    => 'disclaimer_format',
						'value'   => isset( $field['disclaimer_format'] ) ? '1' : '0',
						'desc'    => esc_html__( 'Enable Disclaimer / Terms of Service Display', 'wpforms-lite' ),
						'tooltip' => esc_html__( 'Check this option to adjust the field styling to support Disclaimers and Terms of Service type agreements.', 'wpforms-lite' ),
					],
					false
				),
			]
		);

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

		// Label.
		$this->field_preview_option( 'label', $field );

		// Choices.
		$this->field_preview_option( 'choices', $field );

		// Description.
		$this->field_preview_option(
			'description',
			$field,
			[
				'class' => ! empty( $field['disclaimer_format'] ) ? 'disclaimer nl2br' : false,
			]
		);
	}

	/**
	 * Field display on the form front-end.
	 *
	 * @since 1.0.0
	 *
	 * @param array $field      Field settings.
	 * @param array $deprecated Deprecated array.
	 * @param array $form_data  Form data and settings.
	 */
	public function field_display( $field, $deprecated, $form_data ) {

		$using_image_choices = empty( $field['dynamic_choices'] ) && ! empty( $field['choices_images'] );
		$using_icon_choices  = empty( $field['dynamic_choices'] ) && empty( $field['choices_images'] ) && ! empty( $field['choices_icons'] );

		// Define data.
		$container = $field['properties']['input_container'];
		$choices   = $field['properties']['inputs'];

		$amp_state_id = '';

		if ( wpforms_is_amp() && ( $using_image_choices || $using_icon_choices ) ) {
			$amp_state_id = str_replace( '-', '_', sanitize_key( $container['id'] ) ) . '_state';
			$state        = [];

			foreach ( $choices as $key => $choice ) {
				$state[ $choice['id'] ] = ! empty( $choice['default'] );
			}
			printf(
				'<amp-state id="%s"><script type="application/json">%s</script></amp-state>',
				esc_attr( $amp_state_id ),
				wp_json_encode( $state )
			);
		}

		printf(
			'<ul %s>',
			wpforms_html_attributes( $container['id'], $container['class'], $container['data'], $container['attr'] )
		);

			foreach ( $choices as $key => $choice ) {

				if ( wpforms_is_amp() && ( $using_image_choices || $using_icon_choices ) ) {
					$choice['container']['attr']['[class]'] = sprintf(
						'%s + ( %s[%s] ? " wpforms-selected" : "")',
						wp_json_encode( implode( ' ', $choice['container']['class'] ) ),
						$amp_state_id,
						wp_json_encode( $choice['id'] )
					);
				}

				// If the field is required, has the label hidden, and has
				// disclaimer mode enabled, so the required status in choice
				// label.
				$required = '';

				if ( ! empty( $field['disclaimer_format'] ) && ! empty( $choice['required'] ) && ! empty( $field['label_hide'] ) ) {
					$required = wpforms_get_field_required_label();
				}

				printf(
					'<li %s>',
					wpforms_html_attributes( $choice['container']['id'], $choice['container']['class'], $choice['container']['data'], $choice['container']['attr'] )
				);

					// The required constraint in HTML5 form validation does not work with checkbox groups, so omit in AMP.
					$required_attr = wpforms_is_amp() && count( $choices ) > 1 ? '' : $choice['required'];

					if ( $using_image_choices ) {

						// Make sure the image choices are keyboard-accessible.
						$choice['label']['attr']['tabindex'] = 0;

						if ( wpforms_is_amp() ) {
							$choice['label']['attr']['on']   = sprintf(
								'tap:AMP.setState({ %s: { %s: ! %s[%s] } })',
								wp_json_encode( $amp_state_id ),
								wp_json_encode( $choice['id'] ),
								$amp_state_id,
								wp_json_encode( $choice['id'] )
							);
							$choice['label']['attr']['role'] = 'button';
						}

						// Image choices.
						printf(
							'<label %s>',
							wpforms_html_attributes( $choice['label']['id'], $choice['label']['class'], $choice['label']['data'], $choice['label']['attr'] )
						);

							if ( ! empty( $choice['image'] ) ) {
								printf(
									'<span class="wpforms-image-choices-image"><img src="%s" alt="%s"%s></span>',
									esc_url( $choice['image'] ),
									esc_attr( $choice['label']['text'] ),
									! empty( $choice['label']['text'] ) ? ' title="' . esc_attr( $choice['label']['text'] ) . '"' : ''
								);
							}

							if ( $field['choices_images_style'] === 'none' ) {
								echo '<br>';
							}

							$choice['attr']['tabindex'] = '-1';

							if ( wpforms_is_amp() ) {
								$choice['attr']['[checked]'] = sprintf(
									'%s[%s]',
									$amp_state_id,
									wp_json_encode( $choice['id'] )
								);
							}

							printf(
								'<input type="checkbox" %s %s %s>',
								wpforms_html_attributes( $choice['id'], $choice['class'], $choice['data'], $choice['attr'] ),
								esc_attr( $required_attr ),
								checked( '1', $choice['default'], false )
							);

							echo '<span class="wpforms-image-choices-label">' . wp_kses_post( $choice['label']['text'] ) . '</span>';

						echo '</label>';

					} elseif ( $using_icon_choices ) {

						if ( wpforms_is_amp() ) {
							$choice['label']['attr']['on']   = sprintf(
								'tap:AMP.setState({ %s: { %s: ! %s[%s] } })',
								wp_json_encode( $amp_state_id ),
								wp_json_encode( $choice['id'] ),
								$amp_state_id,
								wp_json_encode( $choice['id'] )
							);
							$choice['label']['attr']['role'] = 'button';
						}

						// Icon Choices.
						wpforms()->get( 'icon_choices' )->field_display( $field, $choice, 'checkbox' );

					} else {

						// Normal display.
						printf(
							'<input type="checkbox" %s %s %s>',
							wpforms_html_attributes( $choice['id'], $choice['class'], $choice['data'], $choice['attr'] ),
							esc_attr( $required_attr ),
							checked( '1', $choice['default'], false )
						);

						printf(
							'<label %s>%s%s</label>',
							wpforms_html_attributes( $choice['label']['id'], $choice['label']['class'], $choice['label']['data'], $choice['label']['attr'] ),
							wp_kses_post( $choice['label']['text'] ),
							wp_kses(
								$required,
								[
									'span' => [
										'class' => true,
									],
								]
							)
						);
					}

				echo '</li>';
			}

		echo '</ul>';
	}

	/**
	 * Validate field on form submit.
	 *
	 * @since 1.5.2
	 *
	 * @param int   $field_id       field ID.
	 * @param array $field_submit   submitted data.
	 * @param array $form_data      form data.
	 */
	public function validate( $field_id, $field_submit, $form_data ) {

		$field_submit  = (array) $field_submit;
		$choice_limit  = empty( $form_data['fields'][ $field_id ]['choice_limit'] ) ? 0 : (int) $form_data['fields'][ $field_id ]['choice_limit'];
		$count_choices = count( $field_submit );

		if ( $choice_limit > 0 && $count_choices > $choice_limit ) {
			// Generating the error.
			$error = wpforms_setting( 'validation-check-limit', esc_html__( 'You have exceeded the number of allowed selections: {#}.', 'wpforms-lite' ) );
			$error = str_replace( '{#}', $choice_limit, $error );
		}

		// Basic required check - If field is marked as required, check for entry data.
		if (
			! empty( $form_data['fields'][ $field_id ]['required'] ) &&
			(
				empty( $field_submit ) ||
				(
					count( $field_submit ) === 1 &&
					( ! isset( $field_submit[0] ) || (string) $field_submit[0] === '' )
				)
			)
		) {
			$error = wpforms_get_required_label();
		}

		if ( ! empty( $error ) ) {
			wpforms()->process->errors[ $form_data['id'] ][ $field_id ] = $error;
		}
	}

	/**
	 * Format and sanitize field.
	 *
	 * @since 1.0.2
	 *
	 * @param int   $field_id     Field ID.
	 * @param array $field_submit Submitted form data.
	 * @param array $form_data    Form data and settings.
	 */
	public function format( $field_id, $field_submit, $form_data ) {

		$field_submit = (array) $field_submit;
		$field        = $form_data['fields'][ $field_id ];
		$dynamic      = ! empty( $field['dynamic_choices'] ) ? $field['dynamic_choices'] : false;
		$name         = sanitize_text_field( $field['label'] );
		$value_raw    = wpforms_sanitize_array_combine( $field_submit );

		$data = [
			'name'      => $name,
			'value'     => '',
			'value_raw' => $value_raw,
			'id'        => absint( $field_id ),
			'type'      => $this->type,
		];

		if ( 'post_type' === $dynamic && ! empty( $field['dynamic_post_type'] ) ) {

			// Dynamic population is enabled using post type.
			$value_raw                 = implode( ',', array_map( 'absint', $field_submit ) );
			$data['value_raw']         = $value_raw;
			$data['dynamic']           = 'post_type';
			$data['dynamic_items']     = $value_raw;
			$data['dynamic_post_type'] = $field['dynamic_post_type'];
			$posts                     = [];

			foreach ( $field_submit as $id ) {
				$post = get_post( $id );

				if ( ! is_wp_error( $post ) && ! empty( $post ) && $data['dynamic_post_type'] === $post->post_type ) {
					$posts[] = esc_html( wpforms_get_post_title( $post ) );
				}
			}

			$data['value'] = ! empty( $posts ) ? wpforms_sanitize_array_combine( $posts ) : '';

		}
		elseif ( 'taxonomy' === $dynamic && ! empty( $field['dynamic_taxonomy'] ) ) {

			// Dynamic population is enabled using taxonomy.
			$value_raw                = implode( ',', array_map( 'absint', $field_submit ) );
			$data['value_raw']        = $value_raw;
			$data['dynamic']          = 'taxonomy';
			$data['dynamic_items']    = $value_raw;
			$data['dynamic_taxonomy'] = $field['dynamic_taxonomy'];
			$terms                    = [];

			foreach ( $field_submit as $id ) {
				$term = get_term( $id, $field['dynamic_taxonomy'] );

				if ( ! is_wp_error( $term ) && ! empty( $term ) ) {
					$terms[] = esc_html( wpforms_get_term_name( $term ) );
				}
			}

			$data['value'] = ! empty( $terms ) ? wpforms_sanitize_array_combine( $terms ) : '';

		} else {

			// Normal processing, dynamic population is off.
			$choice_keys = [];

			// If show_values is true, that means values posted are the raw values
			// and not the labels. So we need to set label values. Also store
			// the choice keys.
			if ( ! empty( $field['show_values'] ) && (int) $field['show_values'] === 1 ) {

				foreach ( $field_submit as $item ) {
					foreach ( $field['choices'] as $key => $choice ) {
						if ( $item === $choice['value'] || ( empty( $choice['value'] ) && (int) str_replace( 'Choice ', '', $item ) === $key ) ) {
							$value[]       = $choice['label'];
							$choice_keys[] = $key;

							break;
						}
					}
				}

				$data['value'] = ! empty( $value ) ? wpforms_sanitize_array_combine( $value ) : '';

			} else {

				$data['value'] = $value_raw;

				// Determine choices keys, this is needed for image choices.
				foreach ( $field_submit as $item ) {
					foreach ( $field['choices'] as $key => $choice ) {
						/* translators: %s - choice number. */
						if ( $item === $choice['label'] || $item === sprintf( esc_html__( 'Choice %s', 'wpforms-lite' ), $key ) ) {
							$choice_keys[] = $key;

							break;
						}
					}
				}
			}

			// Images choices are enabled, lookup and store image URLs.
			if ( ! empty( $choice_keys ) && ! empty( $field['choices_images'] ) ) {

				$data['images'] = [];

				foreach ( $choice_keys as $key ) {
					$data['images'][] = ! empty( $field['choices'][ $key ]['image'] ) ? esc_url_raw( $field['choices'][ $key ]['image'] ) : '';
				}
			}
		}

		// Push field details to be saved.
		wpforms()->process->fields[ $field_id ] = $data;
	}
}

new WPForms_Field_Checkbox();
