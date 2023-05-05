<?php

/**
 * Email text field.
 *
 * @since 1.0.0
 */
class WPForms_Field_Email extends WPForms_Field {

	/**
	 * Encoding.
	 *
	 * @since 1.6.9
	 */
	const ENCODING = 'UTF-8';

	/**
	 * Email type of sanitization.
	 *
	 * @since 1.7.5
	 */
	const EMAIL = 'email';

	/**
	 * Rules type of sanitization.
	 *
	 * @since 1.7.5
	 */
	const RULES = 'rules';

	/**
	 * Primary class constructor.
	 *
	 * @since 1.0.0
	 */
	public function init() {

		// Define field type information.
		$this->name  = esc_html__( 'Email', 'wpforms-lite' );
		$this->type  = 'email';
		$this->icon  = 'fa-envelope-o';
		$this->order = 170;

		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.8.1
	 */
	private function hooks() {

		// Define additional field properties.
		add_filter( 'wpforms_field_properties_email', [ $this, 'field_properties' ], 5, 3 );

		// Set field to default to required.
		add_filter( 'wpforms_field_new_required', [ $this, 'default_required' ], 10, 2 );

		// Set confirmation status to option wrapper class.
		add_filter( 'wpforms_builder_field_option_class', [ $this, 'field_option_class' ], 10, 2 );

		add_action( 'wp_ajax_wpforms_restricted_email', [ $this, 'ajax_check_restricted_email' ] );
		add_action( 'wp_ajax_nopriv_wpforms_restricted_email', [ $this, 'ajax_check_restricted_email' ] );

		add_action( 'wp_ajax_wpforms_sanitize_restricted_rules', [ $this, 'ajax_sanitize_restricted_rules' ] );
		add_action( 'wp_ajax_wpforms_sanitize_default_email', [ $this, 'ajax_sanitize_default_email' ] );

		add_filter( 'wpforms_save_form_args', [ $this, 'save_form_args' ], 11, 3 );

		add_filter( 'wpforms_builder_strings', [ $this, 'add_builder_strings' ], 10, 2 );

		// This field requires fieldset+legend instead of the field label.
		add_filter( "wpforms_frontend_modern_is_field_requires_fieldset_{$this->type}", [ $this, 'is_field_requires_fieldset' ], PHP_INT_MAX, 2 );
	}

	/**
	 * Define additional field properties.
	 *
	 * @since 1.3.7
	 *
	 * @param array $properties List field properties.
	 * @param array $field      Field data and settings.
	 * @param array $form_data  Form data and settings.
	 *
	 * @return array
	 */
	public function field_properties( $properties, $field, $form_data ) {

		// Prevent "spell-jacking" of email addresses.
		$properties['inputs']['primary']['attr']['spellcheck'] = 'false';

		if ( ! empty( $field['confirmation'] ) ) {
			$properties = $this->confirmation_field_properties( $properties, $field, $form_data );
		}
		if ( ! empty( $field['filter_type'] ) ) {
			$properties = $this->filter_type_field_properties( $properties, $field, $form_data );
		}

		return $properties;
	}

	/**
	 * Define the confirmation field properties.
	 *
	 * @since 1.6.3
	 *
	 * @param array $properties List field properties.
	 * @param array $field      Field data and settings.
	 * @param array $form_data  Form data and settings.
	 *
	 * @return array
	 */
	public function confirmation_field_properties( $properties, $field, $form_data ) {
		$form_id  = absint( $form_data['id'] );
		$field_id = absint( $field['id'] );

		// Email confirmation setting enabled.
		$props = [
			'inputs' => [
				'primary'   => [
					'block'    => [
						'wpforms-field-row-block',
						'wpforms-one-half',
						'wpforms-first',
					],
					'class'    => [
						'wpforms-field-email-primary',
					],
					'sublabel' => [
						'hidden' => ! empty( $field['sublabel_hide'] ),
						'value'  => esc_html__( 'Email', 'wpforms-lite' ),
					],
				],
				'secondary' => [
					'attr'     => [
						'name'        => "wpforms[fields][{$field_id}][secondary]",
						'value'       => '',
						'placeholder' => ! empty( $field['confirmation_placeholder'] ) ? $field['confirmation_placeholder'] : '',
						'spellcheck'  => 'false',
					],
					'block'    => [
						'wpforms-field-row-block',
						'wpforms-one-half',
					],
					'class'    => [
						'wpforms-field-email-secondary',
					],
					'data'     => [
						'rule-confirm' => '#' . $properties['inputs']['primary']['id'],
					],
					'id'       => "wpforms-{$form_id}-field_{$field_id}-secondary",
					'required' => ! empty( $field['required'] ) ? 'required' : '',
					'sublabel' => [
						'hidden' => ! empty( $field['sublabel_hide'] ),
						'value'  => esc_html__( 'Confirm Email', 'wpforms-lite' ),
					],
					'value'    => '',
				],
			],
		];

		$properties = array_merge_recursive( $properties, $props );

		// Input Primary: adjust name.
		$properties['inputs']['primary']['attr']['name'] = "wpforms[fields][{$field_id}][primary]";

		// Input Primary: remove size and error classes.
		$properties['inputs']['primary']['class'] = array_diff(
			$properties['inputs']['primary']['class'],
			[
				'wpforms-field-' . sanitize_html_class( $field['size'] ),
				'wpforms-error',
			]
		);

		// Input Primary: add error class if needed.
		if ( ! empty( $properties['error']['value']['primary'] ) ) {
			$properties['inputs']['primary']['class'][] = 'wpforms-error';
		}

		// Input Secondary: add error class if needed.
		if ( ! empty( $properties['error']['value']['secondary'] ) ) {
			$properties['inputs']['secondary']['class'][] = 'wpforms-error';
		}

		// Input Secondary: add required class if needed.
		if ( ! empty( $field['required'] ) ) {
			$properties['inputs']['secondary']['class'][] = 'wpforms-field-required';
		}

		return $properties;
	}

	/**
	 * Define the filter field properties.
	 *
	 * @since 1.6.3
	 *
	 * @param array $properties List field properties.
	 * @param array $field      Field data and settings.
	 * @param array $form_data  Form data and settings.
	 *
	 * @return array
	 */
	public function filter_type_field_properties( $properties, $field, $form_data ) {

		if ( ! empty( $field['filter_type'] ) && ! empty( $field[ $field['filter_type'] ] ) ) {
			$properties['inputs']['primary']['data']['rule-restricted-email'] = true;
		}

		return $properties;
	}

	/**
	 * Field should default to being required.
	 *
	 * @since 1.0.9
	 * @param bool $required
	 * @param array $field
	 * @return bool
	 */
	public function default_required( $required, $field ) {

		if ( 'email' === $field['type'] ) {
			return true;
		}
		return $required;
	}

	/**
	 * Add class to field options wrapper to indicate if field confirmation is
	 * enabled.
	 *
	 * @since 1.3.0
	 *
	 * @param string $class Class strings.
	 * @param array  $field Current field.
	 *
	 * @return string
	 */
	public function field_option_class( $class, $field ) {

		if ( 'email' !== $field['type'] ) {
			return $class;
		}

		$class .= isset( $field['confirmation'] ) ? ' wpforms-confirm-enabled' : ' wpforms-confirm-disabled';
		if ( ! empty( $field['filter_type'] ) ) {
			$class .= ' wpforms-filter-' . $field['filter_type'];
		}

		return $class;
	}

	/**
	 * Field options panel inside the builder.
	 *
	 * @since 1.0.0
	 *
	 * @param array $field
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

		// Required toggle.
		$this->field_option( 'required', $field );

		// Confirmation toggle.
		$fld = $this->field_element(
			'toggle',
			$field,
			[
				'slug'    => 'confirmation',
				'value'   => isset( $field['confirmation'] ) ? '1' : '0',
				'desc'    => esc_html__( 'Enable Email Confirmation', 'wpforms-lite' ),
				'tooltip' => esc_html__( 'Check this option to ask users to provide an email address twice.', 'wpforms-lite' ),
			],
			false
		);

		$args = [
			'slug'    => 'confirmation',
			'content' => $fld,
		];

		$this->field_element( 'row', $field, $args );

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

		// Placeholder.
		$this->field_option( 'placeholder', $field );

		// Confirmation Placeholder.
		$lbl = $this->field_element(
			'label',
			$field,
			[
				'slug'    => 'confirmation_placeholder',
				'value'   => esc_html__( 'Confirmation Placeholder Text', 'wpforms-lite' ),
				'tooltip' => esc_html__( 'Enter text for the confirmation field placeholder.', 'wpforms-lite' ),
			],
			false
		);

		$fld = $this->field_element(
			'text',
			$field,
			[
				'slug'  => 'confirmation_placeholder',
				'value' => ! empty( $field['confirmation_placeholder'] ) ? esc_attr( $field['confirmation_placeholder'] ) : '',
			],
			false
		);

		$args = [
			'slug'    => 'confirmation_placeholder',
			'content' => $lbl . $fld,
		];

		$this->field_element( 'row', $field, $args );

		// Default value.
		$this->field_option( 'default_value', $field );

		$filter_type_label = $this->field_element(
			'label',
			$field,
			[
				'slug'    => 'filter_type',
				'value'   => esc_html__( 'Allowlist / Denylist', 'wpforms-lite' ),
				'tooltip' => esc_html__( 'Restrict which email addresses are allowed. Be sure to separate each email address with a comma.', 'wpforms-lite' ),
			],
			false
		);

		$filter_type_field = $this->field_element(
			'select',
			$field,
			[
				'slug'    => 'filter_type',
				'value'   => ! empty( $field['filter_type'] ) ? esc_attr( $field['filter_type'] ) : '',
				'options' => [
					''          => esc_html__( 'None', 'wpforms-lite' ),
					'allowlist' => esc_html__( 'Allowlist', 'wpforms-lite' ),
					'denylist'  => esc_html__( 'Denylist', 'wpforms-lite' ),
				],
			],
			false
		);

		$this->field_element(
			'row',
			$field,
			[
				'slug'    => 'filter_type',
				'content' => $filter_type_label . $filter_type_field,
			]
		);

		$this->field_element(
			'row',
			$field,
			[
				'slug'    => 'allowlist',
				'content' => $this->field_element(
					'textarea',
					$field,
					[
						'slug'  => 'allowlist',
						'value' => ! empty( $field['allowlist'] ) ? esc_attr( $this->decode_email_patterns_rules_list( $field['allowlist'] ) ) : '',
					],
					false
				),
			]
		);

		$this->field_element(
			'row',
			$field,
			[
				'slug'    => 'denylist',
				'content' => $this->field_element(
					'textarea',
					$field,
					[
						'slug'  => 'denylist',
						'value' => ! empty( $field['denylist'] ) ? esc_attr( $this->decode_email_patterns_rules_list( $field['denylist'] ) ) : '',
					],
					false
				),
			]
		);

		// Custom CSS classes.
		$this->field_option( 'css', $field );

		// Hide Label.
		$this->field_option( 'label_hide', $field );

		// Hide sublabels.
		$this->field_option( 'sublabel_hide', $field );

		// Options close markup.
		$args = [
			'markup' => 'close',
		];

		$this->field_option( 'advanced-options', $field, $args );
	}

	/**
	 * Field preview inside the builder.
	 *
	 * @since 1.0.0
	 * @param array $field
	 */
	public function field_preview( $field ) {

		// Define data.
		$placeholder         = ! empty( $field['placeholder'] ) ? $field['placeholder'] : '';
		$confirm_placeholder = ! empty( $field['confirmation_placeholder'] ) ? $field['confirmation_placeholder'] : '';
		$default_value       = ! empty( $field['default_value'] ) ? $field['default_value'] : '';
		$confirm             = ! empty( $field['confirmation'] ) ? 'enabled' : 'disabled';

		// Label.
		$this->field_preview_option( 'label', $field );
		?>

		<div class="wpforms-confirm wpforms-confirm-<?php echo sanitize_html_class( $confirm ); ?>">

			<div class="wpforms-confirm-primary">
				<input type="email" placeholder="<?php echo esc_attr( $placeholder ); ?>" value="<?php echo esc_attr( $default_value ); ?>" class="primary-input" readonly>
				<label class="wpforms-sub-label"><?php esc_html_e( 'Email', 'wpforms-lite' ); ?></label>
			</div>

			<div class="wpforms-confirm-confirmation">
				<input type="email" placeholder="<?php echo esc_attr( $confirm_placeholder ); ?>" class="secondary-input" readonly>
				<label class="wpforms-sub-label"><?php esc_html_e( 'Confirm Email', 'wpforms-lite' ); ?></label>
			</div>

		</div>

		<?php
		// Description.
		$this->field_preview_option( 'description', $field );
	}

	/**
	 * Field display on the form front-end.
	 *
	 * @since 1.0.0
	 * @param array $field
	 * @param array $deprecated
	 * @param array $form_data
	 */
	public function field_display( $field, $deprecated, $form_data ) {

		// Define data.
		$form_id      = absint( $form_data['id'] );
		$confirmation = ! empty( $field['confirmation'] );
		$primary      = $field['properties']['inputs']['primary'];
		$secondary    = ! empty( $field['properties']['inputs']['secondary'] ) ? $field['properties']['inputs']['secondary'] : '';

		// Standard email field.
		if ( ! $confirmation ) {

			// Primary field.
			printf(
				'<input type="email" %s %s>',
				wpforms_html_attributes( $primary['id'], $primary['class'], $primary['data'], $primary['attr'] ),
				esc_attr( $primary['required'] )
			);
			$this->field_display_error( 'primary', $field );

		// Confirmation email field configuration.
		} else {

			// Row wrapper.
			echo '<div class="wpforms-field-row wpforms-field-' . sanitize_html_class( $field['size'] ) . '">';

				// Primary field.
				echo '<div ' . wpforms_html_attributes( false, $primary['block'] ) . '>';
					$this->field_display_sublabel( 'primary', 'before', $field );
					printf(
						'<input type="email" %s %s>',
						wpforms_html_attributes( $primary['id'], $primary['class'], $primary['data'], $primary['attr'] ),
						$primary['required']
					);
					$this->field_display_sublabel( 'primary', 'after', $field );
					$this->field_display_error( 'primary', $field );
				echo '</div>';

				// Secondary field.
				echo '<div ' . wpforms_html_attributes( false, $secondary['block'] ) . '>';
					$this->field_display_sublabel( 'secondary', 'before', $field );
					printf(
						'<input type="email" %s %s>',
						wpforms_html_attributes( $secondary['id'], $secondary['class'], $secondary['data'], $secondary['attr'] ),
						$secondary['required']
					);
					$this->field_display_sublabel( 'secondary', 'after', $field );
					$this->field_display_error( 'secondary', $field );
				echo '</div>';

			echo '</div>';

		} // End if().
	}

	/**
	 * Format and sanitize field.
	 *
	 * @since 1.3.0
	 * @param int   $field_id     Field ID.
	 * @param mixed $field_submit Field value that was submitted.
	 * @param array $form_data    Form data and settings.
	 */
	public function format( $field_id, $field_submit, $form_data ) {

		// Define data.
		if ( is_array( $field_submit ) ) {
			$value = ! empty( $field_submit['primary'] ) ? $field_submit['primary'] : '';
		} else {
			$value = ! empty( $field_submit ) ? $field_submit : '';
		}

		if ( $value && ! wpforms_is_email( $value ) ) {
			wpforms()->get( 'process' )->errors[ $form_data['id'] ][ $field_id ] = esc_html__( 'The provided email is not valid.', 'wpforms-lite' );

			return;
		}

		$name = ! empty( $form_data['fields'][ $field_id ] ['label'] ) ? $form_data['fields'][ $field_id ]['label'] : '';

		// Set final field details.
		wpforms()->process->fields[ $field_id ] = [
			'name'  => sanitize_text_field( $name ),
			'value' => sanitize_text_field( $this->decode_punycode( $value ) ),
			'id'    => absint( $field_id ),
			'type'  => $this->type,
		];
	}

	/**
	 * Validate field on form submit.
	 *
	 * @since 1.0.0
	 *
	 * @param int   $field_id     Field ID.
	 * @param mixed $field_submit Field value that was submitted.
	 * @param array $form_data    Form data and settings.
	 */
	public function validate( $field_id, $field_submit, $form_data ) { // phpcs:ignore Generic.Metrics.CyclomaticComplexity.TooHigh

		$form_id = (int) $form_data['id'];

		parent::validate( $field_id, $field_submit, $form_data );

		if ( ! is_array( $field_submit ) && ! empty( $field_submit ) ) {
			$field_submit = [
				'primary' => $field_submit,
			];
		}

		if ( empty( $field_submit['primary'] ) ) {
			return;
		}

		$process = wpforms()->get( 'process' );

		if ( ! $process ) {
			return;
		}

		$field_submit['primary'] = $this->email_encode_punycode( $field_submit['primary'] );

		if ( ! $field_submit['primary'] ) {
			$process->errors[ $form_id ][ $field_id ] = esc_html__( 'The provided email is not valid.', 'wpforms-lite' );

			return;
		}

		// Validate email field with confirmation.
		if ( isset( $form_data['fields'][ $field_id ]['confirmation'] ) && ! empty( $field_submit['secondary'] ) ) {
			$field_submit['secondary'] = $this->email_encode_punycode( $field_submit['secondary'] );

			if ( ! $field_submit['secondary'] ) {
				$process->errors[ $form_id ][ $field_id ] = esc_html__( 'The provided email is not valid.', 'wpforms-lite' );

				return;
			}

			if ( $field_submit['primary'] !== $field_submit['secondary'] ) {
				$process->errors[ $form_id ][ $field_id ] = esc_html__( 'The provided emails do not match.', 'wpforms-lite' );

				return;
			}

			if ( ! $this->is_restricted_email( $field_submit['primary'], $form_data['fields'][ $field_id ] ) ) {
				$process->errors[ $form_id ][ $field_id ] = wpforms_setting( 'validation-email-restricted', esc_html__( 'This email address is not allowed.', 'wpforms-lite' ) );

				return;
			}
		}

		// Validate regular email field, without confirmation.
		if ( ! isset( $form_data['fields'][ $field_id ]['confirmation'] ) && ! $this->is_restricted_email( $field_submit['primary'], $form_data['fields'][ $field_id ] ) ) {
			$process->errors[ $form_id ][ $field_id ] = wpforms_setting( 'validation-email-restricted', esc_html__( 'This email address is not allowed.', 'wpforms-lite' ) );
		}
	}

	/**
	 * Ajax handler to detect restricted email.
	 *
	 * @since 1.6.3
	 */
	public function ajax_check_restricted_email() {

		$form_id  = filter_input( INPUT_POST, 'form_id', FILTER_SANITIZE_NUMBER_INT );
		$field_id = filter_input( INPUT_POST, 'field_id', FILTER_SANITIZE_NUMBER_INT );
		$email    = filter_input( INPUT_POST, 'email', FILTER_SANITIZE_FULL_SPECIAL_CHARS );

		if ( ! $form_id || ! $field_id || ! $email ) {
			wp_send_json_error();
		}

		$form_data = wpforms()->form->get(
			$form_id,
			[ 'content_only' => true ]
		);

		if ( empty( $form_data['fields'][ $field_id ] ) ) {
			wp_send_json_error();
		}

		wp_send_json_success(
			$this->is_restricted_email( $email, $form_data['fields'][ $field_id ] )
		);
	}

	/**
	 * Sanitize restricted rules.
	 *
	 * @since 1.6.3
	 */
	public function ajax_sanitize_restricted_rules() {

		$this->ajax_sanitize( self::RULES );
	}

	/**
	 * Sanitize default email.
	 *
	 * @since 1.7.5
	 */
	public function ajax_sanitize_default_email() {

		$this->ajax_sanitize( self::EMAIL );
	}

	/**
	 * Sanitize email options input.
	 *
	 * @since 1.7.5
	 *
	 * @param string $type Type of sanitization.
	 *
	 * @return void
	 */
	private function ajax_sanitize( $type ) {

		// Run a security check.
		check_ajax_referer( 'wpforms-builder', 'nonce' );

		$content = filter_input( INPUT_GET, 'content', FILTER_SANITIZE_FULL_SPECIAL_CHARS );
		$content = wpforms_json_decode( $content, true );

		if ( ! $content ) {
			wp_send_json_error();
		}

		switch ( $type ) {
			case self::RULES:
				$current         = $content['current'];
				$other           = $current === 'allow' ? 'deny' : 'allow';
				$current_rules   = $this->sanitize_restricted_rules( $content[ $current ] );
				$other_rules     = $this->sanitize_restricted_rules( $content[ $other ] );
				$intersect_rules = array_intersect( $current_rules, $other_rules );
				$current_rules   = array_diff( $current_rules, $intersect_rules );
				$content         = [
					'currentField' => $this->decode_email_patterns_rules_array( $current_rules ),
					'intersect'    => str_replace(
						PHP_EOL,
						'<br>',
						$this->decode_email_patterns_rules_array( $intersect_rules )
					),
				];
				break;

			case self::EMAIL:
				list( $local, $domain ) = $this->parse_email_pattern( $content );

				$local  = $this->sanitize_local_pattern( $local );
				$domain = $this->sanitize_domain_pattern( $domain );

				$content = (string) wpforms_is_email( $this->get_pattern( $local, $domain ) );
				break;

			default:
				break;
		}

		wp_send_json_success( $content );
	}

	/**
	 * Verify that an email pattern is valid.
	 *
	 * @since 1.7.5
	 *
	 * @param string $pattern Email pattern.
	 *
	 * @return string|false
	 */
	private function is_email_pattern( $pattern ) {

		if ( ! $pattern ) {
			// Empty pattern is not valid.
			return false;
		}

		list( $local, $domain ) = $this->parse_email_pattern( $pattern );

		$local  = $this->sanitize_local_pattern( $local );
		$domain = $this->sanitize_domain_pattern( $domain );

		if ( mb_strpos( $pattern, '@' ) === false ) {
			return $this->is_email_pattern_without_at( $local );
		}

		$domain_check  = str_replace( '*', '', $domain );
		$domain_check  = $this->maybe_adjust_domain( $domain_check );
		$pattern_check = $this->get_pattern( $local, $domain_check );

		if ( wpforms_is_email( $pattern_check ) ) {
			return $this->get_pattern( $local, $domain );
		}

		return false;
	}

	/**
	 * Sanitize the local or domain part of the email pattern.
	 *
	 * @since 1.7.5
	 *
	 * @param string $part    Local or domain part of the email pattern.
	 * @param string $pattern Sanitization pattern.
	 *
	 * @return string
	 */
	private function sanitize_part_pattern( $part, $pattern ) {

		/**
		 * Smart tag placeholder. Should contain allowed chars only.
		 * See patterns in sanitize_local_pattern(), sanitize_domain_pattern().
		 */
		$smart_tag_placeholder = '-wpforms-smart-tag-';

		$smart_tag_pattern = '/{.+?}/';
		$smart_tags        = [];

		if ( preg_match_all( $smart_tag_pattern, $part, $m ) ) {
			$smart_tags = $m[0];

			foreach ( $smart_tags as $smart_tag ) {
				$part = preg_replace(
					'/' . preg_quote( $smart_tag, '/' ) . '/',
					$smart_tag_placeholder,
					$part,
					1
				);
			}
		}

		// Sanitize part by pattern.
		$part = preg_replace( $pattern, '', $part );

		foreach ( $smart_tags as $smart_tag ) {
			$part = preg_replace(
				'/' . preg_quote( $smart_tag_placeholder, '/' ) . '/',
				$smart_tag,
				$part,
				1
			);
		}

		return $part;
	}

	/**
	 * Sanitize the local part of the email pattern.
	 *
	 * @since 1.7.5
	 *
	 * @param string $local Local part of the email pattern.
	 *
	 * @return string
	 */
	private function sanitize_local_pattern( $local ) {

		/**
		 * This regexp is from is_email() WP core function
		 * with added international characters and
		 * asterisk [*] for patterns.
		 */
		return $this->sanitize_part_pattern( $local, '/[^a-zA-Z0-9\x{0080}-\x{0FFF}!#$%&\'*+\/=?^_`{|}~.-]/u' );
	}

	/**
	 * Sanitize the domain part of the email pattern.
	 *
	 * @since 1.7.5
	 *
	 * @param string $domain Domain part of the email pattern.
	 *
	 * @return string
	 */
	private function sanitize_domain_pattern( $domain ) {

		/**
		 * This regexp is from is_email() WP core function
		 * with added international characters,
		 * dot [.] for the whole domain part and
		 * asterisk [*] for patterns.
		 */
		return $this->sanitize_part_pattern( $domain, '/[^a-z0-9\x{0080}-\x{FFFF}-.*]/u' );
	}

	/**
	 * Maybe replace empty subdomains with templates.
	 *
	 * @since 1.7.5
	 *
	 * @param string $domain Email domain.
	 *
	 * @return string
	 */
	private function maybe_adjust_domain( $domain ) {

		$domain_subs          = array_pad( explode( '.', $domain ), 2, '' );
		$domain_template_subs = [ 'a', 'me' ];

		foreach ( $domain_template_subs as $index => $domain_template_sub ) {
			$domain_subs[ $index ] = trim( $domain_subs[ $index ] );

			if ( ! $domain_subs[ $index ] ) {
				$domain_subs[ $index ] = $domain_template_sub;
			}
		}

		return implode( '.', $domain_subs );
	}

	/**
	 * Get pattern from local and domain parts.
	 *
	 * @since 1.7.5
	 *
	 * @param string $local  Local part.
	 * @param string $domain Domain part.
	 *
	 * @return string
	 */
	private function get_pattern( $local, $domain = '' ) {

		return implode( '@', array_filter( [ $local, $domain ] ) );
	}

	/**
	 * Sanitize restricted rules.
	 *
	 * @since 1.6.3
	 *
	 * @param string $content Content.
	 *
	 * @return array
	 */
	private function sanitize_restricted_rules( $content ) {

		$patterns = array_filter( preg_split( '/\r\n|\r|\n|,/', $content ) );

		foreach ( $patterns as $key => $pattern ) {
			$pattern       = mb_strtolower( trim( $pattern ) );
			$email_pattern = $this->is_email_pattern( $pattern );

			if ( ! $email_pattern ) {
				unset( $patterns[ $key ] );
				continue;
			}

			$patterns[ $key ] = $this->encode_punycode( $email_pattern );
		}

		return array_unique( $patterns );
	}

	/**
	 * The check is a restricted email.
	 *
	 * @since 1.6.3
	 *
	 * @param string $email Email string.
	 * @param array  $field Field data.
	 *
	 * @return bool
	 */
	private function is_restricted_email( $email, $field ) {

		if ( empty( $field['filter_type'] ) || empty( $field[ $field['filter_type'] ] ) ) {
			return true;
		}

		$email = mb_strtolower( trim( $email ) );

		if ( ! wpforms_is_email( $email ) ) {
			return false;
		}

		// Chrome and Edge encode <input type="email"> to punycode, but domain part only.
		// Firefox sends intl email as is.
		if ( $this->is_encoded_punycode( $email ) ) {
			$email = $this->decode_punycode( $email );
		}

		$patterns = $this->sanitize_restricted_rules( $field[ $field['filter_type'] ] );
		$patterns = array_map( [ $this, 'decode_punycode' ], $patterns );
		$patterns = array_map( [ $this, 'sanitize_email_pattern' ], $patterns );

		$check = $field['filter_type'] === 'allowlist';

		foreach ( $patterns as $pattern ) {
			if ( preg_match( '/' . $pattern . '/', $email ) ) {
				return $check;
			}
		}

		return ! $check;
	}

	/**
	 * Sanitize from email patter a REGEX pattern.
	 *
	 * @since 1.6.3
	 *
	 * @param string $pattern Pattern line.
	 *
	 * @return string
	 */
	private function sanitize_email_pattern( $pattern ) {

		// Create regex pattern from a string.
		return '^' . str_replace( [ '.', '*' ], [ '\.', '.*' ], $pattern ) . '$';
	}

	/**
	 * Sanitize allow/deny list and default value before saving.
	 *
	 * @since 1.6.8
	 *
	 * @param array $form Form array which is usable with `wp_update_post()`.
	 * @param array $data Data retrieved from $_POST and processed.
	 * @param array $args Empty by default, may contain custom data not intended to be saved, but used for processing.
	 *
	 * @return array
	 */
	public function save_form_args( $form, $data, $args ) {

		// Get a filtered form content.
		$form_data = json_decode( stripslashes( $form['post_content'] ), true );

		if ( ! empty( $form_data['fields'] ) ) {
			foreach ( (array) $form_data['fields'] as $key => $field ) {
				if ( empty( $field['type'] ) || $field['type'] !== 'email' ) {
					continue;
				}

				$form_data['fields'][ $key ]['allowlist']     = ! empty( $field['allowlist'] ) ? implode( PHP_EOL, $this->sanitize_restricted_rules( $field['allowlist'] ) ) : '';
				$form_data['fields'][ $key ]['denylist']      = ! empty( $field['denylist'] ) ? implode( PHP_EOL, $this->sanitize_restricted_rules( $field['denylist'] ) ) : '';
				$form_data['fields'][ $key ]['default_value'] = isset( $field['default_value'] ) ? wpforms_is_email( $field['default_value'] ) : '';
			}
		}

		$form['post_content'] = wpforms_encode( $form_data );

		return $form;
	}

	/**
	 * Add a custom JS i18n strings for the builder.
	 *
	 * @since 1.7.5
	 *
	 * @param array $strings List of strings.
	 * @param array $form    Current form.
	 *
	 * @return array
	 */
	public function add_builder_strings( $strings, $form ) {

		$strings['allow_deny_lists_intersect'] = esc_html__(
			'We’ve detected the same text in your allowlist and denylist. To prevent a conflict, we’ve removed the following text from the list you’re currently viewing:',
			'wpforms-lite'
		);

		return $strings;
	}

	/**
	 * Get Punycode lib class.
	 *
	 * @since 1.6.9
	 *
	 * @return \TrueBV\Punycode
	 */
	private function get_punycode() {

		static $punycode;

		if ( ! $punycode ) {
			$punycode = new \TrueBV\Punycode();
		}

		return $punycode;
	}

	/**
	 * Get email patterns parts splitted by @ and *.
	 *
	 * @since 1.6.9
	 *
	 * @param string $email_pattern Email pattern.
	 *
	 * @return array
	 */
	private function get_email_pattern_parts( $email_pattern ) {

		$parts = preg_split( '/[*@.]/', $email_pattern, - 1, PREG_SPLIT_OFFSET_CAPTURE );

		if ( empty( $parts ) ) {
			return [];
		}

		foreach ( $parts as $key => $part ) {

			// Replace split symbol position to the split symbol.
			$part[1] = $part[1] > 0 ? $email_pattern[ $part[1] - 1 ] : '';

			$parts[ $key ] = $part;
		}

		return $parts;
	}

	/**
	 * Glue email patterns parts.
	 *
	 * @since 1.6.9
	 *
	 * @param array $parts Email pattern parts.
	 *
	 * @return string
	 */
	private function glue_email_pattern_parts( $parts ) {

		$email_pattern = '';

		foreach ( $parts as $part ) {
			$email_pattern .= $part[1] . $part[0];
		}

		return $email_pattern;
	}

	/**
	 * Decode email patterns rules array.
	 *
	 * @since 1.7.5
	 *
	 * @param array $rules_arr Patterns rules array.
	 *
	 * @return string
	 */
	private function decode_email_patterns_rules_array( $rules_arr ) {

		return implode(
			PHP_EOL,
			array_filter(
				array_map(
					function ( $rule ) {
						$rule = mb_strtolower( trim( $rule ) );

						return $this->is_email_pattern( $rule ) ? $this->decode_punycode( $rule ) : '';
					},
					$rules_arr
				)
			)
		);
	}

	/**
	 * Decode email patterns rules list.
	 *
	 * @since 1.6.9
	 *
	 * @param string $rules Patterns rules list.
	 *
	 * @return string
	 */
	private function decode_email_patterns_rules_list( $rules ) {

		return $this->decode_email_patterns_rules_array( preg_split( '/\r\n|\r|\n|,/', $rules ) );
	}

	/**
	 * Encode email.
	 *
	 * @since 1.7.3
	 *
	 * @param string $email Email.
	 *
	 * @return string
	 */
	private function email_encode_punycode( $email ) {

		if ( ! wpforms_is_email( $email ) ) {
			return '';
		}

		return $this->encode_punycode( $email );
	}

	/**
	 * Is email encoded.
	 *
	 * @since 1.7.5
	 *
	 * @param string $email Email.
	 *
	 * @return bool
	 */
	private function is_encoded_punycode( $email ) {

		list( $local, $domain ) = $this->parse_email_pattern( $email );

		// Check xn-- prefix in the beginning of domain part only.
		return strpos( $domain, 'xn--' ) === 0;
	}

	/**
	 * Encode email pattern.
	 *
	 * @since 1.6.9
	 *
	 * @param string $email_pattern Email pattern.
	 *
	 * @return string
	 */
	private function encode_punycode( $email_pattern ) {

		try {
			$encoded = $this->transform_punycode( $email_pattern, [ $this->get_punycode(), 'encode' ] );
		} catch ( Exception $e ) {
			return '';
		}

		return $encoded;
	}

	/**
	 * Decode email pattern.
	 *
	 * @since 1.6.9
	 *
	 * @param string $email_pattern Email pattern.
	 *
	 * @return string
	 */
	private function decode_punycode( $email_pattern ) {

		return $this->transform_punycode( $email_pattern, [ $this->get_punycode(), 'decode' ] );
	}

	/**
	 * Transform email pattern.
	 *
	 * @since 1.6.9
	 *
	 * @param string   $email_pattern Email pattern.
	 * @param callable $callback      Punycode callback.
	 *
	 * @return string
	 */
	private function transform_punycode( $email_pattern, callable $callback ) {

		$parts = $this->get_email_pattern_parts( $email_pattern );

		foreach ( $parts as $key => $part ) {
			if ( ! $part[0] ) {
				continue;
			}

			$parts[ $key ][0] = call_user_func( $callback, $part[0] );
		}

		return $this->glue_email_pattern_parts( $parts );
	}

	/**
	 * Parse email pattern and return local and domain parts (maybe empty).
	 *
	 * @since 1.7.5
	 *
	 * @param string $pattern Email pattern.
	 *
	 * @return array
	 */
	private function parse_email_pattern( $pattern ) {

		return array_pad( explode( '@', $pattern ), 2, '' );
	}

	/**
	 * Verify that an email pattern without @ is valid.
	 *
	 * @since 1.7.5
	 *
	 * @param string $pattern Local part.
	 *
	 * @return false|string
	 */
	private function is_email_pattern_without_at( $pattern ) {

		if ( mb_strpos( $pattern, '*' ) === false ) {
			return false;
		}

		/**
		 * If pattern does not have @ separator, we should check the pattern twice, assuming:
		 * case 1 - pattern is a local pattern,
		 * case 2 - pattern is a domain pattern.
		 */

		// Check case 1.
		$pattern_check = $this->get_pattern( $pattern, 'a.me' );

		if ( wpforms_is_email( $pattern_check ) ) {
			return $this->get_pattern( $pattern );
		}

		// Check case 2.
		// Asterisk in the email is allowed in local part, but not in the domain part.
		$pattern_check = $this->get_pattern( 'a', str_replace( '*', '', $pattern ) );

		if ( wpforms_is_email( $pattern_check ) ) {
			return $this->get_pattern( $pattern );
		}

		return false;
	}

	/**
	 * Determine if the field requires fieldset instead of the regular field label.
	 *
	 * @since 1.8.1
	 *
	 * @param bool  $requires_fieldset True if requires fieldset.
	 * @param array $field             Field data.
	 *
	 * @return bool
	 *
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function is_field_requires_fieldset( $requires_fieldset, $field ) {

		return ! empty( $field['confirmation'] );
	}
}
