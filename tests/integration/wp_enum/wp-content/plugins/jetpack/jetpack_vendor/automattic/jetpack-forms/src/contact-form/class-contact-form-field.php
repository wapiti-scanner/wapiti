<?php
/**
 * Contact_Form_Field class.
 *
 * @package automattic/jetpack-forms
 */

namespace Automattic\Jetpack\Forms\ContactForm;

use Automattic\Jetpack\Assets;

/**
 * Class for the contact-field shortcode.
 * Parses shortcode to output the contact form field as HTML.
 * Validates input.
 */
class Contact_Form_Field extends Contact_Form_Shortcode {

	/**
	 * The shortcode name.
	 *
	 * @var string
	 */
	public $shortcode_name = 'contact-field';

	/**
	 * The parent form.
	 *
	 * @var Grunion_Contact_Form
	 */
	public $form;

	/**
	 * Default or POSTed value.
	 *
	 * @var string
	 */
	public $value;

	/**
	 * Is the input valid?
	 *
	 * @var bool
	 */
	public $error = false;

	/**
	 * Styles to be applied to the field
	 *
	 * @var string
	 */
	public $block_styles = '';

	/**
	 * Styles to be applied to the field
	 *
	 * @var string
	 */
	public $field_styles = '';

	/**
	 * Styles to be applied to the field option
	 *
	 * @var string
	 */
	public $option_styles = '';

	/**
	 * Styles to be applied to the field
	 *
	 * @var string
	 */
	public $label_styles = '';

	/**
	 * Constructor function.
	 *
	 * @param array                $attributes An associative array of shortcode attributes.  @see shortcode_atts().
	 * @param null|string          $content Null for selfclosing shortcodes.  The inner content otherwise.
	 * @param Grunion_Contact_Form $form The parent form.
	 */
	public function __construct( $attributes, $content = null, $form = null ) {
		$attributes = shortcode_atts(
			array(
				'label'                  => null,
				'togglelabel'            => null,
				'type'                   => 'text',
				'required'               => false,
				'requiredtext'           => null,
				'options'                => array(),
				'id'                     => null,
				'style'                  => null,
				'fieldbackgroundcolor'   => null,
				'textcolor'              => null,
				'default'                => null,
				'values'                 => null,
				'placeholder'            => null,
				'class'                  => null,
				'width'                  => null,
				'consenttype'            => null,
				'implicitconsentmessage' => null,
				'explicitconsentmessage' => null,
				'borderradius'           => null,
				'borderwidth'            => null,
				'lineheight'             => null,
				'labellineheight'        => null,
				'bordercolor'            => null,
				'inputcolor'             => null,
				'labelcolor'             => null,
				'labelfontsize'          => null,
				'fieldfontsize'          => null,
			),
			$attributes,
			'contact-field'
		);

		// special default for subject field
		if ( 'subject' === $attributes['type'] && $attributes['default'] === null && $form !== null ) {
			$attributes['default'] = $form->get_attribute( 'subject' );
		}

		// allow required=1 or required=true
		if ( '1' === $attributes['required'] || 'true' === strtolower( $attributes['required'] ) ) {
			$attributes['required'] = true;
		} else {
			$attributes['required'] = false;
		}

		if ( $attributes['requiredtext'] === null ) {
			$attributes['requiredtext'] = __( '(required)', 'jetpack-forms' );
		}

		// parse out comma-separated options list (for selects, radios, and checkbox-multiples)
		if ( ! empty( $attributes['options'] ) && is_string( $attributes['options'] ) ) {
			$attributes['options'] = array_map( 'trim', explode( ',', $attributes['options'] ) );

			if ( ! empty( $attributes['values'] ) && is_string( $attributes['values'] ) ) {
				$attributes['values'] = array_map( 'trim', explode( ',', $attributes['values'] ) );
			}
		}

		if ( $form ) {
			// make a unique field ID based on the label, with an incrementing number if needed to avoid clashes
			$form_id = $form->get_attribute( 'id' );
			$id      = isset( $attributes['id'] ) ? $attributes['id'] : false;

			$unescaped_label = $this->unesc_attr( $attributes['label'] );
			$unescaped_label = str_replace( '%', '-', $unescaped_label ); // jQuery doesn't like % in IDs?
			$unescaped_label = preg_replace( '/[^a-zA-Z0-9.-_:]/', '', $unescaped_label );

			if ( empty( $id ) ) {
				$id        = sanitize_title_with_dashes( 'g' . $form_id . '-' . $unescaped_label );
				$i         = 0;
				$max_tries = 99;
				while ( isset( $form->fields[ $id ] ) ) {
					++$i;
					$id = sanitize_title_with_dashes( 'g' . $form_id . '-' . $unescaped_label . '-' . $i );

					if ( $i > $max_tries ) {
						break;
					}
				}
			}

			$attributes['id'] = $id;
		}

		parent::__construct( $attributes, $content );

		// Store parent form
		$this->form = $form;
	}

	/**
	 * This field's input is invalid.  Flag as invalid and add an error to the parent form
	 *
	 * @param string $message The error message to display on the form.
	 */
	public function add_error( $message ) {
		$this->is_error = true;

		if ( ! is_wp_error( $this->form->errors ) ) {
			$this->form->errors = new \WP_Error();
		}

		$this->form->errors->add( $this->get_attribute( 'id' ), $message );
	}

	/**
	 * Is the field input invalid?
	 *
	 * @see $error
	 *
	 * @return bool
	 */
	public function is_error() {
		return $this->error;
	}

	/**
	 * Validates the form input
	 */
	public function validate() {
		// If it's not required, there's nothing to validate
		if ( ! $this->get_attribute( 'required' ) ) {
			return;
		}

		$field_id    = $this->get_attribute( 'id' );
		$field_type  = $this->maybe_override_type();
		$field_label = $this->get_attribute( 'label' );

		if ( isset( $_POST[ $field_id ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- no site changes.
			if ( is_array( $_POST[ $field_id ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- no site changes.
				$field_value = array_map( 'sanitize_text_field', wp_unslash( $_POST[ $field_id ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce verification should happen in caller.
			} else {
				$field_value = sanitize_text_field( wp_unslash( $_POST[ $field_id ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce verification should happen in caller.
			}
		} else {
			$field_value = '';
		}

		switch ( $field_type ) {
			case 'url':
				if ( ! is_string( $field_value ) || empty( $field_value ) || ! preg_match(
					'%^(?:(?:https?|ftp)://)?(?:\S+(?::\S*)?@|\d{1,3}(?:\.\d{1,3}){3}|(?:(?:[a-z\d\x{00a1}-\x{ffff}]+-?)*[a-z\d\x{00a1}-\x{ffff}]+)(?:\.(?:[a-z\d\x{00a1}-\x{ffff}]+-?)*[a-z\d\x{00a1}-\x{ffff}]+)*(?:\.[a-z\x{00a1}-\x{ffff}]{2,6}))(?::\d+)?(?:[^\s]*)?$%iu',
					$field_value
				) ) {
					/* translators: %s is the name of a form field */
					$this->add_error( sprintf( __( '%s: Please enter a valid URL - https://www.example.com', 'jetpack-forms' ), $field_label ) );
				}
				break;
			case 'email':
				// Make sure the email address is valid
				if ( ! is_string( $field_value ) || ! is_email( $field_value ) ) {
					/* translators: %s is the name of a form field */
					$this->add_error( sprintf( __( '%s requires a valid email address', 'jetpack-forms' ), $field_label ) );
				}
				break;
			case 'checkbox-multiple':
				// Check that there is at least one option selected
				if ( empty( $field_value ) ) {
					/* translators: %s is the name of a form field */
					$this->add_error( sprintf( __( '%s requires at least one selection', 'jetpack-forms' ), $field_label ) );
				}
				break;
			default:
				// Just check for presence of any text
				if ( ! is_string( $field_value ) || ! strlen( trim( $field_value ) ) ) {
					/* translators: %s is the name of a form field */
					$this->add_error( sprintf( __( '%s is required', 'jetpack-forms' ), $field_label ) );
				}
		}
	}

	/**
	 * Check the default value for options field
	 *
	 * @param string $value - the value we're checking.
	 * @param int    $index - the index.
	 * @param string $options - default field option.
	 *
	 * @return string
	 */
	public function get_option_value( $value, $index, $options ) {
		if ( empty( $value[ $index ] ) ) {
			return $options;
		}
		return $value[ $index ];
	}

	/**
	 * Outputs the HTML for this form field
	 *
	 * @return string HTML
	 */
	public function render() {
		global $current_user, $user_identity;

		$field_id            = $this->get_attribute( 'id' );
		$field_type          = $this->maybe_override_type();
		$field_label         = $this->get_attribute( 'label' );
		$field_required      = $this->get_attribute( 'required' );
		$field_required_text = $this->get_attribute( 'requiredtext' );
		$field_placeholder   = $this->get_attribute( 'placeholder' );
		$field_width         = $this->get_attribute( 'width' );
		$class               = 'date' === $field_type ? 'jp-contact-form-date' : $this->get_attribute( 'class' );

		if ( is_numeric( $this->get_attribute( 'borderradius' ) ) ) {
			$this->block_styles .= '--jetpack--contact-form--border-radius: ' . esc_attr( $this->get_attribute( 'borderradius' ) ) . 'px;';
			$this->field_styles .= 'border-radius: ' . (int) $this->get_attribute( 'borderradius' ) . 'px;';
		}
		if ( is_numeric( $this->get_attribute( 'borderwidth' ) ) ) {
			$this->block_styles .= '--jetpack--contact-form--border-size: ' . esc_attr( $this->get_attribute( 'borderwidth' ) ) . 'px;';
			$this->field_styles .= 'border-width: ' . (int) $this->get_attribute( 'borderwidth' ) . 'px;';
		}
		if ( is_numeric( $this->get_attribute( 'lineheight' ) ) ) {
			$this->block_styles  .= '--jetpack--contact-form--line-height: ' . esc_attr( $this->get_attribute( 'lineheight' ) ) . ';';
			$this->field_styles  .= 'line-height: ' . (int) $this->get_attribute( 'lineheight' ) . ';';
			$this->option_styles .= 'line-height: ' . (int) $this->get_attribute( 'lineheight' ) . ';';
		}
		if ( ! empty( $this->get_attribute( 'bordercolor' ) ) ) {
			$this->block_styles .= '--jetpack--contact-form--border-color: ' . esc_attr( $this->get_attribute( 'bordercolor' ) ) . ';';
			$this->field_styles .= 'border-color: ' . esc_attr( $this->get_attribute( 'bordercolor' ) ) . ';';
		}
		if ( ! empty( $this->get_attribute( 'inputcolor' ) ) ) {
			$this->block_styles  .= '--jetpack--contact-form--text-color: ' . esc_attr( $this->get_attribute( 'inputcolor' ) ) . ';';
			$this->field_styles  .= 'color: ' . esc_attr( $this->get_attribute( 'inputcolor' ) ) . ';';
			$this->option_styles .= 'color: ' . esc_attr( $this->get_attribute( 'inputcolor' ) ) . ';';
		}
		if ( ! empty( $this->get_attribute( 'fieldbackgroundcolor' ) ) ) {
			$this->block_styles .= '--jetpack--contact-form--input-background: ' . esc_attr( $this->get_attribute( 'fieldbackgroundcolor' ) ) . ';';
			$this->field_styles .= 'background-color: ' . esc_attr( $this->get_attribute( 'fieldbackgroundcolor' ) ) . ';';
		}
		if ( ! empty( $this->get_attribute( 'fieldfontsize' ) ) ) {
			$this->block_styles  .= '--jetpack--contact-form--font-size: ' . esc_attr( $this->get_attribute( 'fieldfontsize' ) ) . ';';
			$this->field_styles  .= 'font-size: ' . esc_attr( $this->get_attribute( 'fieldfontsize' ) ) . ';';
			$this->option_styles .= 'font-size: ' . esc_attr( $this->get_attribute( 'fieldfontsize' ) ) . ';';
		}

		if ( ! empty( $this->get_attribute( 'labelcolor' ) ) ) {
			$this->label_styles .= 'color: ' . esc_attr( $this->get_attribute( 'labelcolor' ) ) . ';';
		}
		if ( ! empty( $this->get_attribute( 'labelfontsize' ) ) ) {
			$this->label_styles .= 'font-size: ' . esc_attr( $this->get_attribute( 'labelfontsize' ) ) . ';';
		}
		if ( is_numeric( $this->get_attribute( 'labellineheight' ) ) ) {
			$this->label_styles .= 'line-height: ' . (int) $this->get_attribute( 'labellineheight' ) . ';';
		}

		if ( ! empty( $field_width ) ) {
			$class .= ' grunion-field-width-' . $field_width;
		}

		/**
		 * Filters the "class" attribute of the contact form input
		 *
		 * @module contact-form
		 *
		 * @since 6.6.0
		 *
		 * @param string $class Additional CSS classes for input class attribute.
		 */
		$field_class = apply_filters( 'jetpack_contact_form_input_class', $class );

		if ( isset( $_POST[ $field_id ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- no site changes.
			if ( is_array( $_POST[ $field_id ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- no site changes.
				$this->value = array_map( 'sanitize_textarea_field', wp_unslash( $_POST[ $field_id ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- no site changes.
			} else {
				$this->value = sanitize_textarea_field( wp_unslash( $_POST[ $field_id ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- no site changes.
			}
		} elseif ( isset( $_GET[ $field_id ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no site changes.
			$this->value = sanitize_textarea_field( wp_unslash( $_GET[ $field_id ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no site changes.
		} elseif (
			is_user_logged_in() &&
			( ( defined( 'IS_WPCOM' ) && IS_WPCOM ) ||
			/**
			 * Allow third-party tools to prefill the contact form with the user's details when they're logged in.
			 *
			 * @module contact-form
			 *
			 * @since 3.2.0
			 *
			 * @param bool false Should the Contact Form be prefilled with your details when you're logged in. Default to false.
			 */
			true === apply_filters( 'jetpack_auto_fill_logged_in_user', false )
			)
		) {
			// Special defaults for logged-in users
			switch ( $field_type ) {
				case 'email':
					$this->value = $current_user->data->user_email;
					break;
				case 'name':
					$this->value = $user_identity;
					break;
				case 'url':
					$this->value = $current_user->data->user_url;
					break;
				default:
					$this->value = $this->get_attribute( 'default' );
			}
		} else {
			$this->value = $this->get_attribute( 'default' );
		}

		$field_value = Contact_Form_Plugin::strip_tags( $this->value );
		$field_label = Contact_Form_Plugin::strip_tags( $field_label );

		$rendered_field = $this->render_field( $field_type, $field_id, $field_label, $field_value, $field_class, $field_placeholder, $field_required, $field_required_text );

		/**
		 * Filter the HTML of the Contact Form.
		 *
		 * @module contact-form
		 *
		 * @since 2.6.0
		 *
		 * @param string $rendered_field Contact Form HTML output.
		 * @param string $field_label Field label.
		 * @param int|null $id Post ID.
		 */
		return apply_filters( 'grunion_contact_form_field_html', $rendered_field, $field_label, ( in_the_loop() ? get_the_ID() : null ) );
	}

	/**
	 * Return the HTML for the label.
	 *
	 * @param string $type - the field type.
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 * @param array  $extra_attrs Array of key/value pairs to append as attributes to the element.
	 *
	 * @return string HTML
	 */
	public function render_label( $type, $id, $label, $required, $required_field_text, $extra_attrs = array() ) {
		$form_style = $this->get_form_style();

		if ( ! empty( $form_style ) && $form_style !== 'default' ) {
			return '';
		}

		if ( ! empty( $this->label_styles ) ) {
			$extra_attrs['style'] = $this->label_styles;
		}

		$extra_attrs_string = '';
		if ( is_array( $extra_attrs ) && ! empty( $extra_attrs ) ) {
			foreach ( $extra_attrs as $attr => $val ) {
				$extra_attrs_string .= sprintf( '%s="%s" ', esc_attr( $attr ), esc_attr( $val ) );
			}
		}

		$type_class = $type ? ' ' . $type : '';
		return "<label
				for='" . esc_attr( $id ) . "'
				class='grunion-field-label{$type_class}" . ( $this->is_error() ? ' form-error' : '' ) . "'"
				. $extra_attrs_string
				. '>'
				. esc_html( $label )
				. ( $required ? '<span>' . $required_field_text . '</span>' : '' )
				. "</label>\n";
	}

	/**
	 * Return the HTML for the input field.
	 *
	 * @param string $type - the field type.
	 * @param int    $id - the ID.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param string $placeholder - the field placeholder content.
	 * @param bool   $required - if the field is marked as required.
	 * @param array  $extra_attrs Array of key/value pairs to append as attributes to the element.
	 *
	 * @return string HTML
	 */
	public function render_input_field( $type, $id, $value, $class, $placeholder, $required, $extra_attrs = array() ) {
		$extra_attrs_string = '';

		if ( ! empty( $this->field_styles ) ) {
			$extra_attrs['style'] = $this->field_styles;
		}

		if ( is_array( $extra_attrs ) && ! empty( $extra_attrs ) ) {
			foreach ( $extra_attrs as $attr => $val ) {
				$extra_attrs_string .= sprintf( '%s="%s" ', esc_attr( $attr ), esc_attr( $val ) );
			}
		}
		return "<input
					type='" . esc_attr( $type ) . "'
					name='" . esc_attr( $id ) . "'
					id='" . esc_attr( $id ) . "'
					value='" . esc_attr( $value ) . "'
					" . $class . $placeholder . '
					' . ( $required ? "required aria-required='true'" : '' ) .
					$extra_attrs_string .
					" />\n";
	}

	/**
	 * Return the HTML for the email field.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 * @param string $placeholder - the field placeholder content.
	 *
	 * @return string HTML
	 */
	public function render_email_field( $id, $label, $value, $class, $required, $required_field_text, $placeholder ) {
		$field  = $this->render_label( 'email', $id, $label, $required, $required_field_text );
		$field .= $this->render_input_field( 'email', $id, $value, $class, $placeholder, $required );
		return $field;
	}

	/**
	 * Return the HTML for the telephone field.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 * @param string $placeholder - the field placeholder content.
	 *
	 * @return string HTML
	 */
	public function render_telephone_field( $id, $label, $value, $class, $required, $required_field_text, $placeholder ) {
		$field  = $this->render_label( 'telephone', $id, $label, $required, $required_field_text );
		$field .= $this->render_input_field( 'tel', $id, $value, $class, $placeholder, $required );
		return $field;
	}

	/**
	 * Return the HTML for the URL field.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 * @param string $placeholder - the field placeholder content.
	 *
	 * @return string HTML
	 */
	public function render_url_field( $id, $label, $value, $class, $required, $required_field_text, $placeholder ) {
		$custom_validation_message = __( 'Please enter a valid URL - https://www.example.com', 'jetpack-forms' );
		$validation_attrs          = array(
			'title'              => $custom_validation_message,
			'oninvalid'          => 'setCustomValidity("' . $custom_validation_message . '")',
			'oninput'            => 'setCustomValidity("")',
			'pattern'            => '(([:\/a-zA-Z0-9_\-]+)?(\.[a-zA-Z0-9_\-\/]+)+)',
			'data-type-override' => 'url',
		);

		$field  = $this->render_label( 'url', $id, $label, $required, $required_field_text );
		$field .= $this->render_input_field( 'text', $id, $value, $class, $placeholder, $required, $validation_attrs );
		return $field;
	}

	/**
	 * Return the HTML for the text area field.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 * @param string $placeholder - the field placeholder content.
	 *
	 * @return string HTML
	 */
	public function render_textarea_field( $id, $label, $value, $class, $required, $required_field_text, $placeholder ) {
		$field  = $this->render_label( 'textarea', 'contact-form-comment-' . $id, $label, $required, $required_field_text );
		$field .= "<textarea
		                style='" . $this->field_styles . "'
		                name='" . esc_attr( $id ) . "'
		                id='contact-form-comment-" . esc_attr( $id ) . "'
		                rows='20' "
						. $class
						. $placeholder
						. ' ' . ( $required ? "required aria-required='true'" : '' ) .
						'>' . esc_textarea( $value )
				. "</textarea>\n";
		return $field;
	}

	/**
	 * Return the HTML for the radio field.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 *
	 * @return string HTML
	 */
	public function render_radio_field( $id, $label, $value, $class, $required, $required_field_text ) {
		$field  = $this->render_label( '', $id, $label, $required, $required_field_text );
		$field .= '<div class="grunion-radio-options">';

		$field_style = 'style="' . $this->option_styles . '"';

		foreach ( (array) $this->get_attribute( 'options' ) as $option_index => $option ) {
			$option = Contact_Form_Plugin::strip_tags( $option );
			if ( is_string( $option ) && $option !== '' ) {
				$field .= "\t\t<label {$field_style} class='grunion-radio-label radio" . ( $this->is_error() ? ' form-error' : '' ) . "'>";
				$field .= "<input
									type='radio'
									name='" . esc_attr( $id ) . "'
									value='" . esc_attr( $this->get_option_value( $this->get_attribute( 'values' ), $option_index, $option ) ) . "' "
									. $class
									. checked( $option, $value, false ) . ' '
									. ( $required ? "required aria-required='true'" : '' )
									. '/> ';
				$field .= esc_html( $option ) . "</label>\n";
			}
		}
		$field .= '</div>';
		return $field;
	}

	/**
	 * Return the HTML for the checkbox field.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 *
	 * @return string HTML
	 */
	public function render_checkbox_field( $id, $label, $value, $class, $required, $required_field_text ) {
		$field  = "<label class='grunion-field-label checkbox" . ( $this->is_error() ? ' form-error' : '' ) . "' style='" . $this->label_styles . "'>";
		$field .= "\t\t<input type='checkbox' name='" . esc_attr( $id ) . "' value='" . esc_attr__( 'Yes', 'jetpack-forms' ) . "' " . $class . checked( (bool) $value, true, false ) . ' ' . ( $required ? "required aria-required='true'" : '' ) . "/> \n";
		$field .= "\t\t" . esc_html( $label ) . ( $required ? '<span>' . $required_field_text . '</span>' : '' );
		$field .= "</label>\n";
		$field .= "<div class='clear-form'></div>\n";
		return $field;
	}

	/**
	 * Return the HTML for the consent field.
	 *
	 * @param string $id field id.
	 * @param string $class html classes (can be set by the admin).
	 */
	private function render_consent_field( $id, $class ) {
		$consent_type    = 'explicit' === $this->get_attribute( 'consenttype' ) ? 'explicit' : 'implicit';
		$consent_message = 'explicit' === $consent_type ? $this->get_attribute( 'explicitconsentmessage' ) : $this->get_attribute( 'implicitconsentmessage' );

		$field = "<label class='grunion-field-label consent consent-" . $consent_type . "' style='" . $this->label_styles . "'>";

		if ( 'implicit' === $consent_type ) {
			$field .= "\t\t<input aria-hidden='true' type='checkbox' checked name='" . esc_attr( $id ) . "' value='" . esc_attr__( 'Yes', 'jetpack-forms' ) . "' style='display:none;' /> \n";
		} else {
			$field .= "\t\t<input type='checkbox' name='" . esc_attr( $id ) . "' value='" . esc_attr__( 'Yes', 'jetpack-forms' ) . "' " . $class . "/> \n";
		}
		$field .= "\t\t" . esc_html( $consent_message );
		$field .= "</label>\n";
		$field .= "<div class='clear-form'></div>\n";
		return $field;
	}

	/**
	 * Return the HTML for the multiple checkbox field.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 *
	 * @return string HTML
	 */
	public function render_checkbox_multiple_field( $id, $label, $value, $class, $required, $required_field_text ) {
		$field  = $this->render_label( '', $id, $label, $required, $required_field_text );
		$field .= '<div class="grunion-checkbox-multiple-options">';

		$field_style = 'style="' . $this->option_styles . '"';

		foreach ( (array) $this->get_attribute( 'options' ) as $option_index => $option ) {
			$option = Contact_Form_Plugin::strip_tags( $option );
			if ( is_string( $option ) && $option !== '' ) {
				$field .= "\t\t<label {$field_style} class='grunion-checkbox-multiple-label checkbox-multiple " . ( $this->is_error() ? ' form-error' : '' ) . "'>";
				$field .= "<input type='checkbox' name='" . esc_attr( $id ) . "[]' value='" . esc_attr( $this->get_option_value( $this->get_attribute( 'values' ), $option_index, $option ) ) . "' " . $class . checked( in_array( $option, (array) $value, true ), true, false ) . ' /> ';
				$field .= esc_html( $option ) . "</label>\n";
			}
		}
		$field .= '</div>';

		return $field;
	}

	/**
	 * Return the HTML for the select field.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 *
	 * @return string HTML
	 */
	public function render_select_field( $id, $label, $value, $class, $required, $required_field_text ) {
		$field  = $this->render_label( 'select', $id, $label, $required, $required_field_text );
		$field .= "\t<select name='" . esc_attr( $id ) . "' id='" . esc_attr( $id ) . "' " . $class . ( $required ? "required aria-required='true'" : '' ) . ">\n";

		if ( $this->get_attribute( 'togglelabel' ) ) {
			$field .= "\t\t<option>" . $this->get_attribute( 'togglelabel' ) . "</option>\n";
		}

		foreach ( (array) $this->get_attribute( 'options' ) as $option_index => $option ) {
			$option = Contact_Form_Plugin::strip_tags( $option );
			if ( is_string( $option ) && $option !== '' ) {
				$field .= "\t\t<option"
								. selected( $option, $value, false )
								. " value='" . esc_attr( $this->get_option_value( $this->get_attribute( 'values' ), $option_index, $option ) )
								. "'>" . esc_html( $option )
								. "</option>\n";
			}
		}
		$field .= "\t</select>\n";

		wp_enqueue_style(
			'jquery-ui-selectmenu',
			plugins_url( 'css/jquery-ui-selectmenu.css', __FILE__ ),
			array(),
			'1.13.2'
		);

		wp_enqueue_script( 'jquery-ui-selectmenu' );

		wp_enqueue_script(
			'contact-form-dropdown',
			plugins_url( 'js/dropdown.js', __FILE__ ),
			array( 'jquery', 'jquery-ui-selectmenu' ),
			\JETPACK__VERSION,
			true
		);

		return $field;
	}

	/**
	 * Return the HTML for the email field.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 * @param string $placeholder - the field placeholder content.
	 *
	 * @return string HTML
	 */
	public function render_date_field( $id, $label, $value, $class, $required, $required_field_text, $placeholder ) {

		$field  = $this->render_label( 'date', $id, $label, $required, $required_field_text );
		$field .= $this->render_input_field( 'text', $id, $value, $class, $placeholder, $required );

		/* For AMP requests, use amp-date-picker element: https://amp.dev/documentation/components/amp-date-picker */
		if ( class_exists( 'Jetpack_AMP_Support' ) && \Jetpack_AMP_Support::is_amp_request() ) {
			return sprintf(
				'<%1$s mode="overlay" layout="container" type="single" input-selector="[name=%2$s]">%3$s</%1$s>',
				'amp-date-picker',
				esc_attr( $id ),
				$field
			);
		}

		wp_enqueue_script(
			'grunion-frontend',
			Assets::get_file_url_for_environment(
				'_inc/build/contact-form/js/grunion-frontend.min.js',
				'modules/contact-form/js/grunion-frontend.js'
			),
			array( 'jquery', 'jquery-ui-datepicker' ),
			\JETPACK__VERSION,
			false
		);
		wp_enqueue_style( 'jp-jquery-ui-datepicker', plugins_url( 'css/jquery-ui-datepicker.css', __FILE__ ), array( 'dashicons' ), '1.0' );

		// Using Core's built-in datepicker localization routine
		wp_localize_jquery_ui_datepicker();
		return $field;
	}

	/**
	 * Return the HTML for the default field.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 * @param string $placeholder - the field placeholder content.
	 * @param string $type - the type.
	 *
	 * @return string HTML
	 */
	public function render_default_field( $id, $label, $value, $class, $required, $required_field_text, $placeholder, $type ) {
		$field  = $this->render_label( $type, $id, $label, $required, $required_field_text );
		$field .= $this->render_input_field( 'text', $id, $value, $class, $placeholder, $required );
		return $field;
	}

	/**
	 * Return the HTML for the outlined label.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 *
	 * @return string HTML
	 */
	public function render_outline_label( $id, $label, $required, $required_field_text ) {
		return '
			<div class="notched-label">
				<div class="notched-label__leading"></div>
				<div class="notched-label__notch">
					<label
						for="' . esc_attr( $id ) . '"
						class="notched-label__label ' . ( $this->is_error() ? ' form-error' : '' ) . '"
						style="' . $this->label_styles . '"
					>'
			. esc_html( $label )
			. ( $required ? '<span>' . $required_field_text . '</span>' : '' ) .
			'</label>
				</div>
				<div class="notched-label__trailing"></div>
			</div>';
	}

	/**
	 * Return the HTML for the animated label.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 *
	 * @return string HTML
	 */
	public function render_animated_label( $id, $label, $required, $required_field_text ) {
		return '
			<label
				for="' . esc_attr( $id ) . '"
				class="animated-label__label ' . ( $this->is_error() ? ' form-error' : '' ) . '"
				style="' . $this->label_styles . '"
			>'
			. esc_html( $label )
			. ( $required ? '<span>' . $required_field_text . '</span>' : '' ) .
			'</label>';
	}

	/**
	 * Return the HTML for the below label.
	 *
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text in the required text field.
	 *
	 * @return string HTML
	 */
	public function render_below_label( $id, $label, $required, $required_field_text ) {
		return '
			<label
				for="' . esc_attr( $id ) . '"
				class="below-label__label ' . ( $this->is_error() ? ' form-error' : '' ) . '"
			>'
			. esc_html( $label )
			. ( $required ? '<span>' . $required_field_text . '</span>' : '' ) .
			'</label>';
	}

	/**
	 * Return the HTML for the email field.
	 *
	 * @param string $type - the type.
	 * @param int    $id - the ID.
	 * @param string $label - the label.
	 * @param string $value - the value of the field.
	 * @param string $class - the field class.
	 * @param string $placeholder - the field placeholder content.
	 * @param bool   $required - if the field is marked as required.
	 * @param string $required_field_text - the text for a field marked as required.
	 *
	 * @return string HTML
	 */
	public function render_field( $type, $id, $label, $value, $class, $placeholder, $required, $required_field_text ) {
		$class .= ' grunion-field';

		if ( $type === 'select' ) {
			$class .= ' contact-form-dropdown';
		}

		$form_style = $this->get_form_style();
		if ( ! empty( $form_style ) && $form_style !== 'default' ) {
			if ( empty( $placeholder ) ) {
				$placeholder .= ' ';
			} else {
				$class .= ' has-placeholder';
			}
		}

		$field_placeholder = ( ! empty( $placeholder ) ) ? "placeholder='" . esc_attr( $placeholder ) . "'" : '';
		$field_class       = "class='" . trim( esc_attr( $type ) . ' ' . esc_attr( $class ) ) . "' ";
		$wrap_classes      = empty( $class ) ? '' : implode( '-wrap ', array_filter( explode( ' ', $class ) ) ) . '-wrap'; // this adds

		if ( $type === 'select' ) {
			$wrap_classes .= ' ui-front';
		}

		if ( empty( $label ) ) {
			$wrap_classes .= ' no-label';
		}

		$shell_field_class = "class='grunion-field-" . trim( esc_attr( $type ) . '-wrap ' . esc_attr( $wrap_classes ) ) . "' ";

		/**
		 * Filter the Contact Form required field text
		 *
		 * @module contact-form
		 *
		 * @since 3.8.0
		 *
		 * @param string $var Required field text. Default is "(required)".
		 */
		$required_field_text = esc_html( apply_filters( 'jetpack_required_field_text', $required_field_text ) );

		$block_style = 'style="' . $this->block_styles . '"';

		$field = "\n<div {$block_style} {$shell_field_class} >\n"; // new in Jetpack 6.8.0

		// If they are logged in, and this is their site, don't pre-populate fields
		if ( current_user_can( 'manage_options' ) ) {
			$value = '';
		}

		switch ( $type ) {
			case 'email':
				$field .= $this->render_email_field( $id, $label, $value, $field_class, $required, $required_field_text, $field_placeholder );
				break;
			case 'telephone':
				$field .= $this->render_telephone_field( $id, $label, $value, $field_class, $required, $required_field_text, $field_placeholder );
				break;
			case 'url':
				$field .= $this->render_url_field( $id, $label, $value, $field_class, $required, $required_field_text, $field_placeholder );
				break;
			case 'textarea':
				$field .= $this->render_textarea_field( $id, $label, $value, $field_class, $required, $required_field_text, $field_placeholder );
				break;
			case 'radio':
				$field .= $this->render_radio_field( $id, $label, $value, $field_class, $required, $required_field_text, $field_placeholder );
				break;
			case 'checkbox':
				$field .= $this->render_checkbox_field( $id, $label, $value, $field_class, $required, $required_field_text );
				break;
			case 'checkbox-multiple':
				$field .= $this->render_checkbox_multiple_field( $id, $label, $value, $field_class, $required, $required_field_text );
				break;
			case 'select':
				$field .= $this->render_select_field( $id, $label, $value, $field_class, $required, $required_field_text );
				break;
			case 'date':
				$field .= $this->render_date_field( $id, $label, $value, $field_class, $required, $required_field_text, $field_placeholder );
				break;
			case 'consent':
				$field .= $this->render_consent_field( $id, $field_class );
				break;
			default: // text field
				$field .= $this->render_default_field( $id, $label, $value, $field_class, $required, $required_field_text, $field_placeholder, $type );
				break;
		}

		if ( ! empty( $form_style ) && $form_style !== 'default' && ! in_array( $type, array( 'checkbox', 'consent' ), true ) ) {
			switch ( $form_style ) {
				case 'outlined':
					$field .= $this->render_outline_label( $id, $label, $required, $required_field_text );
					break;
				case 'animated':
					$field .= $this->render_animated_label( $id, $label, $required, $required_field_text );
					break;
				case 'below':
					$field .= $this->render_below_label( $id, $label, $required, $required_field_text );
					break;
			}
		}

		$field .= "\t</div>\n";
		return $field;
	}

	/**
	 * Overrides input type (maybe).
	 *
	 * @module contact-form
	 *
	 * Custom input types, like URL, will rely on browser's implementation to validate
	 * the value. If the input carries a data-type-override, we allow to override
	 * the type at render/submit so it can be validated with custom patterns.
	 * This method will try to match the input's type to a custom data-type-override
	 * attribute and return it. Defaults to input's type.
	 *
	 * @return string The input's type attribute or the overriden type.
	 */
	private function maybe_override_type() {
		// Define overridables-to-custom-type, extend as needed.
		$overridable_types = array( 'text' => array( 'url' ) );
		$type              = $this->get_attribute( 'type' );

		if ( ! array_key_exists( $type, $overridable_types ) ) {
			return $type;
		}

		$override_type = $this->get_attribute( 'data-type-override' );

		if ( in_array( $override_type, $overridable_types[ $type ], true ) ) {
			return $override_type;
		}

		return $type;
	}

	/**
	 * Gets the form style based on its CSS class.
	 *
	 * @return string The form style type.
	 */
	private function get_form_style() {
		$class_name = $this->form->get_attribute( 'className' );
		preg_match( '/is-style-([^\s]+)/i', $class_name, $matches );
		return count( $matches ) >= 2 ? $matches[1] : null;
	}
}
