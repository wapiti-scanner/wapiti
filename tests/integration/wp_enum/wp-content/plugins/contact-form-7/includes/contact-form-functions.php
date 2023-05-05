<?php
/**
 * Contact form helper functions
 */


/**
 * Wrapper function of WPCF7_ContactForm::get_instance().
 *
 * @param WPCF7_ContactForm|WP_Post|int $post Object or post ID.
 * @return WPCF7_ContactForm|null Contact form object. Null if unset.
 */
function wpcf7_contact_form( $post ) {
	return WPCF7_ContactForm::get_instance( $post );
}


/**
 * Searches for a contact form by an old unit ID.
 *
 * @param int $old_id Old unit ID.
 * @return WPCF7_ContactForm Contact form object.
 */
function wpcf7_get_contact_form_by_old_id( $old_id ) {
	global $wpdb;

	$q = "SELECT post_id FROM $wpdb->postmeta WHERE meta_key = '_old_cf7_unit_id'"
		. $wpdb->prepare( " AND meta_value = %d", $old_id );

	if ( $new_id = $wpdb->get_var( $q ) ) {
		return wpcf7_contact_form( $new_id );
	}
}


/**
 * Searches for a contact form by title.
 *
 * @param string $title Title of contact form.
 * @return WPCF7_ContactForm|null Contact form object if found, null otherwise.
 */
function wpcf7_get_contact_form_by_title( $title ) {
	if ( ! is_string( $title ) or '' === $title ) {
		return null;
	}

	$contact_forms = WPCF7_ContactForm::find( array(
		'title' => $title,
		'posts_per_page' => 1,
	) );

	if ( $contact_forms ) {
		return wpcf7_contact_form( reset( $contact_forms ) );
	}
}


/**
 * Wrapper function of WPCF7_ContactForm::get_current().
 *
 * @return WPCF7_ContactForm Contact form object.
 */
function wpcf7_get_current_contact_form() {
	if ( $current = WPCF7_ContactForm::get_current() ) {
		return $current;
	}
}


/**
 * Returns true if it is in the state that a non-Ajax submission is accepted.
 */
function wpcf7_is_posted() {
	if ( ! $contact_form = wpcf7_get_current_contact_form() ) {
		return false;
	}

	return $contact_form->is_posted();
}


/**
 * Retrieves the user input value through a non-Ajax submission.
 *
 * @param string $name Name of form control.
 * @param string $default_value Optional default value.
 * @return string The user input value through the form-control.
 */
function wpcf7_get_hangover( $name, $default_value = null ) {
	if ( ! wpcf7_is_posted() ) {
		return $default_value;
	}

	$submission = WPCF7_Submission::get_instance();

	if ( ! $submission
	or $submission->is( 'mail_sent' ) ) {
		return $default_value;
	}

	return isset( $_POST[$name] ) ? wp_unslash( $_POST[$name] ) : $default_value;
}


/**
 * Retrieves an HTML snippet of validation error on the given form control.
 *
 * @param string $name Name of form control.
 * @return string Validation error message in a form of HTML snippet.
 */
function wpcf7_get_validation_error( $name ) {
	if ( ! $contact_form = wpcf7_get_current_contact_form() ) {
		return '';
	}

	return $contact_form->validation_error( $name );
}


/**
 * Returns a reference key to a validation error message.
 *
 * @param string $name Name of form control.
 * @param string $unit_tag Optional. Unit tag of the contact form.
 * @return string Reference key code.
 */
function wpcf7_get_validation_error_reference( $name, $unit_tag = '' ) {
	if ( '' === $unit_tag ) {
		$contact_form = wpcf7_get_current_contact_form();

		if ( $contact_form and $contact_form->validation_error( $name ) ) {
			$unit_tag = $contact_form->unit_tag();
		} else {
			return null;
		}
	}

	return preg_replace( '/[^0-9a-z_-]+/i', '',
		sprintf(
			'%1$s-ve-%2$s',
			$unit_tag,
			$name
		)
	);
}


/**
 * Retrieves a message for the given status.
 */
function wpcf7_get_message( $status ) {
	if ( ! $contact_form = wpcf7_get_current_contact_form() ) {
		return '';
	}

	return $contact_form->message( $status );
}


/**
 * Returns a class names list for a form-tag of the specified type.
 *
 * @param string $type Form-tag type.
 * @param string $default_classes Optional default classes.
 * @return string Whitespace-separated list of class names.
 */
function wpcf7_form_controls_class( $type, $default_classes = '' ) {
	$type = trim( $type );
	$default_classes = array_filter( explode( ' ', $default_classes ) );

	$classes = array_merge( array( 'wpcf7-form-control' ), $default_classes );

	$typebase = rtrim( $type, '*' );
	$required = ( '*' == substr( $type, -1 ) );

	$classes[] = 'wpcf7-' . $typebase;

	if ( $required ) {
		$classes[] = 'wpcf7-validates-as-required';
	}

	$classes = array_unique( $classes );

	return implode( ' ', $classes );
}


/**
 * Callback function for the contact-form-7 shortcode.
 */
function wpcf7_contact_form_tag_func( $atts, $content = null, $code = '' ) {
	if ( is_feed() ) {
		return '[contact-form-7]';
	}

	if ( 'contact-form-7' == $code ) {
		$atts = shortcode_atts(
			array(
				'id' => 0,
				'title' => '',
				'html_id' => '',
				'html_name' => '',
				'html_title' => '',
				'html_class' => '',
				'output' => 'form',
			),
			$atts, 'wpcf7'
		);

		$id = (int) $atts['id'];
		$title = trim( $atts['title'] );

		if ( ! $contact_form = wpcf7_contact_form( $id ) ) {
			$contact_form = wpcf7_get_contact_form_by_title( $title );
		}

	} else {
		if ( is_string( $atts ) ) {
			$atts = explode( ' ', $atts, 2 );
		}

		$id = (int) array_shift( $atts );
		$contact_form = wpcf7_get_contact_form_by_old_id( $id );
	}

	if ( ! $contact_form ) {
		return sprintf(
			'<p class="wpcf7-contact-form-not-found"><strong>%1$s</strong> %2$s</p>',
			esc_html( __( 'Error:', 'contact-form-7' ) ),
			esc_html( __( "Contact form not found.", 'contact-form-7' ) )
		);
	}

	$callback = function ( $contact_form, $atts ) {
		return $contact_form->form_html( $atts );
	};

	return wpcf7_switch_locale(
		$contact_form->locale(),
		$callback,
		$contact_form, $atts
	);
}


/**
 * Saves the contact form data.
 */
function wpcf7_save_contact_form( $args = '', $context = 'save' ) {
	$args = wp_parse_args( $args, array(
		'id' => -1,
		'title' => null,
		'locale' => null,
		'form' => null,
		'mail' => null,
		'mail_2' => null,
		'messages' => null,
		'additional_settings' => null,
	) );

	$args = wp_unslash( $args );

	$args['id'] = (int) $args['id'];

	if ( -1 == $args['id'] ) {
		$contact_form = WPCF7_ContactForm::get_template();
	} else {
		$contact_form = wpcf7_contact_form( $args['id'] );
	}

	if ( empty( $contact_form ) ) {
		return false;
	}

	if ( null !== $args['title'] ) {
		$contact_form->set_title( $args['title'] );
	}

	if ( null !== $args['locale'] ) {
		$contact_form->set_locale( $args['locale'] );
	}

	$properties = array();

	if ( null !== $args['form'] ) {
		$properties['form'] = wpcf7_sanitize_form( $args['form'] );
	}

	if ( null !== $args['mail'] ) {
		$properties['mail'] = wpcf7_sanitize_mail( $args['mail'] );
		$properties['mail']['active'] = true;
	}

	if ( null !== $args['mail_2'] ) {
		$properties['mail_2'] = wpcf7_sanitize_mail( $args['mail_2'] );
	}

	if ( null !== $args['messages'] ) {
		$properties['messages'] = wpcf7_sanitize_messages( $args['messages'] );
	}

	if ( null !== $args['additional_settings'] ) {
		$properties['additional_settings'] = wpcf7_sanitize_additional_settings(
			$args['additional_settings']
		);
	}

	$contact_form->set_properties( $properties );

	do_action( 'wpcf7_save_contact_form', $contact_form, $args, $context );

	if ( 'save' == $context ) {
		$contact_form->save();
	}

	return $contact_form;
}


/**
 * Sanitizes the form property data.
 */
function wpcf7_sanitize_form( $input, $default_template = '' ) {
	if ( null === $input ) {
		return $default_template;
	}

	$output = trim( $input );

	if ( ! current_user_can( 'unfiltered_html' ) ) {
		$output = wpcf7_kses( $output, 'form' );
	}

	return $output;
}


/**
 * Sanitizes the mail property data.
 */
function wpcf7_sanitize_mail( $input, $defaults = array() ) {
	$input = wp_parse_args( $input, array(
		'active' => false,
		'subject' => '',
		'sender' => '',
		'recipient' => '',
		'body' => '',
		'additional_headers' => '',
		'attachments' => '',
		'use_html' => false,
		'exclude_blank' => false,
	) );

	$input = wp_parse_args( $input, $defaults );

	$output = array();
	$output['active'] = (bool) $input['active'];
	$output['subject'] = trim( $input['subject'] );
	$output['sender'] = trim( $input['sender'] );
	$output['recipient'] = trim( $input['recipient'] );
	$output['body'] = trim( $input['body'] );

	if ( ! current_user_can( 'unfiltered_html' ) ) {
		$output['body'] = wpcf7_kses( $output['body'], 'mail' );
	}

	$output['additional_headers'] = '';

	$headers = str_replace( "\r\n", "\n", $input['additional_headers'] );
	$headers = explode( "\n", $headers );

	foreach ( $headers as $header ) {
		$header = trim( $header );

		if ( '' !== $header ) {
			$output['additional_headers'] .= $header . "\n";
		}
	}

	$output['additional_headers'] = trim( $output['additional_headers'] );
	$output['attachments'] = trim( $input['attachments'] );
	$output['use_html'] = (bool) $input['use_html'];
	$output['exclude_blank'] = (bool) $input['exclude_blank'];

	return $output;
}


/**
 * Sanitizes the messages property data.
 */
function wpcf7_sanitize_messages( $input, $defaults = array() ) {
	$output = array();

	foreach ( wpcf7_messages() as $key => $val ) {
		if ( isset( $input[$key] ) ) {
			$output[$key] = trim( $input[$key] );
		} elseif ( isset( $defaults[$key] ) ) {
			$output[$key] = $defaults[$key];
		}
	}

	return $output;
}


/**
 * Sanitizes the additional settings property data.
 */
function wpcf7_sanitize_additional_settings( $input, $default_template = '' ) {
	if ( null === $input ) {
		return $default_template;
	}

	$output = trim( $input );
	return $output;
}
