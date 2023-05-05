<?php
/**
 * Constant Contact module main file
 *
 * @link https://contactform7.com/constant-contact-integration/
 */

wpcf7_include_module_file( 'constant-contact/service.php' );
wpcf7_include_module_file( 'constant-contact/contact-post-request.php' );
wpcf7_include_module_file( 'constant-contact/contact-form-properties.php' );
wpcf7_include_module_file( 'constant-contact/doi.php' );


add_action(
	'wpcf7_init',
	'wpcf7_constant_contact_register_service',
	20, 0
);

/**
 * Registers the Constant Contact service.
 */
function wpcf7_constant_contact_register_service() {
	$integration = WPCF7_Integration::get_instance();

	$service = WPCF7_ConstantContact::get_instance();
	$integration->add_service( 'constant_contact', $service );
}


add_action( 'wpcf7_submit', 'wpcf7_constant_contact_submit', 10, 2 );

/**
 * Callback to the wpcf7_submit action hook. Creates a contact
 * based on the submission.
 */
function wpcf7_constant_contact_submit( $contact_form, $result ) {
	$service = WPCF7_ConstantContact::get_instance();

	if ( ! $service->is_active() ) {
		return;
	}

	if ( $contact_form->in_demo_mode() ) {
		return;
	}

	$do_submit = true;

	if ( empty( $result['status'] )
	or ! in_array( $result['status'], array( 'mail_sent' ) ) ) {
		$do_submit = false;
	}

	$prop = $contact_form->prop( 'constant_contact' );

	if ( empty( $prop['enable_contact_list'] ) ) {
		$do_submit = false;
	}

	$do_submit = apply_filters( 'wpcf7_constant_contact_submit',
		$do_submit, $contact_form, $result
	);

	if ( ! $do_submit ) {
		return;
	}

	$submission = WPCF7_Submission::get_instance();

	$consented = true;

	foreach ( $contact_form->scan_form_tags( 'feature=name-attr' ) as $tag ) {
		if ( $tag->has_option( 'consent_for:constant_contact' )
		and null == $submission->get_posted_data( $tag->name ) ) {
			$consented = false;
			break;
		}
	}

	if ( ! $consented ) {
		return;
	}

	$request_builder_class_name = apply_filters(
		'wpcf7_constant_contact_contact_post_request_builder',
		'WPCF7_ConstantContact_ContactPostRequest'
	);

	if ( ! class_exists( $request_builder_class_name ) ) {
		return;
	}

	$request_builder = new $request_builder_class_name;
	$request_builder->build( $submission );

	if ( ! $request_builder->is_valid() ) {
		return;
	}

	$email = $request_builder->get_email_address();

	if ( $email ) {
		if ( $service->email_exists( $email ) ) {
			return;
		}

		$token = null;

		do_action_ref_array( 'wpcf7_doi', array(
			'wpcf7_constant_contact',
			array(
				'email_to' => $email,
				'properties' => $request_builder->to_array(),
			),
			&$token,
		) );

		if ( isset( $token ) ) {
			return;
		}
	}

	$service->create_contact( $request_builder->to_array() );
}
