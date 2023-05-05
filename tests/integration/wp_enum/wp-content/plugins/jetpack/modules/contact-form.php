<?php
/**
 * Contact form module.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Forms\Jetpack_Forms;

/**
 * Module Name: Contact Form
 * Module Description: Add a customizable contact form to any post or page using the Jetpack Form Block.
 * Sort Order: 15
 * Recommendation Order: 14
 * First Introduced: 1.3
 * Requires Connection: No
 * Auto Activate: Yes
 * Module Tags: Other
 * Feature: Writing
 * Additional Search Queries: contact, form, grunion, feedback, submission, contact form, email, feedback, contact form plugin, custom form, custom form plugin, form builder, forms, form maker, survey, contact by jetpack, contact us, forms free
 */

/**
 * Whether to load the newer Jetpack Forms package.
 *
 * @use add_filter( 'jetpack_contact_form_use_package', '__return_true' );
 * @module contact-form
 *
 * @since 11.8
 *
 * @param bool $load_contact_form_package Load Jetpack Forms package. Default to false.
 */
if ( apply_filters( 'jetpack_contact_form_use_package', false ) ) {
	Jetpack_Forms::load_contact_form();
	return true; // Not returning true will cause the module to become deactivated.
}

require_once __DIR__ . '/contact-form/grunion-contact-form.php';

/*
 * Filters if the new Contact Form Editor View should be used.
 *
 * A temporary filter to disable the new Editor View for the older UI.
 * Please note this filter and the old UI will be removed in the future.
 * Expected to be removed in Jetpack 5.8 or if a security issue merits removing the old code sooner.
 *
 * @since 5.2.0
 *
 * @param boolean $view Use new Editor View. Default true.
 */
if ( is_admin() && apply_filters( 'tmp_grunion_allow_editor_view', true ) ) {
	require_once __DIR__ . '/contact-form/grunion-editor-view.php';
}

/**
 * Register Jetpack Form patterns
 */
function jetpack_form_register_pattern() {
	$category_slug = 'forms';
	register_block_pattern_category( $category_slug, array( 'label' => __( 'Forms', 'jetpack' ) ) );

	$patterns = array(
		'contact-form'      => array(
			'title'      => 'Contact Form',
			'blockTypes' => array( 'jetpack/contact-form' ),
			'categories' => array( $category_slug ),
			'content'    => '<!-- wp:jetpack/contact-form {"style":{"spacing":{"padding":{"top":"16px","right":"16px","bottom":"16px","left":"16px"}}}} -->
				<div class="wp-block-jetpack-contact-form" style="padding-top:16px;padding-right:16px;padding-bottom:16px;padding-left:16px">
					<!-- wp:jetpack/field-name {"required":true} /-->
					<!-- wp:jetpack/field-email {"required":true} /-->
					<!-- wp:jetpack/field-textarea /-->
					<!-- wp:jetpack/button {"element":"button","text":"Contact Us","lock":{"remove":true}} /-->
				</div>
				<!-- /wp:jetpack/contact-form -->',
		),
		'newsletter-form'   => array(
			'title'      => 'Newsletter Subscription Form',
			'blockTypes' => array( 'jetpack/contact-form' ),
			'categories' => array( $category_slug ),
			'content'    => '<!-- wp:jetpack/contact-form {"style":{"spacing":{"padding":{"top":"16px","right":"16px","bottom":"16px","left":"16px"}}}} -->
				<div class="wp-block-jetpack-contact-form" style="padding-top:16px;padding-right:16px;padding-bottom:16px;padding-left:16px">
					<!-- wp:jetpack/field-name {"required":true} /-->
					<!-- wp:jetpack/field-email {"required":true} /-->
					<!-- wp:jetpack/field-consent /-->
					<!-- wp:jetpack/button {"element":"button","text":"Subscribe","lock":{"remove":true}} /-->
				</div>
				<!-- /wp:jetpack/contact-form -->',
		),
		'rsvp-form'         => array(
			'title'      => 'RSVP Form',
			'blockTypes' => array( 'jetpack/contact-form' ),
			'categories' => array( $category_slug ),
			'content'    => '<!-- wp:jetpack/contact-form {"subject":"A new RSVP from your website","style":{"spacing":{"padding":{"top":"16px","right":"16px","bottom":"16px","left":"16px"}}}} -->
				<div class="wp-block-jetpack-contact-form" style="padding-top:16px;padding-right:16px;padding-bottom:16px;padding-left:16px">
					<!-- wp:jetpack/field-name {"required":true} /-->
					<!-- wp:jetpack/field-email {"required":true} /-->
					<!-- wp:jetpack/field-radio {"label":"Attending?","required":true,"options":["Yes","No"]} /-->
					<!-- wp:jetpack/field-textarea {"label":"Other Details"} /-->
					<!-- wp:jetpack/button {"element":"button","text":"Send RSVP","lock":{"remove":true}} /-->
				</div>
				<!-- /wp:jetpack/contact-form -->',
		),
		'registration-form' => array(
			'title'      => 'Registration Form',
			'blockTypes' => array( 'jetpack/contact-form' ),
			'categories' => array( $category_slug ),
			'content'    => '<!-- wp:jetpack/contact-form {"subject":"A new registration from your website","style":{"spacing":{"padding":{"top":"16px","right":"16px","bottom":"16px","left":"16px"}}}} -->
				<div class="wp-block-jetpack-contact-form" style="padding-top:16px;padding-right:16px;padding-bottom:16px;padding-left:16px">
					<!-- wp:jetpack/field-name {"required":true} /-->
					<!-- wp:jetpack/field-email {"required":true} /-->
					<!-- wp:jetpack/field-telephone {"label":"Phone Number"} /-->
					<!-- wp:jetpack/field-select {"label":"How did you hear about us?","options":["Search Engine","Social Media","TV","Radio","Friend or Family"]} /-->
					<!-- wp:jetpack/field-textarea {"label":"Other Details"} /-->
					<!-- wp:jetpack/button {"element":"button","text":"Send","lock":{"remove":true}} /-->
				</div>
				<!-- /wp:jetpack/contact-form -->',
		),
		'appointment-form'  => array(
			'title'      => 'Appointment Form',
			'blockTypes' => array( 'jetpack/contact-form' ),
			'categories' => array( $category_slug ),
			'content'    => '<!-- wp:jetpack/contact-form {"subject":"A new appointment booked from your website","style":{"spacing":{"padding":{"top":"16px","right":"16px","bottom":"16px","left":"16px"}}}} -->
				<div class="wp-block-jetpack-contact-form" style="padding-top:16px;padding-right:16px;padding-bottom:16px;padding-left:16px">
					<!-- wp:jetpack/field-name {"required":true} /-->
					<!-- wp:jetpack/field-email {"required":true} /-->
					<!-- wp:jetpack/field-telephone {"required":true} /-->
					<!-- wp:jetpack/field-date {"label":"Date","required":true} /-->
					<!-- wp:jetpack/field-radio {"label":"Time","required":true,"options":["Morning","Afternoon"]} /-->
					<!-- wp:jetpack/field-textarea {"label":"Notes"} /-->
					<!-- wp:jetpack/button {"element":"button","text":"Book Appointment","lock":{"remove":true}} /-->
				</div>
				<!-- /wp:jetpack/contact-form -->',
		),
		'feedback-form'     => array(
			'title'      => 'Feedback Form',
			'blockTypes' => array( 'jetpack/contact-form' ),
			'categories' => array( $category_slug ),
			'content'    => '<!-- wp:jetpack/contact-form {"subject":"New feedback received from your website","style":{"spacing":{"padding":{"top":"16px","right":"16px","bottom":"16px","left":"16px"}}}} -->
				<div class="wp-block-jetpack-contact-form" style="padding-top:16px;padding-right:16px;padding-bottom:16px;padding-left:16px">
					<!-- wp:jetpack/field-name {"required":true} /-->
					<!-- wp:jetpack/field-email {"required":true} /-->
					<!-- wp:jetpack/field-radio {"label":"Please rate our website","required":true,"options":["1 - Very Bad","2 - Poor","3 - Average","4 - Good","5 - Excellent"]} /-->
					<!-- wp:jetpack/field-textarea {"label":"How could we improve?"} /-->
					<!-- wp:jetpack/button {"element":"button","text":"Send Feedback","lock":{"remove":true}} /-->
				</div>
				<!-- /wp:jetpack/contact-form -->',
		),
	);

	foreach ( $patterns as $name => $pattern ) {
		register_block_pattern( $name, $pattern );
	}
}

add_action( 'init', 'jetpack_form_register_pattern' );
