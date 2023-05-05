<?php
/**
 * Post to URL using Jetpack Contact Forms.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Forms\Service;

/**
 * Class Post_To_Url
 *
 * Hooks on Jetpack's Contact form to post form data to some URL.
 */
class Post_To_Url {
	/**
	 * Singleton instance
	 *
	 * @var Post_To_Url
	 */
	private static $instance = null;

	/**
	 * Initialize and return singleton instance.
	 *
	 * @return Post_To_Url
	 */
	public static function init() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Post_To_Url class constructor.
	 * Hooks on `grunion_after_feedback_post_inserted` action to send form data to specified URL.
	 * NOTE: As a singleton, this constructor is private and only callable from ::init, which will return the singleton instance,
	 * effectively preventing multiple instances of this class (hence, multiple hooks triggering the POST request).
	 */
	private function __construct() {
		add_action( 'grunion_after_feedback_post_inserted', array( $this, 'feedback_post_hook' ), 10, 4 );
	}

	/**
	 * Get the setup for the post to URL.
	 * This is a helper function to get the setup for the post to URL.
	 * It will return false if the setup is not valid.
	 *
	 * @param array $attributes - the attributes of the contact form.
	 * @return array|bool
	 */
	private function get_setup( $attributes = array() ) {
		$defaults = array(
			'url'      => '',
			'verified' => false,
			'format'   => 'urlencoded',
			'enabled'  => false,
		);

		// Backwards compatibility setup for Salesforce.
		if ( ! empty( $attributes['salesforceData'] ) && ! empty( $attributes['salesforceData']['organizationId'] ) ) {
			$defaults['url']      = 'https://webto.salesforce.com/servlet/servlet.WebToLead?encoding=UTF-8';
			$defaults['format']   = 'urlencoded';
			$defaults['enabled']  = true;
			$defaults['verified'] = true;
		}

		// if new setup for postToUrl is present, use it on top of the defaults (hence, salesforceData will be stepped on)
		$setup = wp_parse_args( ! empty( $attributes['postToUrl'] ) ? $attributes['postToUrl'] : array(), $defaults );
		if ( empty( $setup['enabled'] ) || empty( $setup['url'] ) ) {
			return false;
		}

		if ( ! in_array( $setup['format'], array( 'urlencoded', 'json' ), true ) ) {
			return false;
		}

		// TODO: eventually, I'd like us to verify the URL and invalidate the setup, but for now, we'll just trust the user.
		return $setup;
	}

	/**
	 * Hook on `grunion_after_feedback_post_inserted` action to send form data to specified URL.
	 *
	 * @param int   $post_id - the post_id for the CPT that is created.
	 * @param array $form - Automattic\Jetpack\Forms\ContactForm\Contact_Form instance.
	 * @param bool  $is_spam - marked as spam by Akismet(?).
	 * @param array $entry_values - extra fields added to from the contact form.
	 *
	 * @return null|void
	 */
	private function feedback_post_hook( $post_id, $form, $is_spam, $entry_values ) {
		if ( ! is_a( $form, 'Automattic\Jetpack\Forms\ContactForm\Contact_Form' ) ) {
			return;
		}

		// if spam (hinted by akismet?), don't process
		if ( $is_spam ) {
			return;
		}

		$setup = $this->get_setup( $form->attributes );

		if ( ! $setup ) {
			return;
		}

		$form_data = $this->get_form_data( $form, $entry_values );

		$result = $this->post_to_url( $form_data, $setup );

		if ( is_wp_error( $result ) ) {
			// phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable -- figuring out what to do with the error.
			$message = sprintf(
				'JETPACK %s - Jetpack Forms: POSTing to URL failed: "%s" at %s',
				constant( 'JETPACK__VERSION' ),
				$result->get_error_message(),
				$entry_values['entry_permalink']
			);
			// TODO: not sure what to do with the error. Is not useful at frontend and it would be difficult to
			// solve for a non tech-savvy user. We should log it somewhere, but it could turn messy.
			// Maybe email the owner?
		}
	}

	/**
	 * POST to URL
	 *
	 * @param array $data The data key/value pairs to send in POST.
	 * @param array $options Options for POST.
	 *
	 * @return array|WP_Error The result value from wp_remote_post
	 *
	 * TODO: do complex fields (MC, etc) need to be handled differently? JSON should be fine, but URLencoded might need to be serialized.
	 */
	private function post_to_url( $data, $options = array() ) {
		global $wp_version;

		$user_agent = "WordPress/{$wp_version} | Jetpack/" . constant( 'JETPACK__VERSION' ) . '; ' . get_bloginfo( 'url' );
		$url        = $options['url'];
		$format     = $options['format'] === 'urlencoded' ? 'application/x-www-form-urlencoded' : 'application/json';
		$args       = array(
			'body'      => $data,
			'headers'   => array(
				'Content-Type' => $format,
				'user-agent'   => $user_agent,
			),
			'sslverify' => empty( $options['sslverify'] ) ? false : $options['sslverify'],
		);
		// phpcs:ignore Universal.CodeAnalysis.ConstructorDestructorReturn.ReturnValueFound -- this is no constructor
		return wp_remote_post( $url, $args );
	}

	/**
	 * Gather fields key/value pairs from the form
	 * Sanitizes the hidden fields values
	 *
	 * @param Automattic\Jetpack\Forms\ContactForm\Contact_Form $form The form instance being processed/submitted.
	 * @param array                                             $entry_values The feedback entry values.
	 */
	private function get_form_data( $form, $entry_values ) {
		$fields = array();
		foreach ( $form->fields as $field ) {
			$fields[ $field->get_attribute( 'id' ) ] = $field->value;
		}

		// Right in the middle, backwards compatibility for salesforceData implementation.
		if ( ! empty( $form->attributes['salesforceData'] ) && ! empty( $form->attributes['salesforceData']['organizationId'] ) ) {
			$fields['oid']         = sanitize_text_field( $form->attributes['salesforceData']['organizationId'] );
			$fields['lead_source'] = $entry_values['entry_permalink'];
		}

		if ( ! empty( $form->attributes['hiddenFields'] ) ) {
			foreach ( $form->attributes['hiddenFields'] as $hidden_field ) {
				$fields[ $hidden_field['name'] ] = sanitize_text_field( $hidden_field['value'] );
			}
		}

		return $fields;
	}
}
