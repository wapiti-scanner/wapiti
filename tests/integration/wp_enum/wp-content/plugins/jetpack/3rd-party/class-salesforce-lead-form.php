<?php
/**
 * Salesforce Lead Form using Jetpack Contact Forms.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack;

/**
 * Class Salesforce_Lead_Form
 *
 * Hooks on Jetpack's Contact form to send form data to Salesforce.
 */
class Salesforce_Lead_Form {
	/**
	 * Salesforce_Contact_Form constructor.
	 * Hooks on `grunion_after_feedback_post_inserted` action to send form data to Salesforce.
	 */
	public static function initialize() {
		add_action( 'grunion_after_feedback_post_inserted', array( __CLASS__, 'process_salesforce_form' ), 10, 4 );
	}

	/**
	 * Process Salesforce Lead forms
	 *
	 * @param int   $post_id - the post_id for the CPT that is created.
	 * @param array $fields - Grunion_Contact_Form_Field array.
	 * @param bool  $is_spam - marked as spam by Akismet(?).
	 * @param array $entry_values - extra fields added to from the contact form.
	 *
	 * @return null|void
	 */
	public static function process_salesforce_form( $post_id, $fields, $is_spam, $entry_values ) {
		if ( ! is_array( $fields ) ) {
			// nothing to do, also prevent hook from processing actions triggered with different args
			return;
		}

		// if spam (hinted by akismet?), don't process
		if ( $is_spam ) {
			return;
		}

		$blocks = parse_blocks( get_the_content() );

		$filtered_blocks = self::get_salesforce_contact_form_blocks( $blocks );

		// no contact-form blocks with salesforceData and organizationId, move on
		if ( empty( $filtered_blocks ) ) {
			return;
		}

		// more than one form on post, skipping process
		if ( count( $filtered_blocks ) > 1 ) {
			return;
		}

		$attrs           = $filtered_blocks[0]['attrs']['salesforceData'];
		$organization_id = $attrs['organizationId'];
		// Double sanity check: no organization ID? Abort.
		if ( empty( $organization_id ) ) {
			return;
		}

		$keyed_fields = array_map(
			function ( $field ) {
				return $field->value;
			},
			$fields
		);

		// this is yet TBD, campaign IDs are hard to get from SF app/UI, but if
		// the user filled it, then send as API field Campaign_ID
		if ( ! empty( $attrs['campaignId'] ) ) {
			$keyed_fields['Campaign_ID'] = $attrs['campaignId'];
		}

		// add post/page URL as lead_source
		$keyed_fields['lead_source'] = $entry_values['entry_permalink'];
		$keyed_fields['oid']         = $organization_id;

		// we got this far, try and send it. Need to check for errors on submit
		try {
			self::send_to_salesforce( $keyed_fields );
		} catch ( \Exception $e ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_trigger_error
			trigger_error( sprintf( 'Jetpack Form: Sending lead to Salesforce failed: %s', esc_html( $e->getMessage() ) ) );
		}
	}

	/**
	 * POST to Salesforce WebToLead servlet
	 *
	 * @param array $data The data key/value pairs to send in POST.
	 * @param array $options Options for POST.
	 *
	 * @return array|WP_Error The result value from wp_remote_post
	 */
	public static function send_to_salesforce( $data, $options = array() ) {
		global $wp_version;

		$user_agent = "WordPress/{$wp_version} | Jetpack/" . constant( 'JETPACK__VERSION' ) . '; ' . get_bloginfo( 'url' );
		$url        = 'https://webto.salesforce.com/servlet/servlet.WebToLead?encoding=UTF-8';
		$args       = array(
			'body'      => $data,
			'headers'   => array(
				'Content-Type' => 'application/x-www-form-urlencoded',
				'user-agent'   => $user_agent,
			),
			'sslverify' => empty( $options['sslverify'] ) ? false : $options['sslverify'],
		);

		$args = apply_filters( 'jetpack_contactform_salesforce_request_args', $args );
		return wp_remote_post( $url, $args );
	}

	/**
	 * Extracts any jetpack/contact-form found on post.
	 *
	 * @param array $block_array - Array of blocks.
	 *
	 * @return array Array of jetpack/contact-form blocks found.
	 */
	public static function get_salesforce_contact_form_blocks( $block_array ) {
		$jetpack_form_blocks = array();
		foreach ( $block_array as $block ) {
			if (
				$block['blockName'] === 'jetpack/contact-form' &&
				isset( $block['attrs']['salesforceData'] ) &&
				$block['attrs']['salesforceData'] &&
				isset( $block['attrs']['salesforceData']['sendToSalesforce'] ) &&
				$block['attrs']['salesforceData']['sendToSalesforce'] &&
				isset( $block['attrs']['salesforceData']['organizationId'] ) &&
				$block['attrs']['salesforceData']['organizationId']
				) {
				$jetpack_form_blocks[] = $block;
			} elseif ( isset( $block['innerBlocks'] ) ) {
				$jetpack_form_blocks = array_merge( $jetpack_form_blocks, self::get_salesforce_contact_form_blocks( $block['innerBlocks'] ) );
			}
		}

		return $jetpack_form_blocks;
	}
}

Salesforce_Lead_Form::initialize();
