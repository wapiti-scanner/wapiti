<?php

/**
 * Simple Contact Form Template for WPForms.
 *
 * @since 1.7.5.3
 */
class WPForms_Template_Simple_Contact_Form extends WPForms_Template {

	/**
	 * Primary class constructor.
	 *
	 * @since 1.7.5.3
	 */
	public function init() {

		$this->name        = esc_html__( 'Simple Contact Form', 'wpforms-lite' );
		$this->priority    = 1;
		$this->source      = 'wpforms-core';
		$this->categories  = 'all';
		$this->core        = true;
		$this->slug        = 'simple-contact-form-template';
		$this->url         = 'https://wpforms.com/templates/simple-contact-form-template/';
		$this->description = esc_html__( 'Collect the names, emails, and messages from site visitors that need to talk to you.', 'wpforms-lite' );
		$this->data        = [
			'fields'   => [
				'0' => [
					'id'       => '0',
					'type'     => 'name',
					'format'   => 'first-last',
					'label'    => esc_html__( 'Name', 'wpforms-lite' ),
					'required' => '1',
					'size'     => 'medium',
				],
				'1' => [
					'id'       => '1',
					'type'     => 'email',
					'label'    => esc_html__( 'Email', 'wpforms-lite' ),
					'required' => '1',
					'size'     => 'medium',
				],
				'2' => [
					'id'          => '2',
					'type'        => 'textarea',
					'label'       => esc_html__( 'Comment or Message', 'wpforms-lite' ),
					'size'        => 'medium',
					'placeholder' => '',
					'css'         => '',
				],
			],
			'field_id' => 3,
			'settings' => [
				'form_desc'              => '',
				'submit_text'            => esc_html__( 'Submit', 'wpforms-lite' ),
				'submit_text_processing' => esc_html__( 'Sending...', 'wpforms-lite' ),
				'antispam'               => '1',
				'notification_enable'    => '1',
				'notifications'          => [
					'1' => [
						'email'   => '{admin_email}',
						'replyto' => '{field_id="1"}',
						'message' => '{all_fields}',
					],
				],
				'confirmations'          => [
					'1' => [
						'type'           => 'message',
						'message'        => esc_html__( 'Thanks for contacting us! We will be in touch with you shortly.', 'wpforms-lite' ),
						'message_scroll' => '1',
					],
				],
				'ajax_submit'            => '1',
			],
			'meta'     => [
				'template' => $this->slug,
			],
		];
	}
}

new WPForms_Template_Simple_Contact_Form();
