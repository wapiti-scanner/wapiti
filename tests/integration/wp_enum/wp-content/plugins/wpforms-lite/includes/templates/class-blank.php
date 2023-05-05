<?php

/**
 * Blank form template.
 *
 * @since 1.0.0
 */
class WPForms_Template_Blank extends WPForms_Template {

	/**
	 * Primary class constructor.
	 *
	 * @since 1.0.0
	 */
	public function init() {

		$this->priority    = 1;
		$this->name        = esc_html__( 'Blank Form', 'wpforms-lite' );
		$this->slug        = 'blank';
		$this->source      = 'wpforms-core';
		$this->categories  = 'all';
		$this->description = esc_html__( 'The blank form allows you to create any type of form using our drag & drop builder.', 'wpforms-lite' );
		$this->includes    = '';
		$this->icon        = '';
		$this->modal       = '';
		$this->core        = true;
		$this->data        = [
			'field_id' => '1',
			'fields'   => [],
			'settings' => [
				'antispam'                    => '1',
				'ajax_submit'                 => '1',
				'confirmation_message_scroll' => '1',
				'submit_text_processing'      => esc_html__( 'Sending...', 'wpforms-lite' ),
			],
			'meta'     => [
				'template' => $this->slug,
			],
		];
	}
}

new WPForms_Template_Blank();
