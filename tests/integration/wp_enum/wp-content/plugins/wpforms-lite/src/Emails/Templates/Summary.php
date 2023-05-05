<?php

namespace WPForms\Emails\Templates;

/**
 * Email Summaries email template class.
 *
 * @since 1.5.4
 */
class Summary extends General {

	/**
	 * Template slug.
	 *
	 * @since 1.5.4
	 *
	 * @var string
	 */
	const TEMPLATE_SLUG = 'summary';

	/**
	 * Get header image URL from settings.
	 *
	 * @since 1.5.4
	 *
	 * @return array
	 */
	protected function get_header_image() {

		$img = [
			'url' => \wpforms_setting( 'email-header-image' ),
		];

		if ( ! empty( $img['url'] ) ) {
			return $img;
		}

		// Set specific percentage WPForms logo width for modern email clients.
		$this->set_args(
			[
				'style' => [
					'header_image_max_width' => '45%',
				],
			]
		);

		// Set specific WPForms logo width in pixels for MS Outlook and old email clients.
		return [
			'url'   => \WPFORMS_PLUGIN_URL . 'assets/images/logo.png',
			'width' => 250,
		];
	}
}
