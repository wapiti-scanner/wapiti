<?php

if ( ! class_exists( 'WPCF7_Service' ) ) {
	return;
}

class WPCF7_Akismet extends WPCF7_Service {

	private static $instance;


	public static function get_instance() {
		if ( empty( self::$instance ) ) {
			self::$instance = new self;
		}

		return self::$instance;
	}


	public function get_title() {
		return __( 'Akismet', 'contact-form-7' );
	}


	public function is_active() {
		return wpcf7_akismet_is_available();
	}


	public function get_categories() {
		return array( 'spam_protection' );
	}


	public function icon() {
	}


	public function link() {
		echo wpcf7_link(
			'https://akismet.com/',
			'akismet.com'
		);
	}


	public function display( $action = '' ) {
		echo sprintf(
			'<p>%s</p>',
			esc_html( __( "CAPTCHAs are designed to distinguish spambots from humans, and are therefore helpless against human spammers. In contrast to CAPTCHAs, Akismet checks form submissions against the global database of spam; this means Akismet is a comprehensive solution against spam. This is why we consider Akismet to be the centerpiece of the spam prevention strategy.", 'contact-form-7' ) )
		);

		echo sprintf(
			'<p><strong>%s</strong></p>',
			wpcf7_link(
				__( 'https://contactform7.com/spam-filtering-with-akismet/', 'contact-form-7' ),
				__( 'Spam filtering with Akismet', 'contact-form-7' )
			)
		);

		if ( $this->is_active() ) {
			echo sprintf(
				'<p class="dashicons-before dashicons-yes">%s</p>',
				esc_html( __( "Akismet is active on this site.", 'contact-form-7' ) )
			);
		}
	}

}
