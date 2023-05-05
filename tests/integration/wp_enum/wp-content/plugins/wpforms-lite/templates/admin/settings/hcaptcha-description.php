<p><?php esc_html_e( "hCaptcha is a free and privacy-oriented spam prevention service. Within your forms, hCaptcha will display a checkbox asking users to prove they're human (much like Google's v2 Checkbox reCAPTCHA). This is a simple step for legitimate site visitors, but is extremely effective at blocking spam.", 'wpforms-lite' ); ?></p>
<p>
	<?php
	printf(
		wp_kses( /* translators: %s - WPForms.com Setup hCaptcha URL. */
			__( 'For more details on how hCaptcha works, as well as a step by step setup guide, please check out our <a href="%s" target="_blank" rel="noopener noreferrer">documentation</a>.', 'wpforms-lite' ),
			[
				'a' => [
					'href'   => [],
					'target' => [],
					'rel'    => [],
				],
			]
		),
		esc_url( wpforms_utm_link( 'https://wpforms.com/docs/how-to-set-up-and-use-hcaptcha-in-wpforms/', 'Settings - Captcha', 'hCaptcha Documentation' ) )
	);
	?>
</p>
