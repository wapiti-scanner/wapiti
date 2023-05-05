<p><?php esc_html_e( 'Cloudflare Turnstile is a free, CAPTCHA-like service for preventing form spam while protecting data privacy. It offers a user-friendly experience by confirming visitors are real humans without requiring them to solve puzzles or math questions.', 'wpforms-lite' ); ?></p>
<p>
	<?php
	printf(
		wp_kses( /* translators: %s - WPForms.com Setup Cloudflare Turnstile URL. */
			__( 'For more details on how Turnstile works, as well as a step by step setup guide, please check out our <a href="%s" target="_blank" rel="noopener noreferrer">documentation</a>.', 'wpforms-lite' ),
			[
				'a' => [
					'href'   => [],
					'target' => [],
					'rel'    => [],
				],
			]
		),
		esc_url( wpforms_utm_link( 'https://wpforms.com/docs/setting-up-cloudflare-turnstile/', 'Settings - Captcha', 'Turnstile Documentation' ) )
	);
	?>
</p>
