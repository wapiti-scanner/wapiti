<p><?php esc_html_e( 'reCAPTCHA is a free anti-spam service from Google which helps to protect your website from spam and abuse while letting real people pass through with ease.', 'wpforms-lite' ); ?></p>
<p><?php esc_html_e( 'Google offers 3 versions of reCAPTCHA (all supported within WPForms):', 'wpforms-lite' ); ?></p>
<ul style="list-style: disc;margin-left: 20px;">
	<li>
	<?php
		echo wp_kses(
			__( '<strong>v2 Checkbox reCAPTCHA</strong>: Prompts users to check a box to prove they\'re human.', 'wpforms-lite' ),
			[ 'strong' => [] ]
		);
	?>
	</li>
	<li>
	<?php
		echo wp_kses(
			__( '<strong>v2 Invisible reCAPTCHA</strong>: Uses advanced technology to detect real users without requiring any input.', 'wpforms-lite' ),
			[ 'strong' => [] ]
		);
	?>
	</li>
	<li>
	<?php
		echo wp_kses(
			__( '<strong>v3 reCAPTCHA</strong>: Uses a behind-the-scenes scoring system to detect abusive traffic, and lets you decide the minimum passing score. Recommended for advanced use only (or if using Google AMP).', 'wpforms-lite' ),
			[ 'strong' => [] ]
		);
	?>
	</li>
</ul>
<p><?php esc_html_e( 'Sites already using one type of reCAPTCHA will need to create new site keys before switching to a different option.', 'wpforms-lite' ); ?></p>
<p>
	<?php
	printf(
		wp_kses( /* translators: %s - WPForms.com Setup reCAPTCHA URL. */
			__( '<a href="%s" target="_blank" rel="noopener noreferrer">Read our walk through</a> to learn more and for step-by-step directions.', 'wpforms-lite' ),
			[
				'a' => [
					'href'   => [],
					'target' => [],
					'rel'    => [],
				],
			]
		),
		esc_url( wpforms_utm_link( 'https://wpforms.com/docs/how-to-set-up-and-use-recaptcha-in-wpforms/', 'Settings - Captcha', 'reCAPTCHA Documentation' ) )
	);
	?>
</p>
