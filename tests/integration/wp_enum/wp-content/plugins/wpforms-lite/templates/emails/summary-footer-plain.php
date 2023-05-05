<?php
/**
 * Summary footer template (plain text).
 *
 * This template can be overridden by copying it to yourtheme/wpforms/emails/summary-footer-plain.php.
 *
 * @since 1.6.2.3
 *
 * @version 1.6.2.3
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

echo "\n---\n\n";
printf( /* translators: %s - link to a site. */
	esc_html__( 'This email was auto-generated and sent from %s.', 'wpforms-lite' ),
	esc_html( wp_specialchars_decode( get_bloginfo( 'name' ) ) )
);
echo "\n";
printf( /* translators: %s - link to the documentation. */
	esc_html__( 'Learn how to disable: %s.', 'wpforms-lite' ),
	'https://wpforms.com/docs/how-to-use-email-summaries/#faq'
);
