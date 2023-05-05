<?php
/**
 * SMTP education notice.
 *
 * @since 1.8.1
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>

<div class="wpforms-smtp-education-notice wpforms-dismiss-container">
	<div class="wpforms-smtp-education-notice-title"><?php esc_html_e( 'Make Sure Important Emails Reach Your Customers', 'wpforms-lite' ); ?></div>
	<div class="wpforms-smtp-education-notice-description">
		<?php
		echo wp_kses(
			sprintf( /* translators: %1$s is link to WPForms SMTP page. */
				__( 'Solve common email deliverability issues for good. <a href="%1$s" target="%2$s" rel="noopener noreferrer">Get WP Mail SMTP!</a>', 'wpforms-lite' ),
				esc_url( add_query_arg( 'page', 'wpforms-smtp', admin_url( 'admin.php' ) ) ),
				wpforms_is_admin_page( 'builder' ) ? '_blank' : '_self'
			),
			[
				'a' => [
					'href'   => [],
					'rel'    => [],
					'target' => [],
				],
			]
		);
		?>
	</div>
	<div
			class="wpforms-smtp-education-notice-dismiss-button wpforms-dismiss-button"
			data-section="smtp-notice"
			aria-label="<?php esc_html_e( 'Dismiss this notice', 'wpforms-lite' ); ?>">
		<span class="dashicons dashicons-no-alt"></span>
	</div>
</div>
