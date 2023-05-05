<?php
/**
 * No forms HTML template.
 *
 * @since 1.6.2.3
 */

if ( ! \defined( 'ABSPATH' ) ) {
	exit;
}

?>
<div class="wpforms-admin-empty-state-container wpforms-admin-no-forms">

	<h2 class="waving-hand-emoji"><?php esc_html_e( 'Hi there!', 'wpforms-lite' ); ?></h2>

	<p><?php esc_html_e( 'It looks like you haven’t created any forms yet.', 'wpforms-lite' ); ?></p>
	<p><?php esc_html_e( 'You can use WPForms to build contact forms, surveys, payment forms, and more with just a few clicks.', 'wpforms-lite' ); ?></p>

	<img src="<?php echo esc_url( WPFORMS_PLUGIN_URL . 'assets/images/empty-states/no-forms.svg' ); ?>" alt=""/>

	<br>

	<?php if ( wpforms_current_user_can( 'create_forms' ) ) : ?>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=wpforms-builder' ) ); ?>" class="wpforms-btn add-new-h2 wpforms-btn-orange"><?php esc_html_e( 'Create Your Form', 'wpforms-lite' ); ?></a>
	<?php endif; ?>

	<p class="wpforms-admin-no-forms-footer">
		<?php
		printf(
			wp_kses( /* translators: %s - URL to the documentation article. */
				__( 'Need some help? Check out our <a href="%s" target="_blank" rel="noopener noreferrer">comprehensive guide</a>.', 'wpforms-lite' ),
				[
					'a' => [
						'href'   => [],
						'target' => [],
						'rel'    => [],
					],
				]
			),
			esc_url( wpforms_utm_link( 'https://wpforms.com/docs/creating-first-form/', 'forms-overview', 'Create Your First Form Documentation' ) )
		);
		?>
	</p>

</div>
