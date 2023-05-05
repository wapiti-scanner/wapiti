<?php
/**
 * Form Builder abort message screen template.
 *
 * @since 1.7.3
 *
 * @var string $message An abort message to display.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>

<div id="wpforms-builder-abort-message" class="wpforms-fullscreen-notice wpforms-fullscreen-notice-light">

	<h3 class="waving-hand-emoji"><?php esc_html_e( 'Hi there!', 'wpforms-lite' ); ?></h3>
	<p><?php echo esc_html( $message ); ?></p>

	<img src="<?php echo esc_url( WPFORMS_PLUGIN_URL . 'assets/images/empty-states/no-forms.svg' ); ?>" alt="">

	<?php if ( wpforms_current_user_can( 'view_forms' ) ) : ?>
		<div class="wpforms-fullscreen-notice-buttons">
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=wpforms-overview' ) ); ?>"
			   class="wpforms-fullscreen-notice-button wpforms-fullscreen-notice-button-primary">
				<?php esc_html_e( 'Back to All Forms', 'wpforms-lite' ); ?>
			</a>
		</div>
	<?php endif; ?>

</div>
