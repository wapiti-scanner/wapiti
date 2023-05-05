<?php
/**
 * Form Builder mobile / small screen notice template.
 *
 * @since 1.7.8
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
<div id='wpforms-builder-mobile-notice' class='wpforms-fullscreen-notice'>

	<img src="<?php echo esc_url( WPFORMS_PLUGIN_URL . 'assets/images/sullie-builder-mobile.png' ); ?>" class='sullie-icon' alt="<?php esc_attr_e( 'Sullie the WPForms mascot', 'wpforms-lite' ); ?>">

	<h3><?php esc_html_e( 'Our form builder is optimized for desktop computers.', 'wpforms-lite' ); ?></h3>
	<p><?php esc_html_e( 'We recommend that you edit your forms on a bigger screen. If you\'d like to proceed, please understand that some functionality might not behave as expected.', 'wpforms-lite' ); ?></p>

	<div class="wpforms-fullscreen-notice-buttons">
		<button type="button" class="wpforms-fullscreen-notice-button wpforms-fullscreen-notice-button-primary">
			<?php esc_html_e( 'Back to All Forms', 'wpforms-lite' ); ?>
		</button>
		<button type="button" class="wpforms-fullscreen-notice-button wpforms-fullscreen-notice-button-secondary">
			<?php esc_html_e( 'Continue', 'wpforms-lite' ); ?>
		</button>

		<button type="button" class="close"><span class="screen-reader-text"><?php esc_html_e( 'Close', 'wpforms-lite' ); ?></span></button>
	</div>

</div>
