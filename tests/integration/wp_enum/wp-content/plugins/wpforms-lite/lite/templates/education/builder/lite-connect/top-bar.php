<?php
/**
 * Builder/LiteConnect Top Bar Education template for Lite.
 *
 * @since 1.7.4
 *
 * @var string $toggle     Enable Entry backups toggle markup.
 * @var bool   $is_enabled Is backup entry enabled?
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
<div id="wpforms-builder-lite-connect-top-bar" class="wpforms-education-lite-connect-wrapper wpforms-dismiss-container">
	<div class="wpforms-hidden-element"></div>
	<div class="wpforms-education-lite-connect-setting <?php echo $is_enabled ? 'wpforms-hidden' : ''; ?>">
		<?php echo $toggle; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
	</div>
	<div class="wpforms-education-lite-connect-enabled-info <?php echo ! $is_enabled ? 'wpforms-hidden' : ''; ?>">
		<img src="<?php echo esc_url( WPFORMS_PLUGIN_URL . 'assets/images/lite-connect/check-circle.svg' ); ?>" alt="">
		<?php esc_html_e( 'Form Entry Backups Are Enabled', 'wpforms-lite' ); ?>
	</div>
	<p><?php esc_html_e( 'Easily restore your entries when you upgrade to WPForms Pro.', 'wpforms-lite' ); ?></p>
	<button type="button" class="wpforms-dismiss-button" title="<?php esc_attr_e( 'Dismiss this message.', 'wpforms-lite' ); ?>" data-section="builder-lite-connect-top-bar"></button>
</div>
