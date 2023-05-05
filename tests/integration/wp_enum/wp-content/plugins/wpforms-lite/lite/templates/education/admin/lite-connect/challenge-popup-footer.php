<?php
/**
 * Admin/LiteConnect Challenge popup footer Education template for Lite.
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

<div id="wpforms-challenge-popup-lite-connect" class="wpforms-education-lite-connect-wrapper wpforms-challenge-popup-footer">
	<h3>
		<?php esc_html_e( 'One More Thing', 'wpforms-lite' ); ?>
		<img src="<?php echo esc_url( WPFORMS_PLUGIN_URL . 'assets/images/lite-connect/raised-hand.png' ); ?>" alt="">
	</h3>
	<p>
		<?php esc_html_e( 'WPForms now offers offsite backups for your form entries. If you decide to upgrade to WPForms Pro, you can restore entries collected while you used WPForms Lite.', 'wpforms-lite' ); ?>
	</p>
	<hr>
	<div class="wpforms-education-lite-connect-setting <?php echo $is_enabled ? 'wpforms-hidden' : ''; ?>">
		<?php echo $toggle; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
	</div>
	<div class="wpforms-education-lite-connect-enabled-info <?php echo ! $is_enabled ? 'wpforms-hidden' : ''; ?>">
		<img src="<?php echo esc_url( WPFORMS_PLUGIN_URL . 'assets/images/lite-connect/check-circle.svg' ); ?>" alt="">
		<?php esc_html_e( 'Form Entry Backups Are Enabled', 'wpforms-lite' ); ?>
	</div>
</div>

