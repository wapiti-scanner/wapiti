<?php
/**
 * Admin/LiteConnect Dashboard Widget before Education template for Lite.
 *
 * @since 1.7.4
 *
 * @var string $toggle             Enable Entry backups toggle markup.
 * @var bool   $is_enabled         Is backup entry enabled?
 * @var string $entries_since_info Entries information string.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>

<div id="wpforms-dash-widget-lite-connect-block" class="wpforms-dash-widget-block wpforms-education-lite-connect-wrapper">
	<div class="wpforms-education-lite-connect-setting <?php echo $is_enabled ? 'wpforms-hidden' : ''; ?>">
		<?php echo $toggle; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
	</div>
	<div class="wpforms-education-lite-connect-enabled-info <?php echo ! $is_enabled ? 'wpforms-hidden' : ''; ?>">
		<img src="<?php echo esc_url( WPFORMS_PLUGIN_URL . 'assets/images/lite-connect/info-circle.svg' ); ?>" alt="">
		<span><?php echo esc_html( $entries_since_info ); ?></span>
		<a href="<?php echo esc_url( wpforms_admin_upgrade_link( 'dashboard-widget', 'restore-entries' ) ); ?>" target="_blank" rel="noopener noreferrer" class="wpforms-upgrade-modal">
			<?php esc_html_e( 'Restore Form Entries', 'wpforms-lite' ); ?>
		</a>
	</div>
</div>
