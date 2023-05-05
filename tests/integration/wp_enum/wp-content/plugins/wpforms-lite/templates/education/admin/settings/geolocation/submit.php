<?php
/**
 * Button for geolocation settings page.
 *
 * @since 1.6.6
 *
 * @var string $action       Is plugin installed?
 * @var string $path         Plugin file.
 * @var string $url          URL for download plugin.
 * @var bool   $plugin_allow Allow using plugin.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( $plugin_allow && $action === 'activate' ) {
	?>
	<button
		class="status-inactive wpforms-btn wpforms-btn-lg wpforms-btn-blue wpforms-education-toggle-plugin-btn"
		data-type="addon"
		data-action="<?php echo esc_attr( $action ); ?>"
		data-plugin="<?php echo esc_attr( $path ); ?>">
		<i></i><?php esc_html_e( 'Activate', 'wpforms-lite' ); ?>
	</button>
<?php } elseif ( $plugin_allow && $action === 'install' ) { ?>
	<button
		class="status-download wpforms-btn wpforms-btn-lg wpforms-btn-blue wpforms-education-toggle-plugin-btn"
		data-type="addon"
		data-action="<?php echo esc_attr( $action ); ?>"
		data-plugin="<?php echo esc_url( $url ); ?>">
		<i></i><?php esc_html_e( 'Install & Activate', 'wpforms-lite' ); ?>
	</button>
<?php
	} else {
	$btn_classes   = [ 'wpforms-btn', 'wpforms-btn-lg', 'wpforms-btn-orange' ];
	$btn_classes[] = ! wpforms()->is_pro() ? 'wpforms-upgrade-modal' : '';
?>
	<a
		href="<?php echo esc_url( wpforms_admin_upgrade_link( 'Settings - Geolocation', 'Geolocation Addon' ) ); ?>"
		target="_blank"
		rel="noopener noreferrer"
		class="<?php echo esc_attr( implode( ' ', array_filter( $btn_classes ) ) ); ?>">
		<?php esc_html_e( 'Upgrade to WPForms Pro', 'wpforms-lite' ); ?>
	</a>
	<?php
}
