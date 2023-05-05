<?php
/**
 * File: Generic_WidgetBoldGrid_View.php
 *
 * @package W3TC
 */

namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

?>
<div>
	<p class="notice notice-error"><?php esc_html_e( 'W3 Total Cache has detected that you do not have a Backup Plugin installed.', 'w3-total-cache' ); ?></p>
	<p>
		<strong>
			<?php esc_html_e( 'Protect your WordPress site from data loss by installing the FREE Total Upkeep plugin.', 'w3-total-cache' ); ?>
		</strong>
	</p>

	<p>
		<?php esc_html_e( 'It\'s easy to set up and manage, backs up your entire WordPress site, has automated fault protection if an update fails, and provides easy site migration options.', 'w3-total-cache' ); ?>
	</p>

	<a href="<?php echo esc_url( $install_url ); ?>" id="w3tc-boldgrid-install"
		class="button-primary"><?php esc_html_e( 'Install Free Backup Plugin', 'w3-total-cache' ); ?></a>
</div>
