<?php
/**
 * Admin/Settings/LiteConnect Education modal template for Lite.
 *
 * @since 1.7.4
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
<script type="text/html" id="tmpl-wpforms-settings-lite-connect-modal-content">
	<div class="wpforms-settings-lite-connect-modal-content">
		<img src="<?php echo esc_url( WPFORMS_PLUGIN_URL . 'assets/images/sullie-alt.png' ); ?>" alt="<?php esc_attr_e( 'Sullie the WPForms mascot', 'wpforms-lite' ); ?>" class="wpforms-mascot">

		<h2><?php esc_html_e( 'Form Entry Backups', 'wpforms-lite' ); ?></h2>
		<p>
			<?php esc_html_e( 'If your email notifications aren\'t delivered, you’ll lose form entries. Turn on free backups now and restore your entries when you upgrade to Pro.', 'wpforms-lite' ); ?>
		</p>

		<div class="wpforms-features">
			<section>
				<img src="<?php echo esc_url( WPFORMS_PLUGIN_URL . 'assets/images/lite-connect/lock-alt.svg' ); ?>" alt="<?php esc_attr_e( 'Security and Protection.', 'wpforms-lite' ); ?>">
				<aside>
					<h4><?php esc_html_e( 'Security and Protection', 'wpforms-lite' ); ?></h4>
					<p>
						<?php esc_html_e( 'Entries are stored securely and privately until you\'re ready to upgrade. Our team cannot view your forms or entries.', 'wpforms-lite' ); ?>
					</p>
				</aside>
			</section>
			<section>
				<img src="<?php echo esc_url( WPFORMS_PLUGIN_URL . 'assets/images/lite-connect/cloud.svg' ); ?>" alt="<?php esc_attr_e( 'Backup and Restore.', 'wpforms-lite' ); ?>">
				<aside>
					<h4><?php esc_html_e( 'Backup and Restore', 'wpforms-lite' ); ?></h4>
					<p>
						<?php esc_html_e( 'When you upgrade to WPForms Pro, we\'ll automatically restore all of the entries that you collected in WPForms Lite.', 'wpforms-lite' ); ?>
					</p>
				</aside>
			</section>
			<section>
				<img src="<?php echo esc_url( WPFORMS_PLUGIN_URL . 'assets/images/lite-connect/envelope.svg' ); ?>" alt="<?php esc_attr_e( 'WPForms Newsletter.', 'wpforms-lite' ); ?>">
				<aside>
					<h4><?php esc_html_e( 'WPForms Newsletter', 'wpforms-lite' ); ?></h4>
					<p>
						<?php esc_html_e( 'Ready to grow your website? Get the latest pro tips and updates from the WPForms team.', 'wpforms-lite' ); ?>
					</p>
				</aside>
			</section>
		</div>

		<footer>
			<?php
			printf(
				wp_kses( /* translators: %s - WPForms Terms of Service link. */
					__( 'By enabling Lite Connect you agree to our <a href="%s" target="_blank" rel="noopener noreferrer">Terms of Service</a> and to share your information with WPForms.', 'wpforms-lite' ),
					[
						'a' => [
							'href'   => [],
							'target' => [],
							'rel'    => [],
						],
					]
				),
				esc_url( wpforms_utm_link( 'https://wpforms.com/terms/', 'Lite Connect Modal', 'Terms of Service' ) )
			);
			?>
		</footer>
	</div>
</script>
