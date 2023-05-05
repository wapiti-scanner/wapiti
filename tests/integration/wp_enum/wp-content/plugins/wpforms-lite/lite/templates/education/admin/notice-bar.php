<?php
/**
 * Admin/NoticeBar Education template for Lite.
 *
 * @since 1.6.6
 *
 * @var string $upgrade_link Upgrade to Pro page URL.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
<div id="wpforms-notice-bar" class="wpforms-dismiss-container">
	<span class="wpforms-notice-bar-message">
		<?php
		printf(
			wp_kses(
				/* translators: %s - WPForms.com Upgrade page URL. */
				__( '<strong>You\'re using WPForms Lite.</strong> To unlock more features consider <a href="%s" target="_blank" rel="noopener noreferrer">upgrading to Pro</a> for 50%% off.', 'wpforms-lite' ),
				[
					'a'      => [
						'href'   => [],
						'rel'    => [],
						'target' => [],
					],
					'strong' => [],
				]
			),
			esc_url( $upgrade_link )
		);
		?>
	</span>
	<button type="button" class="wpforms-dismiss-button" title="<?php esc_attr_e( 'Dismiss this message.', 'wpforms-lite' ); ?>" data-section="admin-notice-bar"></button>
</div>
