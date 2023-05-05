<?php
/**
 * Admin/Integrations item Education template for Lite.
 *
 * @since 1.6.6
 *
 * @var string $clear_slug    Clear slug (without `wpforms-` prefix).
 * @var string $modal_name    Name of the addon used in modal window.
 * @var string $license_level License level.
 * @var string $name          Name of the addon.
 * @var string $icon          Addon icon.
 * @var string $video         Video URL.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
<div id="wpforms-integration-<?php echo esc_attr( $clear_slug ); ?>"
	class="wpforms-settings-provider wpforms-clear focus-out education-modal"
	data-name="<?php echo esc_attr( $modal_name ); ?>"
	data-action="upgrade"
	data-video="<?php echo esc_url( $video ); ?>"
	data-license="<?php echo esc_attr( $license_level ); ?>">
	<div class="wpforms-settings-provider-header wpforms-clear">
		<div class="wpforms-settings-provider-logo ">
			<i class="fa fa-chevron-right"></i>
			<img src="<?php echo esc_url( WPFORMS_PLUGIN_URL . 'assets/images/' . $icon ); ?>" alt="<?php echo esc_attr( $modal_name ); ?>">
		</div>
		<div class="wpforms-settings-provider-info">
			<h3><?php echo esc_html( $name ); ?></h3>
			<p>
			<?php
			/* translators: %s - addon name. */
			printf( esc_html__( 'Integrate %s with WPForms', 'wpforms-lite' ), esc_html( $name ) );
			?>
			</p>
		</div>
	</div>
</div>
