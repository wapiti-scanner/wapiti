<?php
/**
 * Builder/Providers and Payments Education template for Lite.
 *
 * @since 1.6.6
 *
 * @var string $clear_slug    Clear slug (without `wpforms-` prefix).
 * @var string $modal_name    Name of the addon used in modal window.
 * @var string $license_level License level.
 * @var string $name          Name of the addon.
 * @var string $icon          Addon icon.
 * @var string $video         Video URL.
 * @var string $utm_content   UTM content.
 * @var bool   $recommended   Flag for recommended providers.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
<a href="#"
	class="wpforms-panel-sidebar-section icon wpforms-panel-sidebar-section-<?php echo esc_attr( $clear_slug ); ?> education-modal"
	data-name="<?php echo esc_attr( $modal_name ); ?>"
	data-slug="<?php echo esc_attr( $clear_slug ); ?>"
	data-video="<?php echo esc_url( $video ); ?>"
	data-license="<?php echo esc_attr( $license_level ); ?>"
	data-utm-content="<?php echo esc_attr( $utm_content ); ?>">
	<img src="<?php echo esc_url( WPFORMS_PLUGIN_URL . 'assets/images/' . $icon ); ?>" alt="<?php echo esc_attr( $modal_name ); ?>">
	<?php echo esc_html( $name ); ?>
	<?php if ( ! empty( $recommended ) ) : ?>
		<span class="wpforms-panel-sidebar-recommended">
			<i class="fa fa-star" aria-hidden="true"></i>
			<?php esc_html_e( 'Recommended', 'wpforms-lite' ); ?>
		</span>
	<?php endif; ?>
	<i class="fa fa-angle-right wpforms-toggle-arrow"></i>
</a>
