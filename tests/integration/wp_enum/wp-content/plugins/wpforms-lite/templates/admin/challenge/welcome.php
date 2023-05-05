<?php
/**
 * Challenge CTA on WPForms welcome activation screen HTML template.
 *
 * @since 1.6.2
 */

if ( ! \defined( 'ABSPATH' ) ) {
	exit;
}

?>
<div class="challenge">
	<div class="block">
		<h1><?php esc_html_e( 'Take the WPForms Challenge', 'wpforms-lite' ); ?></h1>
		<h6><?php esc_html_e( 'Create your first form with our guided setup wizard in less than 5 minutes to experience the WPForms difference.', 'wpforms-lite' ); ?></h6>
		<div class="button-wrap">
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=wpforms-builder' ) ); ?>" class="wpforms-btn wpforms-btn-lg wpforms-btn-orange">
				<?php esc_html_e( 'Start the WPForms Challenge', 'wpforms-lite' ); ?>
			</a>
		</div>
	</div>
</div>

