<?php
/**
 * Form Builder IE / unsupported browser notice template.
 *
 * @since 1.7.8
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
<div id='wpforms-builder-ie-notice' class='wpforms-fullscreen-notice'>

	<img src="<?php echo esc_url( WPFORMS_PLUGIN_URL . 'assets/images/builder/ie-logo.svg' ); ?>" alt='Internet Explorer &reg;'>
	<h3><?php esc_html_e( 'You are using an outdated browser!', 'wpforms-lite' ); ?></h3>

	<p>
		<?php
		printf(
			wp_kses( /* translators: %1$s - Link to the update Internet Explorer page, %2$s - link to the browse happy page. */
				__( 'The Internet Explorer browser no more supported.<br>Our form builder is optimized for modern browsers.<br>Please <a href="%1$s" target="_blank" rel="nofollow noopener">install Microsoft Edge</a> or learn<br>how to <a href="%2$s" target="_blank" rel="nofollow noopener">browse happy</a>.', 'wpforms-lite' ),
				[
					'a'  => [
						'href'   => [],
						'target' => [],
						'rel'    => [],
					],
					'br' => [],
				]
			),
			'https://www.microsoft.com/en-us/edge',
			'https://browsehappy.com/'
		);
		?>
	</p>

	<div class="wpforms-fullscreen-notice-buttons">
		<a href="<?php echo esc_url( wpforms_current_user_can( 'view_forms' ) ? admin_url( 'admin.php?page=wpforms-overview' ) : admin_url() ); ?>" class="wpforms-fullscreen-notice-button wpforms-fullscreen-notice-button-primary">
			<?php esc_html_e( 'Back to All Forms', 'wpforms-lite' ); ?>
		</a>
	</div>

</div>
