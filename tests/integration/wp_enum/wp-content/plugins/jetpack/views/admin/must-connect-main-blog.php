<?php
/**
 * View template file for main network site connection prompt.
 *
 * @package automattic/jetpack
 */

?>
<div class="wrap">
	<div class="jetpack-wrap-container dops-card">
		<div class="jetpack-text-container">
			<h1><?php esc_html_e( 'Get started with Jetpack Multisite', 'jetpack' ); ?></h1>
			<p>
				<?php esc_html_e( 'Get started managing your Multisite install of Jetpack by connecting.', 'jetpack' ); ?>
			</p>
		</div>
		<div class="jetpack-install-container">
			<p class="submit"><a href="<?php echo esc_url( $data['url'] ); // phpcs:disable VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable  -- $data is loaded by Jetpack::load_view(). ?>" class="button-connector dops-button is-primary" id="wpcom-connect"><?php esc_html_e( 'Set up Jetpack', 'jetpack' ); ?></a></p>
			<p class="jetpack-install-blurb">
				<?php jetpack_render_tos_blurb(); ?>
			</p>
		</div>
	</div>
</div>
