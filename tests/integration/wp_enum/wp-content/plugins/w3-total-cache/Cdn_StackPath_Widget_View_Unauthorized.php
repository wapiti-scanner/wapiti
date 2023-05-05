<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<div id="stackpath-widget" class="w3tcstackpath_signup">
	<p>
		<?php
		w3tc_e(
			'cdn.stackpath.widget.header',
			sprintf(
				// translators: 1 HTML acronym for Content Delivery Network (CDN).
				__( 'Dramatically increase website speeds in just a few clicks! Add the StackPath content delivery network (%1$s) service to your site.', 'w3-total-cache' ),
				'<acronym title="' . __( 'Content Delivery Network', 'w3-total-cache' ) . '">' . __( 'CDN', 'w3-total-cache' ) . '</acronym>'
			)
		);
		?>
	</p>
	<h4 class="w3tcstackpath_signup_h4"><?php esc_html_e( 'New customers', 'w3-total-cache' ); ?></h4>
	<p><?php w3tc_e( 'cdn.stackpath.widget.works_magically', __( 'StackPath works magically with W3 Total Cache.', 'w3-total-cache' ) ); ?></p>
	<a class="button-primary" href="<?php echo esc_url( W3TC_STACKPATH_SIGNUP_URL ); ?>" target="_blank"><?php esc_html_e( 'Sign Up Now ', 'w3-total-cache' ); ?></a>
	<p><!--span class="desc"><?php esc_html_e( 'Exclusive offers availabel for W3TC users!', 'w3-total-cache' ); ?></span></p>-->
		<h4 class="w3tcstackpath_signup_h4"><?php esc_html_e( 'Current customers', 'w3-total-cache' ); ?></h4>
		<p>
			<?php
			w3tc_e(
				'cdn.stackpath.widget.existing',
				sprintf(
					// translators: 1 HTML acronym for Content Delivery Network (CDN).
					__( 'If you\'re an existing StackPath customer, enable %1$s and:', 'w3-total-cache' ),
					'<acronym title="' . __( 'Content Delivery Network', 'w3-total-cache' ) . '">' . __( 'CDN', 'w3-total-cache' ) . '</acronym>'
				)
			);
			?>
		</p>
		<a class="button-primary" href="<?php echo esc_url( wp_nonce_url( Util_Ui::admin_url( 'admin.php?page=w3tc_cdn' ), 'w3tc' ) ); ?>" target="_blank"><?php esc_html_e( 'Authorize', 'w3-total-cache' ); ?></a>
</div>
