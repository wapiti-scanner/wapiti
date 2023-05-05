<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<p class="widget-loading hide-if-no-js {nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}">
	<?php esc_html_e( 'Loading&#8230;', 'w3-total-cache' ); ?>
</p>
<p class="hide-if-js">
	<?php esc_html_e( 'This widget requires JavaScript.', 'w3-total-cache' ); ?>
</p>
