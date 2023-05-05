<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<style>

.w3tcuw_inactive {
	height: 242px;
	background: url("<?php echo esc_url( plugins_url( 'pub/img/usage-statistics-widget.png', W3TC_FILE ) ); ?>");
	background-repeat: no-repeat;
	background-size: cover;
}

.w3tcuw_inactive input, .w3tcuw_inactive a {
	position: absolute;
	top: 50%;
	left: 50%;
	-ms-transform: translate(-50%, -50%);
	transform: translate(-50%, -50%);
}

.w3tcuw_inactive input, .w3tcuw_inactive span {
	background: #fff;
}

</style>
<p class="w3tcuw_inactive">
	<?php if ( ! Util_Environment::is_w3tc_pro( Dispatcher::config() ) ) : ?>
		<input type="button"
			class="button-primary button-buy-plugin {nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}"  data-src="usagestatistics_widget" value="<?php esc_html_e( 'Upgrade to Pro', 'w3-total-cache' ); ?>" />
	<?php else : ?>
		<a href="admin.php?page=w3tc_general#stats" class="button-primary">Enable</a>
	<?php endif ?>
</p>
