<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

require W3TC_INC_DIR . '/options/common/header.php';
?>
<div class="metabox-holder">
	<?php Util_Ui::postbox_header( esc_html__( 'Usage Statistics', 'w3-total-cache' ) ); ?>

	<p>
		<?php esc_html_e( 'Usage Statistics is collected only when Debug Mode is enabled.', 'w3-total-cache' ); ?>
	</p>

	<a href="admin.php?page=w3tc_general#debug" class="button-primary"><?php esc_html_e( 'Enable it here', 'w3-total-cache' ); ?></a>

	<?php Util_Ui::postbox_footer(); ?>
</div>
