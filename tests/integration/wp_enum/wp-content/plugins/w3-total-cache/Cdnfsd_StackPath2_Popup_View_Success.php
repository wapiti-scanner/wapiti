<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<form class="w3tc_cdn_stackpath2_fsd_form">
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Succeeded', 'w3-total-cache' ) ); ?>

		<div style="text-align: center">
			Site was successfully configured.<br />
		</div>

		<p class="submit">
			<input type="button"
				class="w3tc_cdn_stackpath2_fsd_done w3tc-button-save button-primary"
				value="<?php esc_html_e( 'Done', 'w3-total-cache' ); ?>" />
		</p>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
