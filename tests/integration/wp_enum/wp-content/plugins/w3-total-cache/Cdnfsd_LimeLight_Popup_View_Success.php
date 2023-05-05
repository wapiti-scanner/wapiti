<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<form class="w3tc_popup_form">
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Succeeded', 'w3-total-cache' ) ); ?>

		<div style="text-align: center">
			Plugin was successfully configured to use this service.<br />
			Make sure you have updated domain DNS records.
		<p class="submit">
			<input type="button"
				class="w3tc_cdnfsd_limelight_done w3tc-button-save button-primary"
				value="<?php esc_attr_e( 'Done', 'w3-total-cache' ); ?>" />
		</p>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
