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
			Site <?php echo esc_html( $details['name'] ); ?> was successfully configured.<br />
			Next, update the domain <acronym title="Domain Name System">DNS</acronym> records
			<strong><?php echo esc_html( $details['home_domain'] ); ?></strong> and add <acronym title="Canonical Name">CNAME</acronym> alias to
			<strong><?php echo esc_html( $details['dns_cname_target'] ); ?></strong> to enable caching.
		</div>

		<p class="submit">
			<input type="button"
				class="w3tc_cdn_stackpath_fsd_done w3tc-button-save button-primary"
				value="<?php esc_attr_e( 'Done', 'w3-total-cache' ); ?>" />
		</p>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
