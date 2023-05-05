<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

require W3TC_INC_DIR . '/options/common/header.php';
?>
<div class="metabox-holder ustats_ad_metabox">
	<?php Util_Ui::postbox_header( esc_html__( 'Usage Statistics', 'w3-total-cache' ) ); ?>

	<div class="ustats_ad">
		<?php require __DIR__ . '/UsageStatistics_Page_View_Ad.php'; ?>

		<input type="button" class="button-primary button-buy-plugin"
			data-src="page_stats_bottom"
			value="<?php esc_attr_e( 'upgrade', 'w3-total-cache' ); ?>" />
	</div>

	<?php Util_Ui::postbox_footer(); ?>
</div>
