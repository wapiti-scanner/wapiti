<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<div class="w3tcstackpath2_loading w3tc_loading w3tc_hidden">Loading...</div>
<div class="w3tcstackpath2_error w3tc_none">
	An error occurred
	<div class="w3tcstackpath2_error_details"></div>
</div>

<div id="stackpath-widget" class="stackpath-widget-base w3tcstackpath2_content w3tc_hidden">
	<div class="w3tcstackpath2_wrapper">
		<div class="w3tcstackpath2_tools">
			<ul class="w3tcstackpath2_ul">
				<li><a class="button w3tcstackpath2_href_manage" href=""><?php esc_html_e( 'Manage', 'w3-total-cache' ); ?></a></li>
				<li><a class="button w3tcstackpath2_href_reports" href=""><?php esc_html_e( 'Reports', 'w3-total-cache' ); ?></a></li>
				<li><a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin.php?page=w3tc_cdn&amp;w3tc_cdn_purge' ) ) ); ?>" onclick="w3tc_popupadmin_bar( this.href ); return false;"><?php esc_html_e( 'Purge', 'w3-total-cache' ); ?></a></li>
			</ul>
		</div>
		<div class="w3tcstackpath2_summary">
			<h4 class="w3tcstackpath2_summary_h4"><?php esc_html_e( 'Report - 7 days', 'w3-total-cache' ); ?></h4>
		</div>
		<ul class="w3tcstackpath2_ul">
			<li>
				<span class="w3tcstackpath2_summary_col1"><?php esc_html_e( 'Transferred', 'w3-total-cache' ); ?>:</span>
				<span class="w3tcstackpath2_summary_col2 w3tcstackpath2_summary_mb"></span>
			</li>
			<li>
				<span class="w3tcstackpath2_summary_col1"><?php esc_html_e( 'Requests', 'w3-total-cache' ); ?>:</span>
				<span class="w3tcstackpath2_summary_col2 w3tcstackpath2_summary_requests"></span>
			</li>
		</ul>
		<div class="w3tcstackpath2_chart charts w3tcstackpath2_area">
			<h4 class="w3tcstackpath2_h4"><?php esc_html_e( 'Requests', 'w3-total-cache' ); ?></h4>
			<div id="chart_div" style="width: 320px; height: 220px;margin-left: auto ;  margin-right: auto ;"></div>
		</div>
	</div>
</div>
