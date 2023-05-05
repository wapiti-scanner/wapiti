<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<div class="w3tcstackpath_loading w3tc_loading w3tc_hidden">Loading...</div>
<div class="w3tcstackpath_error w3tc_none">
	An error occurred
	<div class="w3tcstackpath_error_details"></div>
</div>

<div id="stackpath-widget" class="stackpath-widget-base w3tcstackpath_content w3tc_hidden">
	<div class="w3tcstackpath_wrapper">
		<div class="w3tcstackpath_status">
			<p>
				<span>
					<?php esc_html_e( 'Status', 'w3-total-cache' ); ?>
					<span class="w3tcstackpath_account_status"></span>
				</span>
				<span style="display:inline-block;float:right">
					<?php esc_html_e( 'Content Zone:', 'w3-total-cache' ); ?>
					<span class="w3tcstackpath_zone_name"></span>
				</span>
			</p>
		</div>
		<div class="w3tcstackpath_tools">
			<ul class="w3tcstackpath_ul">
				<li><a class="button w3tcstackpath_href_manage" href=""><?php esc_html_e( 'Manage', 'w3-total-cache' ); ?></a></li>
				<li><a class="button w3tcstackpath_href_reports" href=""><?php esc_html_e( 'Reports', 'w3-total-cache' ); ?></a></li>
				<li><a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin.php?page=w3tc_cdn&amp;w3tc_cdn_purge' ) ) ); ?>" onclick="w3tc_popupadmin_bar(this.href); return false;"><?php esc_html_e( 'Purge', 'w3-total-cache' ); ?></a></li>
			</ul>
		</div>
		<div class="w3tcstackpath_summary">
			<h4 class="w3tcstackpath_summary_h4"><?php esc_html_e( 'Report - 30 days', 'w3-total-cache' ); ?></h4>
		</div>
		<ul class="w3tcstackpath_ul">
			<li>
				<span class="w3tcstackpath_summary_col1"><?php esc_html_e( 'Transferred', 'w3-total-cache' ); ?>:</span>
				<span class="w3tcstackpath_summary_col2 w3tcstackpath_summary_size"></span>
			</li>
			<li>
				<span class="w3tcstackpath_summary_col1"><?php esc_html_e( 'Cache Hits', 'w3-total-cache' ); ?>:</span>
				<span class="w3tcstackpath_summary_col2">
					<span class="w3tcstackpath_summary_cache_hit"></span>
					(<span class="w3tcstackpath_summary_cache_hit_percentage"></span>)
				</span>
			</li>
			<li>
				<span class="w3tcstackpath_summary_col1"><?php esc_html_e( 'Cache Misses', 'w3-total-cache' ); ?>:</span>
				<span class="w3tcstackpath_summary_col2">
					<span class="w3tcstackpath_summary_noncache_hit">
					(<span class="w3tcstackpath_summary_noncache_hit_percentage"></span>)
				</span>
			</li>
		</ul>
		<div class="w3tcstackpath_chart charts w3tcstackpath_area">
			<h4 class="w3tcstackpath_h4"><?php esc_html_e( 'Requests', 'w3-total-cache' ); ?></h4>
			<div id="chart_div" style="width: 320px; height: 220px;margin-left: auto ;  margin-right: auto ;"></div>
			<h4 class="w3tcstackpath_h4"><?php esc_html_e( 'Content Breakdown', 'w3-total-cache' ); ?></h4>
			<p>
				<span><?php esc_html_e( 'File', 'w3-total-cache' ); ?></span>
				<span style="display:inline-block;float:right"><?php esc_html_e( 'Hits', 'w3-total-cache' ); ?></span>
			</p>
			<ul class="w3tcstackpath_file_hits">
				<li>A</li>
				<li>A</li>
				<li>A</li>
				<li>A</li>
				<li>A</li>
			</ul>
		</div>
	</div>
</div>
