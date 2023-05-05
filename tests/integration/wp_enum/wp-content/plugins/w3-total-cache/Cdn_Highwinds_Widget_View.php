<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<div class="wrapper">
	<div class="tools area">
		<ul class="w3tchw_tools">
			<li><a class="button"
				href="<?php echo esc_url( $url_manage ); ?>"><?php esc_html_e( 'Manage', 'w3-total-cache' ); ?></a>
			</li>
			<li><a class="button"
				href="<?php echo esc_url( $url_analyze ); ?>"><?php esc_html_e( 'Reports', 'w3-total-cache' ); ?></a>
			</li>
			<li><a class="button" href="<?php echo esc_url( $url_purge ); ?>"
				onclick="w3tc_popupadmin_bar(this.href); return false"><?php esc_html_e( 'Purge', 'w3-total-cache' ); ?></a>
			</li>
		</ul>
	</div>
	<div class="w3tchw_loading w3tc_loading w3tc_hidden">Loading...</div>
	<div class="w3tchw_error w3tc_none">
		An error occurred
		<div class="w3tchw_error_details"></div>
	</div>

	<div class="w3tchw_content w3tc_hidden">
		<div class="summary area">
			<h4><?php esc_html_e( 'Report - 30 days', 'w3-total-cache' ); ?></h4>
			<ul id="w3tchw_report">
				<li>Transferred: <span class="w3tchw_transferred_size"></span></li>
				<li>Average rate Mb/s: <span class="w3tchw_average_mbps"></span></li>
				<li>Average requests/s: <span class="w3tchw_average_rps"></span></li>
			</ul>
		</div>
		<div class="charts area">
			<h4><?php esc_html_e( 'Requests', 'w3-total-cache' ); ?></h4>
			<div id="w3tchw_chart" style="width: 320px; height: 220px;margin-left: auto;  margin-right: auto;"></div>
		</div>
	</div>
</div>
