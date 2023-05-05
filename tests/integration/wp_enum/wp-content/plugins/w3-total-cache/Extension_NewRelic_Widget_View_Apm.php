<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<div id="new-relic-widget">
	<div class="w3tcnr_loading w3tc_loading w3tc_hidden">Loading...</div>
	<div class="w3tcnr_error w3tc_none">An error occurred</div>

	<div class="w3tcnr_content w3tc_hidden">
		<div id="new-relic-summary">
			<h4><?php esc_html_e( 'Overview', 'w3-total-cache' ); ?></h4>
			<ul>
				<li><span>Apdex: </span><span class="w3tcnr_apdex">N/A</span></li>
				<li><span>Application Busy: </span><span class="w3tcnr_application_busy">N/A</span></li>
				<li><span>Error Rate: </span><span class="w3tcnr_error_rate">N/A</span></li>
				<li><span>Throughput: </span><span class="w3tcnr_throughput">N/A</span></li>
				<li><span>Errors: </span><span class="w3tcnr_errors">N/A</span></li>
				<li><span>Response Time: </span><span class="w3tcnr_response_time">N/A</span></li>
				<li><span>DB: </span><span class="w3tcnr_db">N/A</span></li>
				<li><span>CPU: </span><span class="w3tcnr_cpu">N/A</span></li>
				<li><span>Memory: </span><span class="w3tcnr_memory">N/A</span></li>
			</ul>
		</div>
		<div id="new-relic-extra-metrics">
			<h4><?php esc_html_e( 'Average times', 'w3-total-cache' ); ?></h4>
			<ul>
				<li><span>Page load time: </span><span class="w3tcnr_enduser">N/A</span></li>
				<li><span>Web Transaction: </span><span class="w3tcnr_webtransaction">N/A</span></li>
				<li><span>Database: </span><span class="w3tcnr_database">N/A</span></li>
			</ul>
			<div style="clear:both"></div>
		</div>
		<div id="new-relic-top-list">
			<h4><?php esc_html_e( 'Top 5 slowest times', 'w3-total-cache' ); ?></h4>
			<div class="wrapper">
				<h5 class="w3tcnr-header-pageloads"><?php esc_html_e( 'Page load times', 'w3-total-cache' ); ?><div class="handlediv open" title="Click to toggle"><br></div></h5>
				<div class="top-five w3tcnr_pageloads">
					<div class="w3tcnr_topfive_message">Loading...</div>
				</div>
			</div>
			<div class="wrapper">
				<h5 class="w3tcnr-header-webtransactions"><?php esc_html_e( 'Web Transaction times', 'w3-total-cache' ); ?><div class="handlediv open" title="Click to toggle"><br></div></h5>
				<div class="top-five w3tcnr_webtransactions">
					<div class="w3tcnr_topfive_message">Loading...</div>
				</div>
			</div>
			<div class="wrapper">
				<h5 class="w3tcnr-header-dbtimes"><?php esc_html_e( 'Database times', 'w3-total-cache' ); ?><div class="handlediv open" title="Click to toggle"><br></div></h5>
				<div id="w3tc-database-times" class="top-five w3tcnr_dbtimes">
					<div class="w3tcnr_topfive_message">Loading...</div>
				</div>
			</div>
		</div>
		<div style="clear:both"></div>
		<hr>
		<p>
			<?php esc_html_e( 'PHP agent:', 'w3-total-cache' ); ?>
			<span class="w3tcnr_php_agent">N/A</span>
			<br />

			<?php esc_html_e( 'Subscription level:', 'w3-total-cache' ); ?>
			<strong class="w3tcnr_subscription_level">N/A</strong>
		</p>
	</div>
</div>
