<?php
/**
 * File: UsageStatistics_Widget_View.php
 *
 * @package W3TC
 */

namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<style>
#w3tc_usage_statistics:hover .edit-box {
	opacity: 1;
}

.w3tcuw_sizes {
	display: flex;
	width: 100%;
	padding-bottom: 10px;
}

.w3tcuw_name {
	font-weight: bold;
}

.w3tcuw_size_item {
	flex: 1;
	text-align: center;
	display: none;
}
</style>
<div>
	<?php esc_html_e( 'Hit rate', 'w3-total-cache' ); ?>
	<div style="width: 100%; height: 200px">
		<canvas id="w3tcuw_chart"></canvas>
	</div>
</div>

<div class="w3tcuw_sizes">
	<div class="w3tcuw_size_item w3tcuw_memcached_size_percent">
		<div class="w3tcuw_name"><?php esc_html_e( 'Memcached Usage', 'w3-total-cache' ); ?></div>
		<div class="w3tcuw_value"></div>
	</div>
	<div class="w3tcuw_size_item w3tcuw_redis_size_percent">
		<div class="w3tcuw_name"><?php esc_html_e( 'Redis Usage', 'w3-total-cache' ); ?></div>
		<div class="w3tcuw_value"></div>
	</div>
	<div class="w3tcuw_size_item w3tcuw_apc_size_percent">
		<div class="w3tcuw_name"><?php esc_html_e( 'APC Usage', 'w3-total-cache' ); ?></div>
		<div class="w3tcuw_value"></div>
	</div>
</div>
