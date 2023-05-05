<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

require W3TC_INC_DIR . '/options/common/header.php';

?>
<div class="ustats_loading w3tc_loading"><?php esc_html_e( 'Loading...', 'w3-total-cache' ); ?></div>
<div class="ustats_error w3tc_none"><?php esc_html_e( 'An error occurred', 'w3-total-cache' ); ?></div>
<div class="ustats_nodata w3tc_none">
	<p><?php esc_html_e( 'No data collected yet', 'w3-total-cache' ); ?></p>
	<a href="#" class="ustats_reload"><?php esc_html_e( 'Refresh', 'w3-total-cache' ); ?></a>
</div>

<div class="ustats_content w3tc_hidden">
	<span class="ustats_reload">.</span>
</div>

<div class="metabox-holder" style="display: none">
	<?php Util_Ui::postbox_header( esc_html__( 'Web Requests', 'w3-total-cache' ) ); ?>

	<div class="ustats_block ustats_pagecache">
		<div class="ustats_block_data">
			<div class="ustats_header">
				<?php esc_html_e( 'Page Cache', 'w3-total-cache' ); ?>
				<span class="ustats_pagecache_engine_name w3tcus_inline">(<span></span>)</span>
				:
			</div>
			<div class="ustats_pagecache_size_used">
				<?php esc_html_e( 'Cache size: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_pagecache_items">
				<?php esc_html_e( 'Entries: ', 'w3-total-cache' ); ?><span></span>
			</div>

			<div class="ustats_pagecache_requests">
				<?php esc_html_e( 'Requests: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_pagecache_requests_per_second">
				<?php esc_html_e( 'Requests/sec: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_pagecache_requests_hit">
				<?php esc_html_e( 'Cache hits: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_pagecache_requests_hit_rate">
				<?php esc_html_e( 'Cache hit rate: ', 'w3-total-cache' ); ?><span></span>
			</div>

			<div class="ustats_pagecache_request_time_ms">
				<?php esc_html_e( 'Avg processing time: ', 'w3-total-cache' ); ?><span></span><?php esc_html_e( ' ms', 'w3-total-cache' ); ?>
			</div>
			<div class="ustats_pagecache_size_percent">
				<?php esc_html_e( 'Size used: ', 'w3-total-cache' ); ?><span></span>
			</div>
		</div>
		<div class="ustats_block_chart">
			<?php esc_html_e( 'Request time', 'w3-total-cache' ); ?>
			<canvas id="w3tcus_pagecache_chart"></canvas>
		</div>
	</div>

	<div class="ustats_block ustats_php">
		<div class="ustats_block_data">
			<div class="ustats_header"><?php esc_html_e( 'PHP Requests:', 'w3-total-cache' ); ?></div>
			<div class="ustats_php_php_requests_per_second">
				<?php esc_html_e( 'Requests/sec: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<?php
			$this->summary_item(
				'php_php_requests',
				esc_html__( 'Requests/period', 'w3-total-cache' ),
				true,
				'',
				'#009900'
			);
			$this->summary_item(
				'php_php_requests_pagecache_hit',
				$php_php_requests_pagecache_hit_name
			);
			$this->summary_item(
				'php_php_requests_pagecache_miss',
				esc_html__( 'Not cached', 'w3-total-cache' ),
				false,
				'',
				'#990000'
			);
			echo '<div class="ustats_php_php_requests_pagecache_miss_level2_wrap">';
			$this->summary_item(
				'php_php_requests_pagecache_miss_404',
				'404',
				false,
				'ustats_php_php_requests_pagecache_miss_level2',
				'',
				'miss_404'
			);
			$this->summary_item(
				'php_php_requests_pagecache_miss_ajax',
				'AJAX',
				false,
				'ustats_php_php_requests_pagecache_miss_level2',
				'',
				'miss_ajax'
			);
			$this->summary_item(
				'php_php_requests_pagecache_miss_api_call',
				esc_html__( 'API call', 'w3-total-cache' ),
				false,
				'ustats_php_php_requests_pagecache_miss_level2',
				'',
				'miss_api_call'
			);
			$this->summary_item(
				'php_php_requests_pagecache_miss_configuration',
				esc_html__( 'W3TC Configuration', 'w3-total-cache' ),
				false,
				'ustats_php_php_requests_pagecache_miss_level2',
				'',
				'miss_configuration'
			);
			$this->summary_item(
				'php_php_requests_pagecache_miss_fill',
				esc_html__( 'Cache Fill', 'w3-total-cache' ),
				false,
				'ustats_php_php_requests_pagecache_miss_level2',
				'',
				'miss_fill'
			);
			$this->summary_item(
				'php_php_requests_pagecache_miss_logged_in',
				esc_html__( 'Logged In', 'w3-total-cache' ),
				false,
				'ustats_php_php_requests_pagecache_miss_level2',
				'',
				'miss_logged_in'
			);
			$this->summary_item(
				'php_php_requests_pagecache_miss_mfunc',
				'mfunc',
				false,
				'ustats_php_php_requests_pagecache_miss_level2',
				'',
				'miss_mfunc'
			);
			$this->summary_item(
				'php_php_requests_pagecache_miss_query_string',
				esc_html__( 'Query String', 'w3-total-cache' ),
				false,
				'ustats_php_php_requests_pagecache_miss_level2',
				'',
				'miss_query_string'
			);
			$this->summary_item(
				'php_php_requests_pagecache_miss_third_party',
				esc_html__( 'Third Party', 'w3-total-cache' ),
				false,
				'ustats_php_php_requests_pagecache_miss_level2',
				'',
				'miss_third_party'
			);
			$this->summary_item(
				'php_php_requests_pagecache_miss_wp_admin',
				'wp-admin',
				false,
				'ustats_php_php_requests_pagecache_miss_level2',
				'',
				'miss_wp_admin'
			);
			echo '</div>';
			?>
		</div>
		<div class="ustats_block_chart">
			<?php esc_html_e( 'Requests handled by PHP', 'w3-total-cache' ); ?>
			<canvas id="w3tcus_php_requests_chart"></canvas>
		</div>
	</div>

	<div class="ustats_block ustats_access_log" style="height: 32vw">
		<div class="ustats_block_data">
			<div class="ustats_header"><?php esc_html_e( 'Access Log:', 'w3-total-cache' ); ?></div>
			<div class="ustats_access_log_dynamic_requests_total">
				<?php esc_html_e( 'Dynamic Requests/period: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_access_log_dynamic_requests_per_second">
				<?php esc_html_e( 'Dynamic Requests/second: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_access_log_dynamic_requests_timing">
				<?php esc_html_e( 'Dynamic time to process (ms): ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_access_log_static_requests_total">
				<?php esc_html_e( 'Static Requests/period: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_access_log_static_requests_per_second">
				<?php esc_html_e( 'Static Requests/second: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_access_log_static_requests_timing">
				<?php esc_html_e( 'Static time to process (ms): ', 'w3-total-cache' ); ?><span></span>
			</div>
		</div>
		<div class="ustats_block_chart">
			<?php esc_html_e( 'Requests', 'w3-total-cache' ); ?>
			<canvas id="w3tcus_access_log_chart_requests"></canvas>
			<?php esc_html_e( 'Time per request (ms)', 'w3-total-cache' ); ?>
			<canvas id="w3tcus_access_log_chart_timing"></canvas>
		</div>
	</div>

	<?php Util_Ui::postbox_footer(); ?>
</div>

<div class="metabox-holder" style="display: none">
	<?php Util_Ui::postbox_header( esc_html__( 'Minify', 'w3-total-cache' ) ); ?>

	<div class="ustats_block ustats_minify">
		<div class="ustats_block_data">
			<div class="ustats_header"><?php esc_html_e( 'Minify:', 'w3-total-cache' ); ?></div>
			<div class="ustats_minify_size_used">
				<?php esc_html_e( 'Used: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_minify_size_items">
				<?php esc_html_e( 'Files: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_minify_size_compression_css">
				<?php esc_html_e( 'CSS compression in cache: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_minify_size_compression_js">
				<?php esc_html_e( 'JS compression in cache: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_minify_requests_total">
				<?php esc_html_e( 'Requests/period: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_minify_requests_per_second">
				<?php esc_html_e( 'Requests/sec: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_minify_compression_css">
				<?php esc_html_e( 'Responded CSS compression: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_minify_compression_js">
				<?php esc_html_e( 'Responded JS compression: ', 'w3-total-cache' ); ?><span></span>
			</div>
		</div>
	</div>

	<?php Util_Ui::postbox_footer(); ?>
</div>

<div class="metabox-holder" style="display: none">
	<?php Util_Ui::postbox_header( esc_html__( 'Object Cache', 'w3-total-cache' ) ); ?>

	<div class="ustats_block ustats_objectcache" style="height: 32vw">
		<div class="ustats_block_data">
			<div class="ustats_header">
				<?php esc_html_e( 'Object Cache', 'w3-total-cache' ); ?>
				<span class="ustats_objectcache_engine_name w3tcus_inline">(<span></span>)</span>
			</div>
			<div class="ustats_objectcache_get_total">
				<?php esc_html_e( 'Gets/period: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_objectcache_get_hits">
				<?php esc_html_e( 'Hits/period: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_objectcache_hit_rate">
				<?php esc_html_e( 'Hit rate: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_objectcache_sets">
				<?php esc_html_e( 'Sets/period: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_objectcache_flushes">
				<?php esc_html_e( 'Flushes/period: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_objectcache_time_ms">
				<?php esc_html_e( 'Time taken: ', 'w3-total-cache' ); ?><span></span><?php esc_html_e( ' ms', 'w3-total-cache' ); ?>
			</div>

			<div class="ustats_objectcache_calls_per_second">
				<?php esc_html_e( 'Calls/sec: ', 'w3-total-cache' ); ?><span></span>
			</div>

			<a href="?page=w3tc_stats&view=oc_requests"><?php esc_html_e( 'Detailed view (in debug mode only)', 'w3-total-cache' ); ?></a>
		</div>
		<div class="ustats_block_chart">
			<?php esc_html_e( 'Time taken for ObjectCache activity', 'w3-total-cache' ); ?>
			<canvas id="w3tcus_objectcache_time_chart"></canvas>
			<?php esc_html_e( 'Calls', 'w3-total-cache' ); ?>
			<canvas id="w3tcus_objectcache_chart"></canvas>
		</div>
	</div>

	<div class="ustats_block ustats_fragmentcache">
		<div class="ustats_block_data">
			<div class="ustats_header"><?php esc_html_e( 'Fragment Cache:', 'w3-total-cache' ); ?></div>
			<div class="ustats_fragmentcache_calls_total">
				<?php esc_html_e( 'Calls/period: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_fragmentcache_calls_per_second">
				<?php esc_html_e( 'Calls/sec: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_fragmentcache_hit_rate">
				<?php esc_html_e( 'Hit rate: ', 'w3-total-cache' ); ?><span></span>
			</div>
		</div>
	</div>

	<?php Util_Ui::postbox_footer(); ?>
</div>


<div class="metabox-holder" style="display: none">
	<?php Util_Ui::postbox_header( __( 'Database', 'w3-total-cache' ) ); ?>

	<div class="ustats_block ustats_dbcache" style="height: 32vw">
		<div class="ustats_block_data">
			<div class="ustats_header">
				<?php esc_html_e( 'Database Cache', 'w3-total-cache' ); ?>
				<span class="ustats_dbcache_engine_name w3tcus_inline">(<span></span>)</span>
			</div>

			<div class="ustats_dbcache_calls_total">
				<?php esc_html_e( 'Calls/period: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_dbcache_calls_per_second">
				<?php esc_html_e( 'Calls/sec: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_dbcache_hit_rate">
				<?php esc_html_e( 'Hit rate: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_dbcache_flushes">
				<?php esc_html_e( 'Cache flushes: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_dbcache_time_ms">
				<?php esc_html_e( 'Time taken: ', 'w3-total-cache' ); ?><span></span><?php esc_html_e( ' ms', 'w3-total-cache' ); ?>
			</div>

			<a href="?page=w3tc_stats&view=db_requests"><?php esc_html_e( 'Slowest requests (in debug mode only)', 'w3-total-cache' ); ?></a>
		</div>
		<div class="ustats_block_chart">
			<?php esc_html_e( 'Time taken for database activity', 'w3-total-cache' ); ?>
			<canvas id="w3tcus_dbcache_time_chart"></canvas>
			<?php esc_html_e( 'Requests', 'w3-total-cache' ); ?>
			<canvas id="w3tcus_dbcache_chart"></canvas>
		</div>
	</div>

	<div class="ustats_block ustats_wpdb">
		<div class="ustats_block_data">
			<div class="ustats_header"><?php esc_html_e( 'Database:', 'w3-total-cache' ); ?></div>
			<div class="ustats_wpdb_calls_total">
				<?php esc_html_e( 'Calls/period: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_wpdb_calls_per_second">
				<?php esc_html_e( 'Calls/sec: ', 'w3-total-cache' ); ?><span></span>
			</div>
		</div>
		<div class="ustats_block_chart">
			<?php esc_html_e( 'Requests', 'w3-total-cache' ); ?>
			<canvas id="w3tcus_wpdb_chart"></canvas>
		</div>
	</div>

	<?php Util_Ui::postbox_footer(); ?>
</div>


<div class="metabox-holder" style="display: none">
	<?php Util_Ui::postbox_header( esc_html__( 'System Info', 'w3-total-cache' ) ); ?>

	<div class="ustats_block ustats_php">
		<div class="ustats_block_data">
			<div class="ustats_header"><?php esc_html_e( 'PHP Memory:', 'w3-total-cache' ); ?></div>
			<div class="ustats_php_memory">
				<?php esc_html_e( 'Memory used: ', 'w3-total-cache' ); ?><span></span>
			</div>
		</div>
		<div class="ustats_block_chart">
			<?php esc_html_e( 'Memory per request (MB)', 'w3-total-cache' ); ?>
			<canvas id="w3tcus_php_memory_chart"></canvas>
		</div>
	</div>

	<div class="ustats_block ustats_cpu">
		<div class="ustats_block_data">
			<div class="ustats_header"><?php esc_html_e( 'CPU load:', 'w3-total-cache' ); ?></div>
			<div class="ustats_cpu_avg">
				<?php esc_html_e( 'CPU load: ', 'w3-total-cache' ); ?><span></span>
			</div>
		</div>
		<div class="ustats_block_chart">
			<?php esc_html_e( 'CPU load', 'w3-total-cache' ); ?>
			<canvas id="w3tcus_cpu_chart"></canvas>
		</div>
	</div>

	<?php Util_Ui::postbox_footer(); ?>
</div>


<div class="metabox-holder" style="display: none">
	<?php Util_Ui::postbox_header( esc_html__( 'Cache Storage', 'w3-total-cache' ) ); ?>

	<div class="ustats_block ustats_memcached" style="height: 32vw">
		<div class="ustats_block_data">
			<div class="ustats_header">
				<?php esc_html_e( 'Memcached', 'w3-total-cache' ); ?>
			</div>
			<div class="ustats_memcached_used_by">
				<?php esc_html_e( 'Used by ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_memcached_evictions_per_second">
				<?php esc_html_e( 'Evictions/sec: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_memcached_size_used">
				<?php esc_html_e( 'Used: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_memcached_size_percent">
				<?php esc_html_e( 'Used (%): ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_memcached_get_hit_rate">
				<?php esc_html_e( 'Hit rate: ', 'w3-total-cache' ); ?><span></span>
			</div>
		</div>
		<div class="ustats_block_chart">
			<?php esc_html_e( 'Size used (MB)', 'w3-total-cache' ); ?>
			<canvas id="w3tcus_memcached_size_chart"></canvas>
			<?php esc_html_e( 'Hit rate', 'w3-total-cache' ); ?>
			<canvas id="w3tcus_memcached_hit_chart"></canvas>
		</div>
	</div>

	<div class="ustats_block ustats_redis" style="height: 32vw">
		<div class="ustats_block_data">
			<div class="ustats_header">
				<?php esc_html_e( 'Redis', 'w3-total-cache' ); ?>
			</div>
			<div class="ustats_redis_used_by">
				<?php esc_html_e( 'Used by ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_redis_evictions_per_second">
				<?php esc_html_e( 'Evictions/sec: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_redis_size_used">
				<?php esc_html_e( 'Used: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_redis_get_hit_rate">
				<?php esc_html_e( 'Hit rate: ', 'w3-total-cache' ); ?><span></span>
			</div>
		</div>
		<div class="ustats_block_chart">
			<?php esc_html_e( 'Size used (MB)', 'w3-total-cache' ); ?>
			<canvas id="w3tcus_redis_size_chart"></canvas>
			<?php esc_html_e( 'Hit rate', 'w3-total-cache' ); ?>
			<canvas id="w3tcus_redis_hit_chart"></canvas>
		</div>
	</div>

	<div class="ustats_block ustats_apc" style="height: 32vw">
		<div class="ustats_block_data">
			<div class="ustats_header">
				<?php esc_html_e( 'APC', 'w3-total-cache' ); ?>
			</div>
			<div class="ustats_apc_used_by">
				<?php esc_html_e( 'Used by ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_apc_evictions">
				<?php esc_html_e( 'Evictions: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_apc_size_used">
				<?php esc_html_e( 'Used: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_apc_size_percent">
				<?php esc_html_e( 'Used (%): ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_apc_get_hit_rate">
				<?php esc_html_e( 'Hit rate: ', 'w3-total-cache' ); ?><span></span>
			</div>
			<div class="ustats_apc_items">
				<?php esc_html_e( 'Items: ', 'w3-total-cache' ); ?><span></span>
			</div>
		</div>
		<div class="ustats_block_chart">
			<?php esc_html_e( 'Size used (MB)', 'w3-total-cache' ); ?>
			<canvas id="w3tcus_apc_size_chart"></canvas>
			<?php esc_html_e( 'Hit rate', 'w3-total-cache' ); ?>
			<canvas id="w3tcus_apc_hit_chart"></canvas>
		</div>
	</div>

	<?php Util_Ui::postbox_footer(); ?>
</div>
