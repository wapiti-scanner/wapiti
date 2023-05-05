<?php
namespace W3TC;



class UsageStatistics_Plugin {
	public function run() {
		$core = Dispatcher::component( 'UsageStatistics_Core' );
		$core->add_shutdown_handler();

		// usage default statistics handling
		add_action( 'w3tc_usage_statistics_of_request', array(
				$this, 'w3tc_usage_statistics_of_request' ), 10, 1 );
		add_filter( 'w3tc_usage_statistics_metrics', array(
				$this, 'w3tc_usage_statistics_metrics' ) );
		add_filter( 'w3tc_usage_statistics_metric_values', array(
				'\W3TC\UsageStatistics_Sources',
				'w3tc_usage_statistics_metric_values' ) );
		add_filter( 'w3tc_usage_statistics_history_set', array(
				'\W3TC\UsageStatistics_Sources',
				'w3tc_usage_statistics_history_set' ) );

		UsageStatistics_Source_Wpdb::init();
	}



	public function w3tc_usage_statistics_of_request( $storage ) {
		$used_100kb = memory_get_peak_usage( true ) / 1024 / 10.24;

		$storage->counter_add( 'php_memory_100kb', $used_100kb );
		$storage->counter_add( 'php_requests', 1 );

/* keep for mode when pagecache not enabled, otherwise it shows own stats similar to that
		if ( defined( 'WP_ADMIN' ) ) {
			$storage->counter_add( 'php_requests_wp_admin', 1 );
		}
		if ( defined( 'DOING_AJAX' ) ) {
			$storage->counter_add( 'php_requests_ajax', 1 );
		}
*/
	}



	public function w3tc_usage_statistics_metrics( $metrics ) {
		return array_merge( $metrics, array(
				'php_memory_100kb', 'php_requests' ) );
	}
}
