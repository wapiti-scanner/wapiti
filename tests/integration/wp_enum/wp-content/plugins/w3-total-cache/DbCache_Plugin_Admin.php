<?php
namespace W3TC;

class DbCache_Plugin_Admin {
	function run() {
		$config_labels = new DbCache_ConfigLabels();
		add_filter( 'w3tc_config_labels', array( $config_labels, 'config_labels' ) );

		$c = Dispatcher::config();
		if ( $c->get_boolean( 'dbcache.enabled' ) ) {
			add_filter( 'w3tc_usage_statistics_summary_from_history', array(
					$this, 'w3tc_usage_statistics_summary_from_history' ), 10, 2 );
			add_filter( 'w3tc_errors', array( $this, 'w3tc_errors' ) );
		}
	}



	public function w3tc_usage_statistics_summary_from_history( $summary, $history ) {
		// counters
		$dbcache_calls_total = Util_UsageStatistics::sum( $history,
			'dbcache_calls_total' );
		$dbcache_calls_hits = Util_UsageStatistics::sum( $history,
			'dbcache_calls_hits' );
		$dbcache_flushes = Util_UsageStatistics::sum( $history,
			'dbcache_flushes' );
		$dbcache_time_ms = Util_UsageStatistics::sum( $history,
			'dbcache_time_ms' );

		$c = Dispatcher::config();
		$e = $c->get_string( 'dbcache.engine' );

		$summary['dbcache'] = array(
			'calls_total' => Util_UsageStatistics::integer(
				$dbcache_calls_total ),
			'calls_per_second' => Util_UsageStatistics::value_per_period_seconds(
				$dbcache_calls_total, $summary ),
			'flushes' => Util_UsageStatistics::integer( $dbcache_flushes ),
			'time_ms' => Util_UsageStatistics::integer( $dbcache_time_ms ),
			'hit_rate' => Util_UsageStatistics::percent(
				$dbcache_calls_hits, $dbcache_calls_total ),
			'engine_name' => Cache::engine_name( $e )
		);

		return $summary;
	}



	public function w3tc_errors( $errors ) {
		$c = Dispatcher::config();

		if ( $c->get_string( 'dbcache.engine' ) == 'memcached' ) {
			$memcached_servers = $c->get_array( 'dbcache.memcached.servers' );

			if ( !Util_Installed::is_memcache_available( $memcached_servers ) ) {
				if ( !isset( $errors['memcache_not_responding.details'] ) )
					$errors['memcache_not_responding.details'] = array();

				$errors['memcache_not_responding.details'][] = sprintf(
					__( 'Database Cache: %s.', 'w3-total-cache' ),
					implode( ', ', $memcached_servers ) );
			}
		}

		return $errors;
	}
}
