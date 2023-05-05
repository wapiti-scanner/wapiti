<?php
namespace W3TC;



/**
 * Provides statistics data about requests made to mysql server
 */
class UsageStatistics_Source_Wpdb {
	private $query_total = 0;



	static public function init() {
		$o = new UsageStatistics_Source_Wpdb();

		add_filter( 'query', array( $o, 'query' ) );
		add_action( 'w3tc_usage_statistics_of_request', array(
			$o, 'w3tc_usage_statistics_of_request' ), 10, 1 );
		add_filter( 'w3tc_usage_statistics_metrics', array(
			$o, 'w3tc_usage_statistics_metrics' ) );
		add_filter( 'w3tc_usage_statistics_summary_from_history', array(
			$o, 'w3tc_usage_statistics_summary_from_history' ), 10, 2 );
	}



	public function w3tc_usage_statistics_metrics( $metrics ) {
		return array_merge( $metrics, array( 'wpdb_calls_total' ) );
	}



	public function w3tc_usage_statistics_summary_from_history( $summary, $history ) {
		// counters
		$wpdb_calls_total = Util_UsageStatistics::sum( $history,
			'wpdb_calls_total' );

		$summary['wpdb'] = array(
			'calls_total' => Util_UsageStatistics::integer(
				$wpdb_calls_total ),
			'calls_per_second' => Util_UsageStatistics::value_per_period_seconds(
				$wpdb_calls_total, $summary )
		);

		return $summary;
	}



	public function w3tc_usage_statistics_of_request( $storage ) {
		$storage->counter_add( 'wpdb_calls_total', $this->query_total );
	}



	public function query( $q ) {
		$this->query_total++;
		return $q;
	}
}
