<?php
namespace W3TC;



class UsageStatistics_Sources_Apc {
	private $module_names = array();

	public function __construct( $server_descriptors ) {
		foreach ( $server_descriptors as $module_key => $i ) {
			$this->module_names[] = $i['name'];
		}
	}



	public function get_snapshot() {
		$cache = apcu_cache_info();

		return array(
			'items' => $cache['num_entries'],
			'size_used' => $cache['mem_size'],
			'get_hits' => $cache['num_hits'],
			'get_total' => ( $cache['num_hits'] + $cache['num_misses'] )
		);
	}



	public function get_summary() {
		$cache = apcu_cache_info();

		$time = time();
		$runtime = $time - $cache['start_time'];

		$mem = apcu_sma_info();
		$mem_size = $mem['num_seg'] * $mem['seg_size'];
		$mem_avail = $mem['avail_mem'];
		$mem_used = $mem_size - $mem_avail;

		$sum = array(
			'used_by' => implode( ',', $this->module_names ),
			'items' => $cache['num_entries'],
			'size_used' => Util_UsageStatistics::bytes_to_size( $cache['mem_size'] ),
			'get_hits' => $cache['num_hits'],
			'get_total' => ( $cache['num_hits'] + $cache['num_misses'] ),
			'runtime_secs' => $runtime,
			'evictions' => $cache['expunges'],
			'size_percent' => Util_UsageStatistics::percent(
				$mem_used, $mem_avail )
		);

		if ( $sum['runtime_secs'] != 0 ) {
			$sum['requests_per_second'] = sprintf( '%.2f',
				$sum['get_total'] / $sum['runtime_secs'] );
		}

		$sum['get_hit_rate'] = Util_UsageStatistics::percent2(
			$sum, 'get_hits', 'get_total' );

		return $sum;
	}
}
