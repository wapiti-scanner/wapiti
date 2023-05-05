<?php
namespace W3TC;



class UsageStatistics_Sources_Memcached {
	private $servers;



	public function __construct( $server_descriptors ) {
		$this->servers = array();

		foreach ( $server_descriptors as $i ) {
			foreach ( $i['servers'] as $host_port ) {
				if ( !isset( $this->servers[$host_port] ) )
					$this->servers[$host_port] = array(
						'username' => $i['username'],
						'password' => $i['password'],
						'module_names' => array( $i['name'] )
					);
				else
					$this->servers[$host_port]['module_names'][] = $i['name'];
			}
		}
	}



	public function get_snapshot() {
		$size_used = 0;
		$get_calls = 0;
		$get_hits = 0;

		foreach ( $this->servers as $host_port => $i ) {
			$cache = Cache::instance( 'memcached',
				array(
					'servers' => array( $host_port ),
					'username' => $i['username'],
					'password' => $i['password']
				) );

			$stats = $cache->get_statistics();

			$size_used += Util_UsageStatistics::v( $stats, 'bytes' );
			$get_calls += Util_UsageStatistics::v( $stats, 'cmd_get' );
			$get_hits += Util_UsageStatistics::v( $stats, 'get_hits' );
		}

		return array(
			'size_used' => $size_used,
			'get_calls' => $get_calls,
			'get_hits' => $get_hits
		);
	}



	public function get_summary() {
		$sum = array(
			'module_names' => array(),
			'size_used' => 0,
			'size_maxbytes' => 0,
			'get_total' => 0,
			'get_hits' => 0,
			'evictions' => 0,
			'uptime' => 0
		);

		foreach ( $this->servers as $host_port => $i ) {
			$cache = Cache::instance( 'memcached',
				array(
					'servers' => array( $host_port ),
					'username' => $i['username'],
					'password' => $i['password']
				) );

			$stats = $cache->get_statistics();

			$sum['module_names'] =
				array_merge( $sum['module_names'], $i['module_names'] );
			$sum['size_used'] += Util_UsageStatistics::v3( $stats, 'bytes');
			$sum['size_maxbytes'] += Util_UsageStatistics::v3( $stats, 'limit_maxbytes' );
			$sum['get_total'] += Util_UsageStatistics::v3( $stats, 'cmd_get' );
			$sum['get_hits'] += Util_UsageStatistics::v3( $stats, 'get_hits' );
			$sum['evictions'] += Util_UsageStatistics::v3( $stats, 'evictions' );
			$sum['uptime'] += Util_UsageStatistics::v3( $stats, 'uptime' );
		}

		$summary = array(
			'module_names' => implode( ',', $sum['module_names'] ),
			'size_percent' => Util_UsageStatistics::percent2(
				$sum, 'size_used', 'size_maxbytes' ),
			'size_used' => Util_UsageStatistics::bytes_to_size2(
				$sum, 'size_used' ),
			'get_hit_rate' => Util_UsageStatistics::percent2(
				$sum, 'get_hits', 'get_total' ),
			'evictions_per_second' => Util_UsageStatistics::value_per_second(
				$sum, 'evictions', 'uptime' )
		);

		return $summary;
	}
}
