<?php
namespace W3TC;

class Util_UsageStatistics {
	static public function bytes_to_size( $v ) {
		if ( is_null( $v ) )
			return 'n/a';
		if ( $v > 500000000 )
			return sprintf( '%.1f GB', $v / 1024 /*KB*/ / 1024 /*MB*/ / 1024/*GB*/ );
		if ( $v > 500000 )
			return sprintf( '%.1f MB', $v / 1024 /*KB*/ / 1024 /*MB*/ );
		else
			return sprintf( '%.1f KB', $v / 1024 /*KB*/ );
	}



	static public function bytes_to_size2( $a, $p1, $p2 = null, $p3 = null ) {
		$v = self::v( $a, $p1, $p2, $p3 );
		if ( is_null( $v ) )
			return 'n/a';

		return self::bytes_to_size( $v );
	}



	static public function percent( $v1, $v2 ) {
		if ( $v2 == 0 ) {
			return '0 %';
		} elseif ($v1 > $v2 ) {
			return '100 %';
		} else {
			return sprintf( '%d', $v1 / $v2 * 100 ) . ' %';
		}
	}



	static public function percent2( $a, $property1, $property2 ) {
		if ( !isset( $a[$property1] ) || !isset( $a[$property2] ) )
			return 'n/a';
		else if ( $a[$property2] == 0 )
				return '0 %';
			else
				return sprintf( '%d', $a[$property1] / $a[$property2] * 100 ) . ' %';
	}



	static public function sum( $history, $property ) {
		$v = 0;
		foreach ( $history as $i ) {
			$item_value = self::v3( $i, $property );
			if ( !empty( $item_value ) ) {
				$v += $item_value;
			}
		}
		return $v;
	}



	static public function avg( $history, $property ) {
		$v = 0;
		$count = 0;
		foreach ( $history as $i ) {
			$item_value = self::v3( $i, $property );
			if ( !empty( $item_value ) ) {
				$v += $item_value;
				$count++;
			}
		}
		return ( $count <= 0 ? 0 : $v / $count );
	}



	/**
	 * Sum up all positive metric values which names start with specified prefix
	 **/
	static public function sum_by_prefix_positive( &$output, $history, $property_prefix ) {
		$property_prefix_len = strlen( $property_prefix );

		foreach ( $history as $i ) {
			foreach ( $i as $key => $value ) {
				if ( substr( $key, 0, $property_prefix_len ) == $property_prefix &&
					$value > 0 ) {
					if ( !isset( $output[$key] ) ) {
						$output[$key] = 0;
					}

					$output[$key] += $value;
				}
			}
		}
	}



	static public function time_mins( $timestamp ) {
		return date( 'm/d/Y H:i', $timestamp );
	}



	static public function integer( $v ) {
		return number_format( $v );
	}



	static public function integer_divideby( $v, $divide_by ) {
		if ( $divide_by == 0 ) {
			return 'n/a';
		}

		return self::integer( $v / $divide_by );
	}



	static public function integer2( $a, $p1, $p2 = null, $p3 = null ) {
		$v = self::v( $a, $p1, $p2, $p3 );
		if ( is_null( $v ) )
			return 'n/a';
		else
			return number_format( $v );
	}



	static public function v( $a, $p1, $p2 = null, $p3 = null ) {
		if ( !isset( $a[$p1] ) )
			return null;

		$v = $a[$p1];
		if ( is_null( $p2 ) )
			return $v;
		if ( !isset( $v[$p2] ) )
			return null;

		$v = $v[$p2];
		if ( is_null( $p3 ) )
			return $v;
		if ( !isset( $v[$p3] ) )
			return null;

		return $v[$p3];
	}



	static public function v3( $a, $p ) {
		if ( !is_array( $p ) ) {
			$p = array( $p );
		}

		$actual = &$a;
		for ( $i = 0; $i < count( $p ); $i++) {
			$property = $p[$i];

			if ( !isset( $actual[$property] ) ) {
				return null;
			}

			$actual = &$actual[$property];
		}

		return $actual;
	}



	static public function value_per_second( $a, $property1, $property2 ) {
		if ( !isset( $a[$property1] ) || !isset( $a[$property2] ) )
			return 'n/a';
		else if ( $a[$property2] == 0 )
				return '0';
			else
				return sprintf( '%.1f', $a[$property1] / $a[$property2] * 100 );
	}



	static public function value_per_period_seconds( $total, $summary ) {
		if ( empty( $summary['period']['seconds'] ) )
			return 'n/a';

		$period_seconds = $summary['period']['seconds'];

		return sprintf( '%.1f', $total / $period_seconds );
	}



	/**
	 * Special shared code for cache size counting
	 */
	static public function get_or_init_size_transient( $transient, $summary ) {
		$should_count = false;

		$v = get_transient( $transient );
		if ( is_array( $v ) && isset( $v['timestamp_end'] ) &&
			$v['timestamp_end'] == $summary['period']['timestamp_end'] ) {
			return array( $v, false );
		}

		// limit number of processing counting it at the same time
		$v = array(
			'timestamp_end' => $summary['period']['timestamp_end'],
			'size_used' => '...counting',
			'items' => '...counting'
		);
		set_transient( $transient, $v, 120 );
		return array( $v, true );
	}
}
