<?php
namespace W3TC;



/**
 * database queries debug log reader - provides data from this logfile
 */
class UsageStatistics_Source_DbQueriesLog {
	// running values
	private $timestamp_start;
	private $sort_column;

	private $by_query = array();

	/* if need to read more access log chunks */
	private $more_log_needed = true;



	function __construct( $timestamp_start, $sort_column ) {
		$this->timestamp_start = $timestamp_start;
		$this->sort_column = $sort_column;
	}

	/**
	 * Lists entries from log
	 **/
	public function list_entries() {
		$log_filename = Util_Debug::log_filename( 'dbcache-queries' );
		$h = @fopen( $log_filename, 'rb' );
		if ( !$h ) {
			throw new \Exception( 'Failed to open log file' . $log_filename );
		}

		fseek( $h, 0, SEEK_END );
		$pos = ftell( $h );
		$unparsed_head = '';

		while ( $pos >= 0 && $this->more_log_needed ) {
			$pos -= 8192;
			if ( $pos <= 0 ) {
				$pos = 0;
			}
			fseek( $h, $pos );

			$s = fread( $h, 8192 );

			$unparsed_head = $this->parse_string( $s . $unparsed_head, $pos > 0 );
			if ( $pos <= 0 ) {
				$this->more_log_needed = false;
			}
		}

		$output = array();
		foreach ( $this->by_query as $query => $data ) {
			$output[] = array(
				'query' => $query,
				'count_total' => $data['count_total'],
				'count_hit' => $data['count_hit'],
				'avg_size' => (int)( $data['sum_size'] / $data['count_total'] ),
				'avg_time_ms' => (int)( $data['sum_time_ms'] / $data['count_total'] ),
				'sum_time_ms' => (int)$data['sum_time_ms'],
				'reasons' => $data['reasons']
			);
		}

		usort( $output, function($a, $b) {
			return (int)($b[$this->sort_column]) - (int)($a[$this->sort_column]);
		});

		$output = array_slice( $output, 0, 200 );

		return $output;
	}



	private function parse_string( $s, $skip_first_line ) {
		$s_length = strlen( $s );
		$unparsed_head = '';

		$n = 0;
		if ( $skip_first_line ) {
			for ( ; $n < $s_length; $n++ ) {
				$c = substr( $s, $n, 1 );
				if ( $c == "\r" || $c == "\n" ) {
					$unparsed_head = substr( $s, 0, $n + 1 );
					break;
				}
			}
		}

		$line_start = $n;
		for ( ; $n < $s_length; $n++ ) {
			$c = substr( $s, $n, 1 );
			if ( $c == "\r" || $c == "\n" ) {
				if ( $n > $line_start ) {
					$this->push_line( substr( $s, $line_start, $n - $line_start ) );
				}

				$line_start = $n + 1;
			}
		}

		return $unparsed_head;
	}



	private function push_line( $line ) {
		$matches = str_getcsv( $line, "\t" );

		if ( !$matches ) {
			return;
		}

		$date_string = $matches[0];
		$query = $matches[2];
		$time_taken_ms = isset( $matches[3] ) ? (float)$matches[3] / 1000 : 0;
		$reason = isset( $matches[4] ) ? $matches[4] : '';
		$hit = isset( $matches[5] ) ? $matches[5] : false;
		$size = isset( $matches[6] ) ? $matches[6] : 0;

		$time = strtotime($date_string);

		// dont read more if we touched entries before timeperiod of collection
		if ( $time < $this->timestamp_start ) {
			$this->more_log_needed = false;
		}

		if ( !isset( $this->by_query[$query] ) ) {
			$this->by_query[$query] = array(
				'count_total' => 0,
				'count_hit' => 0,
				'sum_size' => 0,
				'sum_time_ms' => 0,
				'reasons' => array()
			);
		}

		$this->by_query[$query]['count_total']++;
		if ($hit) {
			$this->by_query[$query]['count_hit']++;
		}
		$this->by_query[$query]['sum_size'] += $size;
		$this->by_query[$query]['sum_time_ms'] += $time_taken_ms;

		if ( !in_array( $reason, $this->by_query[$query]['reasons']) ) {
			$this->by_query[$query]['reasons'][] = $reason;
		}
	}
}
