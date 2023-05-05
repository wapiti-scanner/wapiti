<?php
namespace W3TC;



/**
 * database queries debug log reader - provides data from this logfile
 */
class UsageStatistics_Source_ObjectCacheLog {
	// running values
	private $timestamp_start;
	private $sort_column;

	private $by_group = array();

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
		$log_filename = Util_Debug::log_filename( 'objectcache-calls' );
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
		foreach ( $this->by_group as $group => $data ) {
			$output[] = array(
				'group' => $group,
				'count_total' => $data['count_total'],
				'count_get_total' => $data['count_get_total'],
				'count_get_hit' => $data['count_get_hit'],
				'count_set' => $data['count_set'],
				'sum_size' => $data['sum_size'],
				'avg_size' => $data['count_total'] ? (int)( $data['sum_size'] / $data['count_total'] ) : 0,
				'sum_time_ms' => (int)$data['sum_time_ms']
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
		$op = $matches[1];
		$group = $matches[2];
		$id = $matches[3];
		$reason = $matches[4];
		$size = (int)$matches[5];
		$time_taken_ms = isset( $matches[6] ) ? (float)$matches[6] / 1000 : 0;

		$time = strtotime($date_string);

		// dont read more if we touched entries before timeperiod of collection
		if ( $time < $this->timestamp_start ) {
			$this->more_log_needed = false;
		}

		if ( $reason == 'not tried cache' ||
			substr( $reason, 0, 7 ) == 'not set' ) {
			return;   // it's not cache-related activity
		}

		if ( !isset( $this->by_group[$group] ) ) {
			$this->by_group[$group] = array(
				'count_total' => 0,
				'count_get_total' => 0,
				'count_get_hit' => 0,
				'count_set' => 0,
				'sum_size' => 0,
				'sum_time_ms' => 0
			);
		}

		if ( $op == 'get' ) {
			$this->by_group[$group]['count_total']++;
			$this->by_group[$group]['count_get_total']++;
			if ($reason == 'from persistent cache') {
				$this->by_group[$group]['count_get_hit']++;
			}
		} elseif ( $op == 'set' ) {
			$this->by_group[$group]['count_total']++;
			$this->by_group[$group]['count_set']++;
		}

		$this->by_group[$group]['sum_size'] += $size;
		$this->by_group[$group]['sum_time_ms'] += $time_taken_ms;
	}
}
