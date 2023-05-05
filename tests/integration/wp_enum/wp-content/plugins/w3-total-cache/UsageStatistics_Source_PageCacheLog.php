<?php
namespace W3TC;



/**
 * PageCache debug log reader - provides data from this logfile
 */
class UsageStatistics_Source_PageCacheLog {
	// running values
	private $timestamp_start;
	private $process_status;
	private $sort_column;

	private $by_uri = array();

	/* if need to read more access log chunks */
	private $more_log_needed = true;



	function __construct( $timestamp_start, $process_status, $sort_column ) {
		$this->timestamp_start = $timestamp_start;
		$this->process_status = $process_status;
		$this->sort_column = $sort_column;
	}

	/**
	 * Lists entries from log with specified cache reject reason code
	 **/
	public function list_entries() {
		$log_filename = Util_Debug::log_filename( 'pagecache' );
		$h = @fopen( $log_filename, 'rb' );
		if ( !$h ) {
			throw new \Exception( 'Failed to open pagecache log file' . $log_filename );
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
		foreach ( $this->by_uri as $uri => $data ) {
			$output[] = array(
				'uri' => $uri,
				'count' => $data['count'],
				'avg_size' => (int)( $data['sum_size'] / $data['count'] ),
				'avg_time_ms' => (int)( $data['sum_time_ms'] / $data['count'] ),
				'sum_time_ms' => $data['sum_time_ms'],
				'reasons' => $data['reasons']
			);
		}

		usort( $output, function($a, $b) {
			return (int)($b[$this->sort_column]) - (int)($a[$this->sort_column]);
		});

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
		$matches = null;
		preg_match(
			'/\[([^>\]]+)\] \[([^>\]]+)\] \[([^>\]]+)\] finished in (\d+) size (\d+) with process status ([^ ]+) reason (.*)/',
			$line, $matches);

		if ( !$matches ) {
			return;
		}

		$date_string = $matches[1];
		$uri = $matches[2];
		$time_taken_ms = $matches[4];
		$size = $matches[5];
		$status = $matches[6];
		$reason = $matches[7];
		$time = strtotime($date_string);

		// dont read more if we touched entries before timeperiod of collection
		if ( $time < $this->timestamp_start ) {
			$this->more_log_needed = false;
		}

		if ( $status != $this->process_status ) {
			return;
		}

		if ( !isset( $this->by_uri[$uri] ) ) {
			$this->by_uri[$uri] = array(
				'count' => 0,
				'sum_size' => 0,
				'sum_time_ms' => 0,
				'reasons' => array()
			);
		}

		$this->by_uri[$uri]['count']++;
		$this->by_uri[$uri]['sum_size'] += $size;
		$this->by_uri[$uri]['sum_time_ms'] += $time_taken_ms;

		if ( !in_array( $reason, $this->by_uri[$uri]['reasons']) ) {
			$this->by_uri[$uri]['reasons'][] = $reason;
		}
	}
}
