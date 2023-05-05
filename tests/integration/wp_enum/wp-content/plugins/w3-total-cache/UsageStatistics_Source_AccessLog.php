<?php
namespace W3TC;



/**
 * Access log reader - provides statistics data from http server access log
 */
class UsageStatistics_Source_AccessLog {
	// configuration
	private $line_regexp;

	private $max_line = '';
	private $max_time = 0;
	private $min_time;
	private $min_line = '';

	// running values

	// read access log after that timestamp
	private $max_already_counted_timestamp;

	// what was loaded now in this cycle
	private $max_now_counted_timestamp = null;

	// if need to read more access log chunks
	private $more_log_needed = true;

	// where data aggregated
	private $history;
	private $history_current_pos;
	private $history_current_item;
	private $history_current_timestamp_start;
	private $history_current_timestamp_end;



	static public function w3tc_usage_statistics_summary_from_history( $summary, $history ) {
		$dynamic_requests_total = Util_UsageStatistics::sum( $history,
			array( 'access_log', 'dynamic_count' ) );
		$dynamic_timetaken_ms_total = Util_UsageStatistics::sum( $history,
			array( 'access_log', 'dynamic_timetaken_ms' ) );
		$static_requests_total = Util_UsageStatistics::sum( $history,
			array( 'access_log', 'static_count' ) );
		$static_timetaken_ms_total = Util_UsageStatistics::sum( $history,
			array( 'access_log', 'static_timetaken_ms' ) );


		$summary['access_log'] = array(
			'dynamic_requests_total_v' => $dynamic_requests_total,
			'dynamic_requests_total' => Util_UsageStatistics::integer(
				$dynamic_requests_total ),
			'dynamic_requests_per_second' => Util_UsageStatistics::value_per_period_seconds(
				$dynamic_requests_total, $summary ),
			'dynamic_requests_timing' => Util_UsageStatistics::integer_divideby(
				$dynamic_timetaken_ms_total, $dynamic_requests_total ),
			'static_requests_total' => Util_UsageStatistics::integer(
				$static_requests_total ),
			'static_requests_per_second' => Util_UsageStatistics::value_per_period_seconds(
				$static_requests_total, $summary ),
			'static_requests_timing' => Util_UsageStatistics::integer_divideby(
				$static_timetaken_ms_total, $static_requests_total ),
		);

		return $summary;
	}



	/**
	 * array( 'webserver', 'format', 'filename' )
	 */
	public function __construct( $data ) {
		$format = $data['format'];
		$webserver = $data['webserver'];
		$this->accesslog_filename = str_replace( '://', '/', $data['filename'] );

		if ( $webserver == 'nginx' ) {
			$line_regexp = $this->logformat_to_regexp_nginx( $format );
		} else {
			$line_regexp = $this->logformat_to_regexp_apache( $format );
		}

		$this->line_regexp = apply_filters( 'w3tc_ustats_access_log_format_regexp',
			$line_regexp );
	}



	public function w3tc_usage_statistics_history_set( $history ) {
		$this->max_already_counted_timestamp = (int)get_site_option( 'w3tc_stats_history_access_log' );
		if ( isset( $history[0]['timestamp_start'] ) &&
				$history[0]['timestamp_start'] > $this->max_already_counted_timestamp ) {
			$this->max_already_counted_timestamp = $history[0]['timestamp_start'] - 1;
		}

		$this->history = $history;
		$this->min_time = time();
		$this->setup_history_item( count( $history ) - 1 );

		$h = @fopen( $this->accesslog_filename, 'rb' );
		if ( !$h ) {
			error_log( 'Failed to open access log for usage statisics collection' );
			return $history;
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

		if ( defined( 'W3TC_DEBUG' ) && W3TC_DEBUG ) {
			Util_Debug::log( 'time',
				"period " .
				date( DATE_ATOM, $this->max_already_counted_timestamp ) . ' - ' .
				date( DATE_ATOM, $this->max_now_counted_timestamp ) . "\n" .
				"min line: " . $this->min_line . "\n" .
				"max line: " . $this->max_line );
		}

		if ( !is_null( $this->max_now_counted_timestamp ) ) {
			update_site_option( 'w3tc_stats_history_access_log',
				$this->max_now_counted_timestamp );
		}

		return $this->history;
	}



	private function setup_history_item( $pos ) {
		$this->history_current_pos = $pos;

		if ( !isset( $this->history[$pos]['access_log'] ) ) {
			$this->history[$pos]['access_log'] = array(
				'dynamic_count' => 0,
				'dynamic_timetaken_ms' => 0,
				'static_count' => 0,
				'static_timetaken_ms' => 0,
			);
		}

		$this->history_current_item = &$this->history[$pos]['access_log'];
		$this->history_current_timestamp_start = $this->history[$pos]['timestamp_start'];
		$this->history_current_timestamp_end = $this->history[$pos]['timestamp_end'];
	}



	private function parse_string( $s, $skip_first_line ) {
		$s_length = strlen( $s );
		$unparsed_head = '';
		$lines = array();

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
		$line_elements = array();
		$line_element_start = $n;

		for ( ; $n < $s_length; $n++ ) {
			$c = substr( $s, $n, 1 );
			if ( $c == "\r" || $c == "\n" ) {
				if ( $n > $line_start ) {
					$lines[] = substr( $s, $line_start, $n - $line_start );
				}

				$line_start = $n + 1;
			}
		}

		// last line comes first, boundary checks logic based on that
		for ( $n = count( $lines ) - 1; $n >= 0; $n-- ) {
			$this->push_line( $lines[$n] );
		}

		return $unparsed_head;
	}



	private function push_line( $line ) {
		$e = array();
		preg_match( $this->line_regexp, $line, $e );

		$e = apply_filters( 'w3tc_ustats_access_log_line_elements', $e, $line );
		if ( !isset( $e['request_line'] ) || !isset( $e['date'] ) ) {
			if ( defined( 'W3TC_DEBUG' ) && W3TC_DEBUG ) {
				Util_Debug::log( 'time',
					"line $line cant be parsed using regexp $this->line_regexp, request_line or date elements missing"
				);
			}
			return;
		}

		$date_string = $e['date'];
		$time = strtotime($date_string);

		// dont read more if we touched entries before timeperiod of collection
		if ( $time <= $this->max_already_counted_timestamp ) {
			$this->more_log_needed = false;
			return;
		}
		if ( $time > $this->history_current_timestamp_end ) {
			return;
		}
		while ( $time < $this->history_current_timestamp_start ) {
			if ( $this->history_current_pos <= 0 ) {
				$this->more_log_needed = false;
				return;
			}
			$this->setup_history_item( $this->history_current_pos - 1 );
		}
		if ( is_null( $this->max_now_counted_timestamp ) ) {
			$this->max_now_counted_timestamp = $time;
		}

		if ( defined( 'W3TC_DEBUG' ) && W3TC_DEBUG ) {
			if ($time < $this->min_time) {
				$this->min_line = $line;
				$this->min_time = $time;
			}
			if ($time > $this->max_time) {
				$this->max_line = $line;
				$this->max_time = $time;
			}
		}

		$http_request_line = $e['request_line'];
		$http_request_line_items = explode( ' ', $http_request_line );
		$uri = $http_request_line_items[1];

		$time_ms = 0;
		if ( isset( $e['time_taken_microsecs'] ) ) {
			$time_ms = (int)($e['time_taken_microsecs'] / 1000);
		} elseif ( isset( $e['time_taken_ms'] ) ) {
			$time_ms = (int)$e['time_taken_ms'];
		}

		$m = null;
		preg_match('~\\.([a-zA-Z0-9]+)(\?.+)?$~', $uri, $m );
		if ( $m && $m[1] != 'php') {
			$this->history_current_item['static_count']++;
			$this->history_current_item['static_timetaken_ms'] += $time_ms;
		} else {
			$this->history_current_item['dynamic_count']++;
			$this->history_current_item['dynamic_timetaken_ms'] += $time_ms;
		}
	}



	// default: %h %l %u %t \"%r\" %>s %b
	// common : %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"
	public function logformat_to_regexp_apache( $format ) {
		// remove modifiers like %>s, %!400,501{User-agent}i
		$format = preg_replace('~%[<>!0-9]([a-zA-Z{])~', '%$1', $format);

		// remove modifiers %{User-agent}^ti, %{User-agent}^to
		$format = preg_replace('~%({[^}]+})(^ti|^to)~', '%$1z', $format);

		// take all quoted vars
		$format = preg_replace_callback('~\\\"(%[a-zA-Z%]|%{[^}]+}[a-zA-Z])\\\"~',
			array( $this, 'logformat_to_regexp_apache_element_quoted' ),
			$format);

		// take all remaining vars
		$format = preg_replace_callback('~(%[a-zA-Z%]|%{[^}]+}[a-zA-Z])~',
			array( $this, 'logformat_to_regexp_apache_element_naked' ),
			$format);

		return '~' . $format . '~';
	}



	public function logformat_to_regexp_apache_element_quoted( $match ) {
		$v = $match[1];

		if ( $v == '%r' ) {
			return '\"(?<request_line>[^"]+)\"';
		}

		// default behavior, expected value doesnt contain spaces
		return '\"([^"]+)\"';
	}



	public function logformat_to_regexp_apache_element_naked( $match ) {
		$v = $match[1];

		if ( $v == '%t' ) {
			return '\[(?<date>[^\]]+)\]';
		} elseif ( $v == '%D' ) {
			return '(?<time_taken_microsecs>[0-9]+)';
		}

		// default behavior, expected value doesnt contain spaces
		return '([^ ]+)';
	}



	// default: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
	// w3tc: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time
	public function logformat_to_regexp_nginx( $format ) {
		// escape quotes
		$format = preg_replace_callback('~([\"\[\]])~',
			array( $this, 'logformat_to_regexp_nginx_quote' ),
			$format);

		// take all quoted vars
		$format = preg_replace_callback('~\\\"(\$[a-zA-Z0-9_]+)\\\"~',
			array( $this, 'logformat_to_regexp_nginx_element_quoted' ),
			$format);

		// take all remaining vars
		$format = preg_replace_callback('~(\$[a-zA-Z0-9_]+)~',
			array( $this, 'logformat_to_regexp_nginx_element_naked' ),
			$format);

		return '~' . $format . '~';
	}



	public function logformat_to_regexp_nginx_quote( $match ) {
		return '\\' . $match[1];
	}



	public function logformat_to_regexp_nginx_element_quoted( $match ) {
		$v = $match[1];

		if ( $v == '$request' ) {
			return '\"(?<request_line>[^"]+)\"';
		}

		// default behavior, expected value doesnt contain spaces
		return '\"([^"]+)\"';
	}



	public function logformat_to_regexp_nginx_element_naked( $match ) {
		$v = $match[1];

		if ( $v == '$time_local' ) {
			return '(?<date>[^\]]+)';
		} elseif ( $v == '$request_time' ) {
			return '(?<time_taken_ms>[0-9.]+)';
		}

		// default behavior, expected value doesnt contain spaces
		return '([^ ]+)';
	}
}
