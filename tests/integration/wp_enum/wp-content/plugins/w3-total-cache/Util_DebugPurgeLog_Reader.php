<?php
namespace W3TC;



/**
 * Reads purge log from the end to top to get last records
 */
class Util_DebugPurgeLog_Reader {
	private $lines = array();
	private $current_item = array();



	private function __construct() {
	}



	static public function read( $module ) {
		$o = new Util_DebugPurgeLog_Reader();
		return $o->_read( $module );
	}



	private function _read( $module ) {
		$log_filename = Util_Debug::log_filename( $module . '-purge' );
		if ( !file_exists( $log_filename) ) {
			return array();
		}

		$h = @fopen( $log_filename, 'rb' );
		if ( !$h ) {
			throw new \Exception( 'Failed to open log file' . $log_filename );
		}

		fseek( $h, 0, SEEK_END );
		$pos = ftell( $h );
		$unparsed_head = '';

		$more_log_needed = true;

		while ( $pos >= 0 ) {
			$to_read = 26;
			$pos -= $to_read;
			if ( $pos <= 0 ) {
				$to_read = $to_read + $pos;
				$pos = 0;
			}
			fseek( $h, $pos );

			$s = fread( $h, $to_read );

			$unparsed_head = $this->parse_string( $s . $unparsed_head );
			if ( count( $this->lines ) > 100 ) {
				break;
			}
			if ( $pos <= 0 ) {
				$this->push_line( $unparsed_head );
				break;
			}
		}

		return $this->lines;
	}



	private function parse_string( $s ) {
		$first_unparsed = strlen( $s );
		$pos = $first_unparsed;

		for ( ; $pos >= 0; $pos-- ) {
			$c = substr( $s, $pos, 1 );
			if ( $c == "\r" || $c == "\n" ) {
				$this->push_line( substr( $s, $pos + 1, $first_unparsed - $pos - 1 ) );
				$first_unparsed = $pos;
			}
		}

		return substr( $s, 0, $first_unparsed );
	}



	private function push_line( $line ) {
		if ( empty( $line ) ) {
			return;
		}

		if ( substr( $line, 0, 1) == "\t" ) {
			array_unshift( $this->current_item, $line );
			return;
		}

		// split secondary lines to urls and backtrace
		$postfix = array();
		$backtrace = array();
		$username = '';
		foreach ( $this->current_item as $item ) {
			$item = trim( $item );
			if ( preg_match( '~^(#[^ ]+) ([^:]+): (.*)~', $item, $m ) ) {
				$backtrace[] = array(
					'number' => $m[1],
					'filename' => $m[2],
					'function' => $m[3]
				);
			} elseif ( preg_match( '~^username:(.*)~', $item, $m ) ) {
				$username = $m[1];
			} else {
				$postfix[] = $item;
			}
		}

		$m = null;
		if ( preg_match( '~\\[([^\\]]+)\\] (.*)~', $line, $m ) ) {
			$this->lines[] = array(
				'date' => $m[1],
				'message' => $m[2],
				'username' => $username,
				'postfix' => $postfix,
				'backtrace' => $backtrace
			);
		}

		$this->current_item = array();
	}
}
