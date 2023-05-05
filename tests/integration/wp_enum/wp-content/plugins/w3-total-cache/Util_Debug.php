<?php
namespace W3TC;

class Util_Debug {
	/**
	 * Returns current microtime
	 *
	 * @return double
	 */
	static public function microtime() {
		list ( $usec, $sec ) = explode( ' ', microtime() );

		return (double) $usec + (double) $sec;
	}

	/**
	 * Return full path to log file for module
	 * Path used in priority
	 * 1) W3TC_DEBUG_DIR
	 * 2) WP_DEBUG_LOG
	 * 3) W3TC_CACHE_DIR
	 *
	 * @param unknown $module
	 * @param null    $blog_id
	 * @return string
	 */
	static public function log_filename( $module, $blog_id = null ) {
		if ( is_null( $blog_id ) )
			$blog_id = Util_Environment::blog_id();

		$postfix = sprintf( '%06d', $blog_id );

		if ( defined( 'W3TC_BLOG_LEVELS' ) ) {
			for ( $n = 0; $n < W3TC_BLOG_LEVELS; $n++ )
				$postfix = substr( $postfix, strlen( $postfix ) - 1 - $n, 1 ) .
					'/' . $postfix;
		}
		$from_dir = W3TC_CACHE_DIR;
		if ( defined( 'W3TC_DEBUG_DIR' ) && W3TC_DEBUG_DIR ) {
			$dir_path = W3TC_DEBUG_DIR;
			if ( !is_dir( W3TC_DEBUG_DIR ) )
				$from_dir = dirname( W3TC_DEBUG_DIR );
		} else
			$dir_path = Util_Environment::cache_dir( 'log' );
		$filename = $dir_path . '/' . $postfix . '/' . $module . '.log';
		if ( !is_dir( dirname( $filename ) ) ) {

			Util_File::mkdir_from_safe( dirname( $filename ), $from_dir );
		}

		return $filename;
	}



	static public function log( $module, $message ) {
		$message = strtr( $message, '<>', '..' );
		$filename = Util_Debug::log_filename( $module );

		return @file_put_contents( $filename, '[' . date( 'r' ) . '] ' .
			$message . "\n", FILE_APPEND );
	}



	/**
	 * Log cache purge event
	 */
	static public function log_purge( $module, $message, $parameters = null,
			$explicit_postfix = null ) {
		$backtrace = debug_backtrace( 0 );
		$backtrace_lines = array();
		$pos = 0;
		for ( $n = 2; $n < count( $backtrace ); $n++ ) {
			if ( !Util_Debug::log_purge_should_print_item( $backtrace, $n ) ) {
				continue;
			}

			$i = $backtrace[$n];
			$filename = isset( $i['file'] ) ? $i['file'] : '';
			$filename = str_replace( ABSPATH, '', $filename );

			$line = isset( $i['line'] ) ? $i['line'] : '';

			$method = ( !empty( $i['class'] ) ? $i['class'] . '--' : '' ) .
				$i['function'];
			$args = ' ' . Util_Debug::encode_params( $i['args'] );
			$backtrace_lines[] = "\t#" . ( $pos ) . ' ' .
				$filename . '(' . $line . '): ' . $method . $args;
			$pos++;
		}

		$message = $message;
		if ( !is_null( $parameters ) ) {
			$message .= Util_Debug::encode_params( $parameters );
		}

		$user = function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null;
		$username = ( empty( $user ) ? 'anonymous' : $user->user_login );
		$message .= "\n\tusername:$username";

		if ( is_array( $explicit_postfix ) ) {
			$message .= "\n\t" . implode( "\n\t", $explicit_postfix );
		}

		$message .= "\n" . implode( "\n", $backtrace_lines );

		return Util_Debug::log( $module . '-purge', $message );
	}



	static private function log_purge_should_print_item( $backtrace, $n ) {
		if ( !empty( $backtrace[$n]['class']) &&
				$backtrace[$n]['class'] == 'W3TC\\CacheFlush_Locally' ) {
			return false;
		}
		if ( !empty( $backtrace[$n]['class']) &&
				$backtrace[$n]['class'] == 'WP_Hook' &&
				!empty( $backtrace[$n + 1]['function'] ) ) {
			$f = $backtrace[$n + 1]['function'];
			if ( $f == 'do_action' || $f == 'apply_filters' ) {
				return false;
			}

			return Util_Debug::log_purge_should_print_item( $backtrace, $n + 1 );
		}

		return true;
	}



	static private function encode_params( $args ) {
		$args_strings = array();
		if ( !is_array( $args ) ) {
			$s = (string)$args;

			if ( strlen( $s ) > 100 ) {
				$s = substr( $s, 0, 98 ) . '..';
			}

			$args_strings[] = $s;
		} else {
			foreach ( $args as $arg ) {
				$s = json_encode( $arg,
					JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
				if ( strlen( $s ) > 100 ) {
					$s = substr( $s, 0, 98 ) . '..';
				}

				$args_strings[] = $s;
			}
		}

		return '(' . implode( ', ', $args_strings ) . ')';
	}

	/**
	 * Clean debug output with label headers.
	 */
	static public function debug( $label, $data ) {
		error_log('===============Debug ' . $label . ' Start===============');
		error_log(print_r($data,true));
		error_log('===============Debug ' . $label . ' End===============');
	}
}
