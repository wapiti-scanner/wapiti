<?php
namespace W3TC;

/**
 * Download extended statistics since module cant do it by itself
 */
class Cache_Memcached_Stats {
	public function __construct( $host, $port ) {
		$this->host = $host;
		$this->port = $port;
	}

	public function request( $command ) {
		$handle = @fsockopen( $this->host, $this->port );
		if ( !$handle )
			return null;

		fwrite( $handle, $command . "\r\n" );

		$response = array();
		while ( ( !feof( $handle ) ) ) {
			$line = fgets( $handle );
			$response[] = $line;

			if ( $this->end( $line, $command ) )
				break;
		}

		@fclose( $handle );
		return $response;
	}

	private function end( $buffer, $command ) {
		// incr or decr also return integer
		if ( ( preg_match( '/^(incr|decr)/', $command ) ) ) {
			if ( preg_match(
					'/^(END|ERROR|SERVER_ERROR|CLIENT_ERROR|NOT_FOUND|[0-9]*)/',
					$buffer ) )
				return true;
		} else {
			if ( preg_match( '/^(END|DELETED|OK|ERROR|SERVER_ERROR|CLIENT_ERROR|NOT_FOUND|STORED|RESET|TOUCHED)/', $buffer ) )
				return true;
		}

		return false;
	}

	public function parse( $lines ) {
		$return = array();

		foreach ( $lines as $line ) {
			$data = explode( ' ', $line );
			$return[] = $data;
		}

		return $return;
	}

	public function slabs() {
		$result = $this->request( 'stats slabs' );
		if ( is_null( $result ) )
			return null;

		$result = $this->parse( $result );
		$slabs = array();

		foreach ( $result as $line_words ) {
			if ( count( $line_words ) < 2 )
				continue;

			$key = explode( ':', $line_words[1] );
			if ( (int)$key[0] > 0 )
				$slabs[$key[0]] = '*';
		}

		return array_keys( $slabs );
	}

	public function cachedump( $slab_id ) {
		$result = $this->request( 'stats cachedump ' . $slab_id . ' 0' );
		if ( is_null( $result ) )
			return null;

		// return pure data to limit memory usage
		return $result;
	}
}
