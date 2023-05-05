<?php
namespace W3TC;



/**
 * CloudFlare API
 */
class Extension_CloudFlare_Api {
	static private $_root_uri = 'https://api.cloudflare.com/client/v4';

	private $_email;
	private $_key;
	private $_zone_id;
	private $_timelimit_api_request;



	function __construct( $config ) {
		$this->_email = $config['email'];
		$this->_key = $config['key'];
		$this->_zone_id =
			( isset( $config['zone_id'] ) ? $config['zone_id'] : '' );

		if ( !isset( $config['timelimit_api_request'] ) ||
			$config['timelimit_api_request'] < 1 )
			$this->_timelimit_api_request = 30;
		else
			$this->_timelimit_api_request = $config['timelimit_api_request'];
	}



	/**
	 * Makes external event request
	 *
	 * @param string  $type
	 * @param string  $value
	 * @return array
	 */
	public function external_event( $type, $value ) {
		$url = sprintf( 'https://www.cloudflare.com/ajax/external-event.html?' .
			'u=%s&tkn=%s&evnt_t=%s&evnt_v=%s',
			urlencode( $this->_email ), urlencode( $this->_key ),
			urlencode( $type ), urlencode( $value ) );
		$response = Util_Http::get( $url );

		if ( !is_wp_error( $response ) ) {
			return json_decode( $response['body'] );
		}

		return null;
	}


	/**
	 * Check
	 *
	 * @throws Util_WpFile_FilesystemOperationException
	 * @throws FileOperationException
	 */
	public function get_ip_ranges() {
		$data = array();
		$response = Util_Http::get( 'https://www.cloudflare.com/ips-v4' );

		if ( !is_wp_error( $response ) ) {
			$ip4_data = $response['body'];
			$ip4_data = explode( "\n", $ip4_data );
			$data['ip4'] = $ip4_data;
		}
		$response = Util_Http::get( 'https://www.cloudflare.com/ips-v6' );
		if ( !is_wp_error( $response ) ) {
			$ip6_data = $response['body'];
			$ip6_data = explode( "\n", $ip6_data );
			$data['ip6'] = $ip6_data;
		}

		return $data;
	}



	public function zones($page = 1) {
		return $this->_wp_remote_request_with_meta( 'GET',
			self::$_root_uri . '/zones?page=' . urlencode($page) );
	}



	public function zone($id) {
		$a = $this->_wp_remote_request( 'GET',
			self::$_root_uri . '/zones/' . $id );

		return $a;
	}



	public function zone_settings() {
		$a = $this->_wp_remote_request( 'GET',
			self::$_root_uri . '/zones/' . $this->_zone_id . '/settings' );

		$by_id = array();
		foreach ( $a as $i ) {
			$by_id[$i['id']] = $i;
		}

		return $by_id;
	}



	public function zone_setting_set( $name, $value ) {
		return $this->_wp_remote_request( 'PATCH',
			self::$_root_uri . '/zones/' . $this->_zone_id . '/settings/' . $name,
			json_encode( array( 'value' => $value ) ) );
	}

	/**
	 * Prepares the analytics dashboard widget query to be performed via the CF GraphQL API
	 *
	 * @throws Exception
	 * @return array
	 */
	public function analytics_dashboard( $start, $end, $type = 'day' ) {
		$dataset = 'httpRequests1dGroups';
		$datetime_filter = 'date';

		if($type === 'hour') {
			$dataset = 'httpRequests1hGroups';
			$datetime_filter = 'datetime';
		}

		return $this->_wp_remote_request_graphql( 'POST',
			self::$_root_uri . '/graphql',
			"{ \"query\": \"query {
				viewer {
					zones(filter: {zoneTag: \\\"" . $this->_zone_id . "\\\"}) {
						" . $dataset . "(
							orderBy: [" . $datetime_filter . "_ASC],
							limit: 100,
							filter: {
								" . $datetime_filter . "_geq: \\\"" . $start . "\\\",
								" . $datetime_filter . "_lt: \\\"" . $end . "\\\"
							}
						) {
							dimensions {
								" . $datetime_filter . "
							}
							sum {
								bytes
								cachedBytes
								cachedRequests
								pageViews
								requests
								threats
							}
							uniq {
								uniques
							}
						}
					}
				}
			}\"}"
		);
	}

	public function purge() {
		return $this->_wp_remote_request( 'DELETE',
			self::$_root_uri . '/zones/' . $this->_zone_id . '/purge_cache',
			'{"purge_everything":true}' );
	}

	/**
	 * Performs the CF API request
	 *
	 * @throws Exception
	 * @return array
	 */
	private function _wp_remote_request( $method, $url, $body = array() ) {
		if ( empty( $this->_email ) || empty( $this->_key ) ) {
			throw new \Exception('Not authenticated');
		}

		$headers = $this->_generate_wp_remote_request_headers();

		$result = wp_remote_request( $url, array(
				'method' => $method,
				'headers' => $headers,
				'timeout' => $this->_timelimit_api_request,
				'body' => $body
			) );

		if ( is_wp_error( $result ) ) {
			throw new \Exception( 'Failed to reach API endpoint' );
		}

		$response_json = @json_decode( $result['body'], true );
		if ( is_null( $response_json ) || !isset( $response_json['success'] ) ) {
			throw new \Exception(
				'Failed to reach API endpoint, got unexpected response ' .
				str_replace( '<', '.', str_replace( '>', '.', $result['body'] ) ) );
		}

		if ( !$response_json['success'] ) {
			$errors = array();

			if ( isset( $response_json['errors'] ) ) {
				foreach ( $response_json['errors'] as $e ) {
					if ( !empty( $e['message'] ) )
						$errors[] = $e['message'];
				}
			}

			if ( empty( $errors ) )
				$errors[] = 'Request failed';

			throw new \Exception( implode( ', ', $errors ) );
		}

		if ( isset( $response_json['result'] ) ) {
			return $response_json['result'];
		}

		return array();
	}

	/**
	 * Performs the CF API request with meta
	 *
	 * @throws Exception
	 * @return array
	 */
	private function _wp_remote_request_with_meta( $method, $url, $body = array() ) {
		if ( empty( $this->_email ) || empty( $this->_key ) ) {
			throw new \Exception('Not authenticated');
		}

		$headers = $this->_generate_wp_remote_request_headers();

		$result = wp_remote_request( $url, array(
				'method' => $method,
				'headers' => $headers,
				'timeout' => $this->_timelimit_api_request,
				'body' => $body
			) );

		if ( is_wp_error( $result ) )
			throw new \Exception( 'Failed to reach API endpoint' );

		$response_json = @json_decode( $result['body'], true );
		if ( is_null( $response_json ) || !isset( $response_json['success'] ) ) {
			throw new \Exception(
				'Failed to reach API endpoint, got unexpected response ' .
				$result['body'] );
		}

		if ( !$response_json['success'] ) {
			$errors = array();

			if ( isset( $response_json['errors'] ) ) {
				foreach ( $response_json['errors'] as $e ) {
				    if ( !empty( $e['message'] ) )
				         $errors[] = $e['message'];
				}
			}
			if ( empty( $errors ) )
				$errors[] = 'Request failed';

			throw new \Exception( implode( ', ', $errors ) );
		}

		if ( isset( $response_json['result'] ) ) {
			return $response_json;
		}

		return array();
	}

	/**
	 * Performs the CF GraphQL API request
	 *
	 * @throws Exception
	 * @return array
	 */
	private function _wp_remote_request_graphql( $method, $url, $body ) {
		if ( empty( $this->_email ) || empty( $this->_key ) ) {
			throw new \Exception('Not authenticated');
		}

		$headers = $this->_generate_wp_remote_request_headers();

		$body = preg_replace( '/\s\s+/', ' ', $body );

		$result = wp_remote_request( $url, array(
				'method' => $method,
				'headers' => $headers,
				'timeout' => $this->_timelimit_api_request,
				'body' => $body
			) );

		if ( is_wp_error( $result ) ) {
			throw new \Exception( 'Failed to reach API endpoint' );
		}

		$response_json = @json_decode( $result['body'], true );
		if ( is_null( $response_json ) ) {
			throw new \Exception(
				'Failed to reach API endpoint, got unexpected response ' .
				str_replace( '<', '.', str_replace( '>', '.', $result['body'] ) ) );
		}

		if ( isset( $response_json['errors'] ) ) {
			$errors = array();

			foreach ( $response_json['errors'] as $e ) {
				if ( !empty( $e['message'] ) )
					$errors[] = $e['message'];
			}

			if ( empty( $errors ) )
				$errors[] = 'Request failed';

			throw new \Exception( implode( ', ', $errors ) );
		}

		if ( isset( $response_json['data'] ) ) {
			return $response_json['data'];
		}

		return array();
	}

	/**
	 * Generates the appropriate request headers for CF API requests based on token or global key presence
	 *
	 * @since 2.2.1
	 *
	 * @throws Exception
	 * @return array
	 */
	private function _generate_wp_remote_request_headers() {
		if ( empty( $this->_email ) || empty( $this->_key ) ) {
			throw new \Exception('Missing authentication email and/or API token / global key');
		}

		$headers = array();

		// CF API Token
		if( strlen( $this->_key ) == 40 ) {
			$headers = array(
				'Content-Type' => 'application/json',
				'Authorization' => 'Bearer ' . $this->_key
			);
		}
		// CF Legacy API Global Key
		else if ( strlen( $this->_key ) == 37 ) {
			$headers = array(
				'Content-Type' => 'application/json',
				'X-Auth-Key' => $this->_key,
				'X-Auth-Email' => $this->_email
			);
		}
		else {
			throw new \Exception('Improper API token / global key length');
		}

		return $headers;
	}
}