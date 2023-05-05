<?php
namespace W3TC;



class Cdnfsd_LimeLight_Api {
	private $url_base;



	public function __construct( $short_name, $username, $api_key ) {
		$this->url_base = 'https://purge.llnw.com/purge/v1/account/' .
			$short_name . '/requests';
		$this->username = $username;
		$this->api_key = $api_key;
	}



	public function purge( $items ) {
		$body = json_encode( array( 'patterns' => $items ) );
		return $this->_wp_remote_post( '', $body );
	}



	public function get( $uri ) {
		return $this->_wp_remote_get( $uri );
	}



	private function _wp_remote_get( $uri, $body = '', $headers = array() ) {
		$url = $this->url_base . $uri;
		$headers = $this->_add_headers( $headers, $url, 'GET', $body );

		$result = wp_remote_get( $url, array(
				'headers' => $headers,
				'body' => $body
			) );

		return $this->_decode_response( $result );
	}



	private function _wp_remote_post( $uri, $body, $headers = array() ) {
		$url = $this->url_base . $uri;
		$headers = $this->_add_headers( $headers, $url, 'POST', $body );

		$result = wp_remote_post( $url, array(
				'headers' => $headers,
				'body' => $body
			) );

		return $this->_decode_response( $result );
	}



	private function _add_headers( $headers, $url, $method, $body ) {
		$timestamp = '' . ( time() * 1000 );

		$headers['Content-Type'] = 'application/json';
		$headers['X-LLNW-Security-Principal'] = $this->username;
		$headers['X-LLNW-Security-Timestamp'] = $timestamp;
		$headers['X-LLNW-Security-Token'] = hash_hmac( 'sha256',
			$method . $url . $timestamp . $body, pack( 'H*', $this->api_key ) );

		return $headers;
	}



	private function _decode_response( $result ) {
		if ( is_wp_error( $result ) )
			throw new \Exception( 'Failed to reach API endpoint' );

		$response_json = @json_decode( $result['body'], true );
		if ( is_null( $response_json ) ) {
			throw new \Exception(
				'Failed to reach API endpoint, got unexpected response ' .
				$result['body'] );
		}

		if ( $result['response']['code'] != '200' &&
			$result['response']['code'] != '201' &&
			$result['response']['code'] != '202' &&
			$result['response']['code'] != '204' ) {
			if ( isset( $response_json['errors'] ) &&
				isset( $response_json['errors'][0]['description'] ) ) {
				throw new \Exception( $response_json['errors'][0]['description'] );
			}

			throw new \Exception( $result['body'] );
		}


		return $response_json;
	}
}
