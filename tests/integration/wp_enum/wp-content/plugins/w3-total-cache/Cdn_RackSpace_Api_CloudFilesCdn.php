<?php
namespace W3TC;



class Cdn_RackSpace_Api_CloudFilesCdn {
	private $_access_token;
	private $_access_region_descriptor;
	private $_new_access_required = null;



	public function __construct( $config = array() ) {
		$this->_access_token = $config['access_token'];
		$this->_access_region_descriptor = $config['access_region_descriptor'];
		$this->_new_access_required = $config['new_access_required'];
	}



	public function containers() {
		return $this->_wp_remote_get( '' );
	}



	public function container_get( $container ) {
		return $this->_wp_remote_head( '/' . $container );
	}



	public function container_cdn_enable( $container ) {
		return $this->_wp_remote_put( '/' . $container,
			array( 'X-Cdn-Enabled' => 'True' ) );
	}



	private function _wp_remote_get( $uri ) {
		if ( !empty( $this->_access_region_descriptor['object-cdn.publicURL'] ) ) {
			$url_base = $this->_access_region_descriptor['object-cdn.publicURL'];

			$result = wp_remote_get( $url_base . $uri . '?format=json', array(
					'headers' => 'X-Auth-Token: ' . $this->_access_token
					//'sslcertificates' => dirname( __FILE__ ) . '/Cdn_RackSpace_Api_CaCert.pem'
				) );

			$r = self::_decode_response_json( $result );
			if ( !$r['auth_required'] )
				return $r['response_json'];
		}

		$new_object = call_user_func( $this->_new_access_required );
		return $new_object->_wp_remote_get( $uri );
	}



	private function _wp_remote_head( $uri, $method = 'GET' ) {
		if ( !empty( $this->_access_region_descriptor['object-cdn.publicURL'] ) ) {
			$url_base = $this->_access_region_descriptor['object-cdn.publicURL'];

			$result = wp_remote_get( $url_base . $uri . '?format=json', array(
					'headers' => 'X-Auth-Token: ' . $this->_access_token,
					//'sslcertificates' => dirname( __FILE__ ) . '/Cdn_RackSpace_Api_CaCert.pem',
					'method' => 'HEAD'
				) );

			$r = self::_decode_response( $result );
			if ( !$r['auth_required'] )
				return $result['headers'];
		}

		$new_object = call_user_func( $this->_new_access_required );
		return $new_object->_wp_remote_head( $uri, $body );
	}



	private function _wp_remote_put( $uri, $body = array(), $headers = array() ) {
		if ( !empty( $this->_access_region_descriptor['object-cdn.publicURL'] ) ) {
			$url_base = $this->_access_region_descriptor['object-cdn.publicURL'];
			$headers['X-Auth-Token'] = $this->_access_token;

			$result = wp_remote_post( $url_base . $uri, array(
					'headers' => $headers,
					'body' => $body,
					//'sslcertificates' => dirname( __FILE__ ) . '/Cdn_RackSpace_Api_CaCert.pem',
					'method' => 'PUT'
				) );

			$r = self::_decode_response( $result );
			if ( !$r['auth_required'] )
				return;
		}

		$new_object = call_user_func( $this->_new_access_required );
		return $new_object->_wp_remote_put( $uri, $body, $headers );
	}



	static private function _decode_response_json( $result ) {
		if ( is_wp_error( $result ) )
			throw new \Exception( 'Failed to reach API endpoint' );

		if ( empty( $result['body'] ) )
			$response_json = array();
		else {
			$response_json = @json_decode( $result['body'], true );
			if ( is_null( $response_json ) )
				throw new \Exception(
					'Failed to reach API endpoint, got unexpected response ' .
					$result['body'] );
		}

		if ( $result['response']['code'] != '200' &&
			$result['response']['code'] != '201' &&
			$result['response']['code'] != '202' &&
			$result['response']['code'] != '204' )
			throw new \Exception( $result['body'] );

		return array( 'response_json' => $response_json, 'auth_required' => false );
	}



	static private function _decode_response( $result ) {
		if ( is_wp_error( $result ) )
			throw new \Exception( 'Failed to reach API endpoint' );

		if ( $result['response']['code'] != '200' &&
			$result['response']['code'] != '201' &&
			$result['response']['code'] != '202' &&
			$result['response']['code'] != '204' ) {

			if ( $result['response']['message'] == 'Unauthorized' )
				return array( 
					'auth_required' => true 
				);

			throw new \Exception(
				'Failed to reach API endpoint, got unexpected response ' .
				$result['response']['message'] );
		}

		return array( 'auth_required' => false );
	}
}
