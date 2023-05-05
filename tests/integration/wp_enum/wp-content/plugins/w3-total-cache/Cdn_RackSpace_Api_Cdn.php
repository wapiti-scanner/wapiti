<?php
namespace W3TC;



class Cdn_RackSpace_Api_Cdn {
	private $_access_token;
	private $_access_region_descriptor;
	private $_new_access_required = null;



	public function __construct( $config = array() ) {
		$this->_access_token = $config['access_token'];
		$this->_access_region_descriptor = $config['access_region_descriptor'];
		$this->_new_access_required = $config['new_access_required'];
	}



	public function services() {
		$r = $this->_wp_remote_get( '/services' );
		if ( !isset( $r['services'] ) )
			return array();

		return $r['services'];
	}



	public function service_get( $service ) {
		$response = $this->_wp_remote_get( '/services/' . $service );

		// expand links to links_by_rel
		if ( isset( $response['links'] ) ) {
			$by_rel = array();
			foreach ( $response['links'] as $r ) {
				$by_rel[ $r['rel'] ] = $r;
			}
			$response['links_by_rel'] = $by_rel;
		}

		return $response;
	}



	public function service_create( $data ) {
		// required static
		$data['flavor_id'] = 'cdn';

		return $this->_wp_remote_post( '/services', json_encode( $data ),
			array(
				'Accept' => 'application/json',
				'Content-type' => 'application/json'
			) );
	}



	public function service_set( $service_id, $data ) {
		return $this->_wp_remote_patch( '/services/' . $service_id,
			json_encode( $data ),
			array(
				'Accept' => 'application/json',
				'Content-type' => 'application/json'
			) );
	}



	public function purge( $service_id, $url ) {
		return $this->_wp_remote_delete( '/services/' . $service_id . '/assets?url=' .
			urlencode( $url ) );
	}



	private function _wp_remote_get( $uri ) {
		if ( !empty( $this->_access_region_descriptor['cdn.publicURL'] ) ) {
			$url_base = $this->_access_region_descriptor['cdn.publicURL'];

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



	private function _wp_remote_patch( $uri, $body = array(), $headers = array() ) {
		if ( !empty( $this->_access_region_descriptor['cdn.publicURL'] ) ) {
			$url_base = $this->_access_region_descriptor['cdn.publicURL'];
			$headers['X-Auth-Token'] = $this->_access_token;

			$result = wp_remote_post( $url_base . $uri, array(
					'headers' => $headers,
					'body' => $body,
					//'sslcertificates' => dirname( __FILE__ ) . '/Cdn_RackSpace_Api_CaCert.pem',
					'method' => 'PATCH'
				) );

			$r = self::_decode_response( $result );
			if ( !$r['auth_required'] ) {
				$location = explode( '/', $result['headers']['location'] );

				return $location[ count( $location ) - 1 ];
			}
		}

		$new_object = call_user_func( $this->_new_access_required );
		return $new_object->_wp_remote_patch( $uri, $body );
	}



	private function _wp_remote_post( $uri, $body = array(), $headers = array() ) {
		if ( !empty( $this->_access_region_descriptor['cdn.publicURL'] ) ) {
			$url_base = $this->_access_region_descriptor['cdn.publicURL'];
			$headers['X-Auth-Token'] = $this->_access_token;

			$result = wp_remote_post( $url_base . $uri, array(
					'headers' => $headers,
					'body' => $body
					//'sslcertificates' => dirname( __FILE__ ) . '/Cdn_RackSpace_Api_CaCert.pem'
				) );

			$r = self::_decode_response( $result );
			if ( !$r['auth_required'] ) {
				$location = explode( '/', $result['headers']['location'] );

				return $location[ count( $location ) - 1 ];
			}
		}

		$new_object = call_user_func( $this->_new_access_required );
		return $new_object->_wp_remote_post( $uri, $body );
	}



	private function _wp_remote_delete( $uri, $headers = array() ) {
		if ( !empty( $this->_access_region_descriptor['cdn.publicURL'] ) ) {
			$url_base = $this->_access_region_descriptor['cdn.publicURL'];
			$headers['X-Auth-Token'] = $this->_access_token;

			$result = wp_remote_post( $url_base . $uri, array(
					'headers' => $headers,
					//'sslcertificates' => dirname( __FILE__ ) . '/Cdn_RackSpace_Api_CaCert.pem',
					'method' => 'DELETE'
				) );

			$r = self::_decode_response( $result );
			if ( !$r['auth_required'] )
				return;
		}

		$new_object = call_user_func( $this->_new_access_required );
		return $new_object->_wp_remote_delete( $uri, array() );
	}



	static private function _decode_response_json( $result ) {
		if ( is_wp_error( $result ) )
			throw new \Exception( 'Failed to reach API endpoint' );

		if ( empty( $result['body'] ) )
			$response_json = array();
		else {
			if ( $result['body'] == 'Unauthorized' )
				return array( 
					'response_json' => array(), 
					'auth_required' => true 
				);

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

		return array( 
			'response_json' => $response_json, 
			'auth_required' => false 
		);
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
					'response_json' => array(), 
					'auth_required' => true 
				);

			// try to decode response
			$response_json = @json_decode( $result['body'], true );
			if ( is_null( $response_json ) ||
				!isset( $response_json['message'] ) )
				throw new \Exception(
					'Failed to reach API endpoint, got unexpected response ' .
					$result['response']['message'] );
			else {
				$errors = array();
				if ( is_string( $response_json['message'] ) ) {
					$errors[] = $response_json['message'];
				} elseif ( isset( $response_json['message']['errors'] ) ) {
					foreach ( $response_json['message']['errors'] as $error )
						$errors[] = $error['message'];
				}

				throw new \Exception( implode( ';', $errors ) );
			}
		}

		return array( 'auth_required' => false );
	}
}
