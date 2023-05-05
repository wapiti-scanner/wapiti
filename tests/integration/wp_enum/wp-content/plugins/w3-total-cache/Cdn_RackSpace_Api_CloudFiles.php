<?php
namespace W3TC;



class Cdn_RackSpace_Api_CloudFiles {
	private $_access_token;
	private $_access_region_descriptor;
	private $_new_access_required;



	public function __construct( $config = array() ) {
		$this->_access_token = $config['access_token'];
		$this->_access_region_descriptor = $config['access_region_descriptor'];

		$this->_new_access_required = $config['new_access_required'];
	}



	public function container_create( $container ) {
		return $this->_wp_remote_put( '/' . $container );
	}



	/**
	 * data is:
	 *   name
	 *   content_type
	 *   content
	 */
	public function object_create( $data ) {
		$headers = array(
			'ETag' => md5( $data['content'] )
		);
		if ( isset( $data['content_type'] ) )
			$headers['Content-Type'] = $data['content_type'];

		return $this->_wp_remote_put( '/' . $data['container'] . '/' .
			ltrim( $data['name'], '/' ),
			$data['content'],
			$headers );
	}



	public function object_get_meta_or_null( $container, $name ) {
		return $this->_wp_remote_head( '/' . $container . '/' .
			ltrim( $name, '/' ) );
	}



	public function object_delete( $container, $name ) {
		return $this->_wp_remote_delete( '/' . $container . '/' .
			ltrim( $name, '/' ) );
	}



	private function _wp_remote_put( $uri, $body = array(), $headers = array() ) {
		if ( !empty( $this->_access_region_descriptor['object-store.publicURL'] ) ) {
			$url_base = $this->_access_region_descriptor['object-store.publicURL'];
			$headers['X-Auth-Token'] = $this->_access_token;
			$headers['Accept'] = 'application/json';

			$result = wp_remote_post( $url_base . $uri . '?format=json', array(
					'headers' => $headers,
					'body' => $body,
					//'sslcertificates' => dirname( __FILE__ ) .
					//'/Cdn_RackSpace_Api_CaCert.pem',
					'timeout' => 120,
					'method' => 'PUT'
				) );

			$r = self::_decode_response( $result );
			if ( !$r['auth_required'] )
				return;
		}

		$new_object = call_user_func( $this->_new_access_required );
		return $new_object->_wp_remote_put( $uri, $body, $headers );
	}



	private function _wp_remote_head( $uri ) {
		if ( !empty( $this->_access_region_descriptor['object-store.publicURL'] ) ) {
			$url_base = $this->_access_region_descriptor['object-store.publicURL'];

			$result = wp_remote_get( $url_base . $uri . '?format=json', array(
					'headers' => array( 'X-Auth-Token' => $this->_access_token ),
					//'sslcertificates' => dirname( __FILE__ ) .
					//'/Cdn_RackSpace_Api_CaCert.pem',
					'method' => 'HEAD'
				) );

			if ( $result['response']['code'] == '404' )
				return null;

			$r = self::_decode_response( $result );
			if ( !$r['auth_required'] )
				return $result['headers'];
		}

		$new_object = call_user_func( $this->_new_access_required );
		return $new_object->_wp_remote_head( $uri );
	}



	private function _wp_remote_delete( $uri ) {
		if ( !empty( $this->_access_region_descriptor['object-store.publicURL'] ) ) {
			$url_base = $this->_access_region_descriptor['object-store.publicURL'];

			$result = wp_remote_post( $url_base . $uri . '?format=json', array(
					'headers' => array( 'X-Auth-Token' => $this->_access_token ),
					//'sslcertificates' => dirname( __FILE__ ) .
					//'/Cdn_RackSpace_Api_CaCert.pem',
					'method' => 'DELETE'
				) );

			$r = self::_decode_response( $result );
			if ( !$r['auth_required'] )
				return;
		}

		$new_object = call_user_func( $this->_new_access_required );
		return $new_object->_wp_remote_delete( $uri );
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
