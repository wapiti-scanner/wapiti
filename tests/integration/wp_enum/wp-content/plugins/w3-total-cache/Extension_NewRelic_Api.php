<?php
namespace W3TC;

/**
 * Interacts with the New Relic Connect API
 *
 * @link newrelic.github.com/newrelic_api/
 */
class Extension_NewRelic_Api {
	private $_api_key;
	static private $url = 'https://api.newrelic.com';

	/**
	 *
	 *
	 * @param string  $api_key New Relic API Key
	 */
	function __construct( $api_key ) {
		$this->_api_key = $api_key;
	}

	/**
	 *
	 *
	 * @param string  $api_call_url url path with query string used to define what to get from the NR API
	 * @throws \Exception
	 * @return bool
	 */
	private function _get( $api_call_url, $query = array() ) {
		$defaults = array(
			'headers'=>'x-api-key:'.$this->_api_key,
			'body' => $query
		);
		$url = self::$url . $api_call_url;

		$response = wp_remote_get( $url, $defaults );

		if ( is_wp_error( $response ) ) {
			throw new \Exception( 'Could not get data' );
		} elseif ( $response['response']['code'] == 200 ) {
			$return = $response['body'];
		} else {
			switch ( $response['response']['code'] ) {
			case '403':
				$message = __( 'Invalid API key', 'w3-total-cache' );
				break;
			default:
				$message = $response['response']['message'];
			}

			throw new \Exception( $message, $response['response']['code'] );
		}
		return $return;
	}

	/**
	 *
	 *
	 * @param string  $api_call_url url path with query string used to define what to get from the NR API
	 * @param array   $params       key value array.
	 * @throws \Exception
	 * @return bool
	 */
	private function _put( $api_call_url, $params ) {
		$defaults = array(
			'method' => 'PUT',
			'headers'=>'x-api-key:'.$this->_api_key,
			'body' => $params
		);
		$url = self::$url . $api_call_url;
		$response = wp_remote_request( $url, $defaults );

		if ( is_wp_error( $response ) ) {
			throw new \Exception( 'Could not put data' );
		} elseif ( $response['response']['code'] == 200 ) {
			$return = true;
		} else {
			throw new \Exception( $response['response']['message'], $response['response']['code'] );
		}
		return $return;
	}



	function get_browser_applications() {
		$response  = $this->_get( '/v2/browser_applications.json' );
		$r = @json_decode( $response, true );
		if ( !$r )
			throw new \Exception( 'Received unexpected response' );

		if ( !isset( $r['browser_applications'] ) )
			return array();

		return $r['browser_applications'];
	}



	function get_browser_application( $id ) {
		$response  = $this->_get( '/v2/browser_applications.json', array(
				'filter[ids]' => $id ) );
		$r = @json_decode( $response, true );
		if ( !$r )
			throw new \Exception( 'Received unexpected response' );

		if ( !isset( $r['browser_applications'] ) ||
			count( $r['browser_applications'] ) != 1 )
			return null;

		return $r['browser_applications'][0];
	}
}
