<?php
namespace W3TC;

define( 'W3TC_CDN_MIRROR_AKAMAI_WSDL', 'https://ccuapi.akamai.com/ccuapi-axis.wsdl' );
define( 'W3TC_CDN_MIRROR_AKAMAI_NAMESPACE', 'http://www.akamai.com/purge' );

class CdnEngine_Mirror_Akamai extends CdnEngine_Mirror {
	/**
	 * PHP5 Constructor
	 *
	 * @param array   $config
	 */
	function __construct( $config = array() ) {
		$config = array_merge( array(
				'username' => '',
				'password' => '',
				'zone' => '',
				'action' => 'invalidate',
				'email_notification' => array()
			), $config );

		parent::__construct( $config );
	}

	/**
	 * Purges remote files
	 *
	 * @param array   $files
	 * @param array   $results
	 * @return boolean
	 */
	function purge( $files, &$results ) {
		if ( empty( $this->_config['username'] ) ) {
			$results = $this->_get_results( $files, W3TC_CDN_RESULT_HALT, __( 'Empty username.', 'w3-total-cache' ) );

			return false;
		}

		if ( empty( $this->_config['password'] ) ) {
			$results = $this->_get_results( $files, W3TC_CDN_RESULT_HALT, __( 'Empty password.', 'w3-total-cache' ) );

			return false;
		}

		require_once W3TC_LIB_DIR . '/Nusoap/nusoap.php';

		$client = new \nusoap_client(
			W3TC_CDN_MIRROR_AKAMAI_WSDL,
			'wsdl'
		);

		$error = $client->getError();

		if ( $error ) {
			$results = $this->_get_results( $files, W3TC_CDN_RESULT_HALT, sprintf( __( 'Constructor error (%s).', 'w3-total-cache' ), $error ) );

			return false;
		}

		$zone = $this->_config['zone'];

		$expressions = array();
		foreach ( $files as $file ) {
			$remote_path = $file['remote_path'];
			$expressions[] = $this->_format_url( $remote_path );
		}

		$action = $this->_config['action'];
		$email = $this->_config['email_notification'];

		$email = implode( ',', $email );
		$options = array( 'action='.$action, 'domain='.$zone, 'type=arl' );
		if ( $email )
			$options[] = 'email-notification='.$email;
		$params = array( $this->_config['username'],
			$this->_config['password'],
			'',
			$options,
			$expressions
		);

		$result = $client->call( 'purgeRequest', $params, W3TC_CDN_MIRROR_AKAMAI_NAMESPACE );

		if ( $client->fault ) {
			$results = $this->_get_results( $files, W3TC_CDN_RESULT_HALT, __( 'Invalid response.', 'w3-total-cache' ) );

			return false;
		}
		$result_code = $result['resultCode'];
		$result_message = $result['resultMsg'];

		$error = $client->getError();

		if ( $error ) {
			$results = $this->_get_results( $files, W3TC_CDN_RESULT_HALT, sprintf( __( 'Unable to purge (%s).', 'w3-total-cache' ), $error ) );

			return false;
		}
		if ( $result_code>=300 ) {
			$results = $this->_get_results( $files, W3TC_CDN_RESULT_HALT, sprintf( __( 'Unable to purge (%s).', 'w3-total-cache' ), $result_message ) );

			return false;
		}

		$results = $this->_get_results( $files, W3TC_CDN_RESULT_OK, __( 'OK', 'w3-total-cache' ) );

		return true;
	}
}
