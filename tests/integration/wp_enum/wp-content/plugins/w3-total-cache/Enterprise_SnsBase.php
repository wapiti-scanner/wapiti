<?php
namespace W3TC;

if ( !defined( 'W3TC_SKIPLIB_AWS' ) ) {
	require_once W3TC_DIR . '/vendor/autoload.php';
}



/**
 * Base class for Sns communication
 */
class Enterprise_SnsBase {
	/**
	 * PHP5-style constructor
	 */
	function __construct() {
		$this->_config = Dispatcher::config();

		$this->_region = $this->_config->get_string( 'cluster.messagebus.sns.region' );
		$this->_topic_arn = $this->_config->get_string( 'cluster.messagebus.sns.topic_arn' );
		$this->_api_key = $this->_config->get_string( 'cluster.messagebus.sns.api_key' );
		$this->_api_secret = $this->_config->get_string( 'cluster.messagebus.sns.api_secret' );

		$this->_debug = $this->_config->get_boolean( 'cluster.messagebus.debug' );
		$this->_api = null;
	}

	/**
	 * Returns API object
	 *
	 * @throws Exception
	 * @return AmazonSNS
	 */
	protected function _get_api() {
		if ( is_null( $this->_api ) ) {
			if ( empty( $this->_api_key ) && empty( $this->_api_secret ) ) {
				$credentials = \Aws\Credentials\CredentialProvider::defaultProvider();
			} else {
				if ( empty( $this->_api_key ) ) {
					throw new \Exception( 'API Key is not configured' );
				}

				if ( empty( $this->_api_secret ) ) {
					throw new \Exception( 'API Secret is not configured' );
				}

				$credentials = new \Aws\Credentials\Credentials(
					$this->_api_key, $this->_api_secret );
			}

			$this->_api = new \Aws\Sns\SnsClient( array(
				'credentials' => $credentials,
				'region' => $this->_region,
				'version' => '2010-03-31'
			) );
		}

		return $this->_api;
	}

	/**
	 * Write log entry
	 *
	 * @param string  $message
	 * @param array   $backtrace
	 * @return bool|int
	 */
	protected function _log( $message, $backtrace = null ) {
		if ( !$this->_debug )
			return true;

		$data = sprintf( "[%s] %s\n", date( 'r' ), $message );
		if ( $backtrace ) {
			$debug = print_r( $backtrace, true );
			$data .= $debug . "\n";
		}
		$data = strtr( $data, '<>', '..' );

		$filename = Util_Debug::log_filename( 'sns' );

		return @file_put_contents( $filename, $data, FILE_APPEND );
	}
}
