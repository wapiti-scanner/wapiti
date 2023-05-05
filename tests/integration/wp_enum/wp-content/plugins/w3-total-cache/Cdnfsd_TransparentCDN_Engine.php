<?php
/**
 * File: Cdnfsd_TransparentCDN_Engine.php
 *
 * @since 0.15.0
 */

namespace W3TC;

if ( ! defined( 'W3TC_CDN_TRANSPARENTCDN_PURGE_URL' ) ) {
	define( 'W3TC_CDN_TRANSPARENTCDN_PURGE_URL', 'https://api.transparentcdn.com/v1/companies/%s/invalidate/' );
}

if ( ! defined( 'W3TC_CDN_TRANSPARENTCDN_AUTHORIZATION_URL' ) ) {
	define( 'W3TC_CDN_TRANSPARENTCDN_AUTHORIZATION_URL', 'https://api.transparentcdn.com/v1/oauth2/access_token/' );
}


/**
 * Class: Cdn_TransparentCDN_Api
 *
 * @since 0.15.0
 */
class Cdn_TransparentCDN_Api {
	/**
	 * Token.
	 *
	 * @since 0.15.0
	 *
	 * @var string
	 */
	var $_token;

	/**
	 * Config.
	 *
	 * @since 0.15.0
	 *
	 * @var array
	 */
	var $_config;

	/**
	 * Constructor.
	 *
	 * @since 0.15.0
	 *
	 * @param array $config
	 */
	public function __construct( $config = array() ) {
		$config = array_merge( array(
			'company_id'    => '',
			'client_id'     => '',
			'client_secret' => ''
		), $config );

		$this->_config = $config;
	}

	/**
	 * Purge URL addresses.
	 *
	 * @since 0.15.0
	 *
	 * @param  array $urls URL addresses
	 * @return bool
	 */
	public function purge( $urls ) {
		if ( empty( $this->_config['company_id'] ) ) {
			return false;
		}

		if ( empty( $this->_config['client_id'] ) ) {
			return false;
		}
		if ( empty( $this->_config['client_secret'] ) ) {
			return false;
		}

		// We ask for the authorization token.
		$this->_get_token();

		$invalidation_urls = array();
		//Included a regex filter because some of our clients reported receiving urls as "True" or "False"
		foreach ( $urls as $url ) {
			//Oh array_map+lambdas, how I miss u...
			if ( filter_var( $url, FILTER_VALIDATE_URL ) ) {
				$invalidation_urls[] = $url;
			}
		}

		if ( count( $invalidation_urls ) === 0 ) {
			$invalidation_urls[] = '';
		}

		return $this->_purge_content( $invalidation_urls, $error );
	}

   /**
	 * Purge content.
	 *
	 * @since 0.15.0
	 *
	 * @param  string $files Files.
	 * @param  string $error Error.
	 * @return bool
	 */
	public function _purge_content( $files, &$error ) {
		$url  = sprintf( W3TC_CDN_TRANSPARENTCDN_PURGE_URL, $this->_config['company_id'] );
		$args = array(
			'method'     => 'POST',
			'user-agent' => W3TC_POWERED_BY,
			'headers'    => array(
				'Accept'        => 'application/json',
				'Content-Type'  => 'application/json',
				'Authorization' => sprintf( 'Bearer %s', $this->_token ),
			),
			'body' => json_encode( array( 'urls' => $files ) ),
		);

		$response = wp_remote_request( $url, $args );

		if ( is_wp_error( $response ) ) {
			$error = implode( '; ', $response->get_error_messages() );
			return false;
		}

		switch ( $response['response']['code'] ) {
			case 200:
				$body = json_decode( $response['body'] );
				if ( is_array( $body->urls_to_send ) && count( $body->urls_to_send ) > 0 ) {
					// We have invalidated at least one URL.
					return true;
				}
				elseif ( 0 < count( $files ) && ! empty( $files[0] ) ) {
					$error = __( 'Invalid Request URL', 'w3-total-cache' );
					break;
				}

				return true;

			case 400:
				if ( count( $files ) > 0 && empty( $files[0] ) ) {
					// Test case.
					return true;
				}

				$error = __( 'Invalid Request Parameter', 'w3-total-cache' );
				break;

			case 403:
				$error = __( 'Authentication Failure or Insufficient Access Rights', 'w3-total-cache' );
				break;

			case 404:
				$error = __( 'Invalid Request URI', 'w3-total-cache' );
				break;

			case 500:
				$error = __( 'Server Error', 'w3-total-cache' );
				break;
			default:
				$error = __( 'Unknown error', 'w3-total-cache' );
				break;
		}

		return false;
	}


	/**
	 * Purges CDN completely.
	 *
	 * @since 0.15.0
	 *
	 * @todo Implement bans using "*".
	 *
	 * @param  array $results Results.
	 * @return bool
	 */
	public function purge_all( &$results ) {
		return false;
	}

	/**
	 * Get the token to use as authorization in override requests.
	 *
	 * @since 0.15.0
	 *
	 * @todo Better bug handline.
	 *
	 * @return bool
	 */
	public function _get_token() {
		$client_id     = $this->_config['client_id'];
		$client_secret = $this->_config['client_secret'];
		$args          = array(
			'method'     => 'POST',
			'user-agent' => W3TC_POWERED_BY,
			'headers'    => array(
				'Accept'       => 'application/json',
				'Content-Type' => 'application/x-www-form-urlencoded',
			),
			'body'       => "grant_type=client_credentials&client_id=$client_id&client_secret=$client_secret",
		);

		$response = wp_remote_request( W3TC_CDN_TRANSPARENTCDN_AUTHORIZATION_URL, $args );

		if ( is_wp_error( $response ) ) {
			$error = implode( '; ', $response->get_error_messages() );
			return false;
		}

		$body         = $response['body'];
		$jobj         = json_decode( $body );
		$this->_token = $jobj->access_token;

		return true;
	}
}

/**
 * Class: Cdnfsd_TransparentCDN_Engine
 *
 * @since 0.15.0
 */
class Cdnfsd_TransparentCDN_Engine {
	/**
	 * Config.
	 *
	 * @since 0.15.0
	 * @access private
	 *
	 * @var array
	 */
	private $config;

	public function __construct( $config = array() ) {
		$this->config = $config;
	}


	/**
	 * Flush URLs.
	 *
	 * @since 0.15.0
	 *
	 * @param  array $urls URL addresses.
	 */
	function flush_urls( $urls ) {
		if ( empty( $this->config['client_id'] ) ) {
			throw new \Exception( __( 'API key not specified.', 'w3-total-cache' ) );
		}

		$api = new Cdn_TransparentCDN_Api( $this->config );

		try {
			$result = $api->purge( $urls );
			throw new \Exception( __( 'Problem purging', 'w3-total-cache' ) );

		} catch ( \Exception $ex ) {
			if ( $ex->getMessage() === 'Validation Failure: Purge url must contain one of your hostnames' ) {
				throw new \Exception( __(
					'CDN site is not configured correctly: Delivery Domain must match your site domain',
					'w3-total-cache'
				) );
			} else {
				throw $ex;
			}
		}
	}

	/**
	 * Flushes CDN completely.
	 *
	 * @since 0.15.0
	 */
	function flush_all() {
		if ( empty( $this->config['client_id'] ) ) {
			throw new \Exception( __( 'API key not specified.', 'w3-total-cache' ) );
		}

		$api = new Cdn_TransparentCDN_Api( $this->config );

		$items   = array();
		$items[] = array(
			'url'       => home_url( '/' ),
			'recursive' => true,
		);

		try {
			$r = $api->purge( array( 'items' => $items ) );
		} catch ( \Exception $ex ) {
			if ( $ex->getMessage() === 'Validation Failure: Purge url must contain one of your hostnames' ) {
				throw new \Exception( __(
					'CDN site is not configured correctly: Delivery Domain must match your site domain',
					'w3-total-cache'
				) );
			} else {
				throw $ex;
			}
		}
	}
}
