<?php
namespace W3TC;

class Util_Http {
	/**
	 * Filter handler for use_curl_transport.
	 * Workaround to not use curl for extra http methods
	 *
	 * @param unknown $result boolean
	 * @param unknown $args   array
	 * @return boolean
	 */
	static public function use_curl_transport( $result, $args ) {
		if ( isset( $args['method'] ) && $args['method'] != 'GET' && $args['method'] != 'POST' )
			return false;

		return $result;
	}

	/**
	 * Sends HTTP request
	 *
	 * @param unknown $url  string
	 * @param unknown $args array
	 * @return WP_Error|array
	 */
	static public function request( $url, $args = array() ) {
		static $filter_set = false;
		if ( !$filter_set ) {
			add_filter( 'use_curl_transport',
				array( '\W3TC\Util_Http', 'use_curl_transport' ), 10, 2 );
			$filter_set = true;
		}

		$args = array_merge( array(
				'user-agent' => W3TC_POWERED_BY
			), $args );

		return wp_remote_request( $url, $args );
	}

	/**
	 * Sends HTTP GET request
	 *
	 * @param string  $url
	 * @param array   $args
	 * @return array|WP_Error
	 */
	static public function get( $url, $args = array() ) {
		$args = array_merge( $args, array(
				'method' => 'GET'
			) );

		return self::request( $url, $args );
	}

	/**
	 * Downloads URL into a file
	 *
	 * @param string  $url
	 * @param string  $file
	 * @return boolean
	 */
	static public function download( $url, $file, $args = array() ) {
		if ( strpos( $url, '//' ) === 0 ) {
			$url = ( Util_Environment::is_https() ? 'https:' : 'http:' ) . $url;
		}

		$response = self::get( $url, $args );

		if ( !is_wp_error( $response ) && $response['response']['code'] == 200 ) {
			return @file_put_contents( $file, $response['body'] );
		}

		return false;
	}

	/**
	 * Returns upload info
	 *
	 * @return array
	 */
	static public function upload_info() {
		static $upload_info = null;

		if ( $upload_info === null ) {
			$upload_info = Util_Environment::wp_upload_dir();

			if ( empty( $upload_info['error'] ) ) {
				$parse_url = @parse_url( $upload_info['baseurl'] );

				if ( $parse_url ) {
					$baseurlpath = ( !empty( $parse_url['path'] ) ? trim( $parse_url['path'], '/' ) : '' );
				} else {
					$baseurlpath = 'wp-content/uploads';
				}

				$upload_info['baseurlpath'] = '/' . $baseurlpath . '/';
			} else {
				$upload_info = false;
			}
		}

		return $upload_info;
	}

	/**
	 * Test the time to first byte.
	 *
	 * @param string $url URL address.
	 * @param bool   $nocache Whether or not to request no cache response, by sending a Cache-Control header.
	 * @return float|false Time in seconds until the first byte is about to be transferred or false on error.
	 */
	public static function ttfb( $url, $nocache = false ) {
		$ch   = curl_init( esc_url( $url ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		$pass = (bool) $ch;
		$ttfb = false;
		$opts = array(
			CURLOPT_FORBID_REUSE   => 1,
			CURLOPT_FRESH_CONNECT  => 1,
			CURLOPT_HEADER         => 0,
			CURLOPT_RETURNTRANSFER => 1,
			CURLOPT_FOLLOWLOCATION => 1,
			CURLOPT_SSL_VERIFYPEER => false,
			CURLOPT_USERAGENT      => 'WordPress/' . get_bloginfo( 'version' ) . '; ' . get_bloginfo( 'url' ),
		);

		if ( $nocache ) {
			$opts[ CURLOPT_HTTPHEADER ] = array(
				'Cache-Control: no-cache',
				'Pragma: no-cache',
			);

			$qs_arr = explode( '&', wp_parse_url( $url, PHP_URL_QUERY ) );
			array_push( $qs_arr, 'time=' . microtime( true ) );

			$opts[ CURLOPT_URL ] = $url . '?' . implode( '&', $qs_arr );
		}

		if ( $ch ) {
			$pass = curl_setopt_array( $ch, $opts ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}

		if ( $pass ) {
			$pass = (bool) curl_exec( $ch ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}

		if ( $pass ) {
			$ttfb = curl_getinfo( $ch, CURLINFO_STARTTRANSFER_TIME ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}

		if ( $ch ) {
			curl_close( $ch ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}

		return $ttfb;
	}

	/**
	 * Retrieve HTTP headers.
	 *
	 * @param  string $url URL address.
	 * @return array
	 */
	public static function get_headers( $url ) {
		$ch      = curl_init( $url ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$pass    = (bool) $ch;
		$headers = array();
		$opts    = array(
			CURLOPT_FORBID_REUSE   => 1,
			CURLOPT_FRESH_CONNECT  => 1,
			CURLOPT_HEADER         => 1,
			CURLOPT_RETURNTRANSFER => 1,
			CURLOPT_FOLLOWLOCATION => 1,
			CURLOPT_SSL_VERIFYPEER => false,
			CURLOPT_USERAGENT      => 'WordPress/' . get_bloginfo( 'version' ) . '; ' . get_bloginfo( 'url' ),
			CURLOPT_HTTPHEADER     => array(
				'Cache-Control: no-cache',
				'Pragma: no-cache',
			),
		);

		if ( $pass ) {
			$pass = curl_setopt_array( $ch, $opts ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}

		if ( $pass ) {
			$response = curl_exec( $ch ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}

		if ( $response ) {
			$header_size = curl_getinfo( $ch, CURLINFO_HEADER_SIZE ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			$header      = substr( $response, 0, $header_size );

			foreach ( explode( "\r\n", $header ) as $index => $line ) {
				if ( 0 === $index ) {
					$headers['http_code'] = $line;
					$http_code_arr        = explode( ' ', $line );
					$headers['protocol']  = $http_code_arr[0];
					$headers['status']    = $http_code_arr[1];
				} elseif ( ! empty( $line ) && false !== strpos( $line, ':' ) ) {
					list ( $key, $value ) = explode( ': ', $line );
					$headers[ $key ]      = $value;
				}
			}
		}

		if ( $ch ) {
			curl_close( $ch ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}

		return $headers;
	}

	/**
	 * Generate unique md5 value based on domain.
	 *
	 * @return string
	 */
	public static function generate_site_id() {
		return md5( network_home_url() );
	}
}
