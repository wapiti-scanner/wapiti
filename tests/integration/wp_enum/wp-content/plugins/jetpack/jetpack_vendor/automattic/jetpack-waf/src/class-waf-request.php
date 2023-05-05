<?php
/**
 * HTTP request representation specific for the WAF.
 *
 * @package automattic/jetpack-waf
 */

namespace Automattic\Jetpack\Waf;

require_once __DIR__ . '/functions.php';

/**
 * Request representation.
 *
 * @template RequestFile as array{ name: string, filename: string }
 */
class Waf_Request {
	/**
	 * The request URL, broken into three pieces: the host, the filename, and the query string
	 *
	 * @example for `https://wordpress.com/index.php?myvar=red`
	 *          $this->url = [ 'https://wordpress.com', '/index.php', '?myvar=red' ]
	 * @var array{ 0: string, 1: string, 2: string }|null
	 */
	protected $url = null;

	/**
	 * Trusted proxies.
	 *
	 * @var array List of trusted proxy IP addresses.
	 */
	private $trusted_proxies = array();

	/**
	 * Trusted headers.
	 *
	 * @var array List of headers to trust from the trusted proxies.
	 */
	private $trusted_headers = array();

	/**
	 * Sets the list of IP addresses for the proxies to trust. Trusted headers will only be accepted as the
	 * user IP address from these IP adresses.
	 *
	 * Popular choices include:
	 * - 192.168.0.1
	 * - 10.0.0.1
	 *
	 * @param array $proxies List of proxy IP addresses.
	 * @return void
	 */
	public function set_trusted_proxies( $proxies ) {
		$this->trusted_proxies = (array) $proxies;
	}

	/**
	 * Sets the list of headers to be trusted from the proxies. These headers will only be taken into account
	 * if the request comes from a trusted proxy as configured with set_trusted_proxies().
	 *
	 * Popular choices include:
	 * - HTTP_CLIENT_IP
	 * - HTTP_X_FORWARDED_FOR
	 * - HTTP_X_FORWARDED
	 * - HTTP_X_CLUSTER_CLIENT_IP
	 * - HTTP_FORWARDED_FOR
	 * - HTTP_FORWARDED
	 *
	 * @param array $headers List of HTTP header strings.
	 * @return void
	 */
	public function set_trusted_headers( $headers ) {
		$this->trusted_headers = (array) $headers;
	}

	/**
	 * Determines the users real IP address based on the settings passed to set_trusted_proxies() and
	 * set_trusted_headers() before. On CLI, this will be null.
	 *
	 * @return string|null
	 */
	public function get_real_user_ip_address() {
		$remote_addr = ! empty( $_SERVER['REMOTE_ADDR'] ) ? wp_unslash( $_SERVER['REMOTE_ADDR'] ) : null; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		if ( in_array( $remote_addr, $this->trusted_proxies, true ) ) {
			$ip_by_header = $this->get_ip_by_header( array_merge( $this->trusted_headers, array( 'REMOTE_ADDR' ) ) );
			if ( ! empty( $ip_by_header ) ) {
				return $ip_by_header;
			}
		}

		return $remote_addr;
	}

	/**
	 * Iterates through a given list of HTTP headers and attempts to get the IP address from the header that
	 * a proxy sends along. Make sure you trust the IP address before calling this method.
	 *
	 * @param array $headers The list of headers to check.
	 * @return string|null
	 */
	private function get_ip_by_header( $headers ) {
		foreach ( $headers as $key ) {
			if ( isset( $_SERVER[ $key ] ) ) {
				foreach ( explode( ',', wp_unslash( $_SERVER[ $key ] ) ) as $ip ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- filter_var is applied below.
					$ip = trim( $ip );

					if ( filter_var( $ip, FILTER_VALIDATE_IP ) !== false ) {
						return $ip;
					}
				}
			}
		}

		return null;
	}

	/**
	 * Returns the headers that were sent with this request
	 *
	 * @return array{ 0: string, 1: scalar }[]
	 */
	public function get_headers() {
		$value              = array();
		$has_content_type   = false;
		$has_content_length = false;
		foreach ( $_SERVER as $k => $v ) {
			$k = strtolower( $k );
			if ( 'http_' === substr( $k, 0, 5 ) ) {
				$value[] = array( $this->normalize_header_name( substr( $k, 5 ) ), $v );
			} elseif ( 'content_type' === $k && '' !== $v ) {
				$has_content_type = true;
				$value[]          = array( 'content-type', $v );
			} elseif ( 'content_length' === $k && '' !== $v ) {
				$has_content_length = true;
				$value[]            = array( 'content-length', $v );
			}
		}
		if ( ! $has_content_type ) {
			// default Content-Type per RFC 7231 section 3.1.5.5.
			$value[] = array( 'content-type', 'application/octet-stream' );
		}
		if ( ! $has_content_length ) {
			$value[] = array( 'content-length', '0' );
		}

		return $value;
	}

	/**
	 * Change a header name to all-lowercase and replace spaces and underscores with dashes.
	 *
	 * @param string $name The header name to normalize.
	 * @return string
	 */
	public function normalize_header_name( $name ) {
		return str_replace( array( ' ', '_' ), '-', strtolower( $name ) );
	}

	/**
	 * Get the method for this request (GET, POST, etc).
	 *
	 * @return string
	 */
	public function get_method() {
		return isset( $_SERVER['REQUEST_METHOD'] )
			? filter_var( wp_unslash( $_SERVER['REQUEST_METHOD'] ), FILTER_DEFAULT )
			: '';
	}

	/**
	 * Get the protocol for this request (HTTP, HTTPS, etc)
	 *
	 * @return string
	 */
	public function get_protocol() {
		return isset( $_SERVER['SERVER_PROTOCOL'] )
			? filter_var( wp_unslash( $_SERVER['SERVER_PROTOCOL'] ), FILTER_DEFAULT )
			: '';
	}

	/**
	 * Returns the URL parts for this request.
	 *
	 * @see $this->url
	 * @return array{ 0: string, 1: string, 2: string }
	 */
	protected function get_url() {
		if ( null !== $this->url ) {
			return $this->url;
		}

		$uri = isset( $_SERVER['REQUEST_URI'] ) ? filter_var( wp_unslash( $_SERVER['REQUEST_URI'] ), FILTER_DEFAULT ) : '/';
		if ( false !== strpos( $uri, '?' ) ) {
			// remove the query string (we'll pull it from elsewhere later)
			$uri = substr( $uri, 0, strpos( $uri, '?' ) );
		}
		$query_string = isset( $_SERVER['QUERY_STRING'] ) ? '?' . filter_var( wp_unslash( $_SERVER['QUERY_STRING'] ), FILTER_DEFAULT ) : '';
		if ( 1 === preg_match( '/^https?:\/\//', $uri ) ) {
			// sometimes $_SERVER[REQUEST_URI] already includes the full domain name
			$uri_host  = substr( $uri, 0, strpos( $uri, '/', 8 ) );
			$uri_path  = substr( $uri, strlen( $uri_host ) );
			$this->url = array( $uri_host, $uri_path, $query_string );
		} else {
			// otherwise build the URI manually
			$uri_scheme = ( ! empty( $_SERVER['HTTPS'] ) && 'on' === $_SERVER['HTTPS'] )
				? 'https'
				: 'http';
			$uri_host   = isset( $_SERVER['HTTP_HOST'] )
				? filter_var( wp_unslash( $_SERVER['HTTP_HOST'] ), FILTER_DEFAULT )
				: (
					isset( $_SERVER['SERVER_NAME'] )
						? filter_var( wp_unslash( $_SERVER['SERVER_NAME'] ), FILTER_DEFAULT )
						: ''
				);
			$uri_port   = isset( $_SERVER['SERVER_PORT'] )
				? filter_var( wp_unslash( $_SERVER['SERVER_PORT'] ), FILTER_SANITIZE_NUMBER_INT )
				: '';
			// we only need to include the port if it's non-standard
			if ( $uri_port && ( 'http' === $uri_scheme && '80' !== $uri_port || 'https' === $uri_scheme && '443' !== $uri_port ) ) {
				$uri_port = ':' . $uri_port;
			} else {
				$uri_port = '';
			}
			$this->url = array(
				$uri_scheme . '://' . $uri_host . $uri_port,
				$uri,
				$query_string,
			);
		}
		return $this->url;
	}

	/**
	 * Get the requested URI
	 *
	 * @param boolean $include_host If true, the scheme and domain will be included in the returned string (i.e. 'https://wordpress.com/index.php).
	 *                              If false, only the requested URI path will be returned (i.e. '/index.php').
	 * @return string
	 */
	public function get_uri( $include_host = false ) {
		list( $host, $file, $query ) = $this->get_url();

		return ( $include_host ? $host : '' ) . $file . $query;
	}

	/**
	 * Return the filename part of the request
	 *
	 * @example for 'https://wordpress.com/some/page?id=5', return '/some/page'
	 * @return string
	 */
	public function get_filename() {
		return $this->get_url()[1];
	}

	/**
	 * Return the query string. If present, it will be prefixed with '?'. Otherwise, it will be an empty string.
	 *
	 * @return string
	 */
	public function get_query_string() {
		return $this->get_url()[2];
	}

	/**
	 * Returns the request body.
	 *
	 * @return string
	 */
	public function get_body() {
		$body = file_get_contents( 'php://input' );
		return false === $body ? '' : $body;
	}

	/**
	 * Returns the cookies
	 *
	 * @return array<string, string>
	 */
	public function get_cookies() {
		return flatten_array( $_COOKIE );
	}

	/**
	 * Returns the GET variables
	 *
	 * @return array<string, mixed|array>
	 */
	public function get_get_vars() {
		return flatten_array( $_GET );
	}

	/**
	 * Returns the POST variables
	 *
	 * @return array<string, mixed|array>
	 */
	public function get_post_vars() {
		return flatten_array( $_POST );
	}

	/**
	 * Returns the files that were uploaded with this request (i.e. what's in the $_FILES superglobal)
	 *
	 * @return RequestFile[]
	 */
	public function get_files() {
		$files = array();
		foreach ( $_FILES as $field_name => $arr ) {
			// flatten the values in case we were given inputs with brackets
			foreach ( flatten_array( $arr ) as list( $arr_key, $arr_value ) ) {
				if ( $arr_key === 'name' ) {
					// if this file was a simple (non-nested) name and unique, then just add it.
					$files[] = array(
						'name'     => $field_name,
						'filename' => $arr_value,
					);
				} elseif ( 'name[' === substr( $arr_key, 0, 5 ) ) {
					// otherwise this was a file with a nested name and/or multiple files with the same name
					$files[] = array(
						'name'     => $field_name . substr( $arr_key, 4 ),
						'filename' => $arr_value,
					);
				}
			}
		}
		return $files;
	}
}
