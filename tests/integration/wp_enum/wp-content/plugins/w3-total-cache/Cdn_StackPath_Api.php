<?php
namespace W3TC;

require_once(W3TC_LIB_DIR . '/OAuth/W3tcOAuth.php');
require_once(W3TC_LIB_NETDNA_DIR . '/W3tcWpHttpException.php');

/**
 * StackPath REST Client Library
 */
class Cdn_StackPath_Api {
	private $alias;
	private $key;
	private $secret;
	private $stackpath_api_url = 'https://api.stackpath.com/v1';



	static public function create( $authorization_key ) {
		$keys = explode( '+', $authorization_key );
		$alias = '';
		$consumerkey = '';
		$consumersecret = '';

		if ( sizeof( $keys ) == 3 ) {
			list( $alias, $consumerkey, $consumersecret ) = $keys;
		}

		$api = new Cdn_StackPath_Api( $alias, $consumerkey, $consumersecret,
			$endpoint );
		return $api;
	}

	public function __construct( $alias, $key, $secret ) {
		$this->alias  = $alias;
		$this->key    = $key;
		$this->secret = $secret;
	}

	public function is_valid() {
		return !empty( $this->alias ) && !empty( $this->key ) &&
			!empty( $this->secret );
	}

	private function execute( $selected_call, $method_type, $params ) {
		//increase the http request timeout
		add_filter( 'http_request_timeout', array( $this, 'filter_timeout_time' ) );
		add_filter( 'https_ssl_verify', array( $this, 'https_ssl_verify' ) );

		$consumer = new \W3tcOAuthConsumer( $this->key, $this->secret, NULL );

		// the endpoint for your request
		$endpoint = "$this->stackpath_api_url/$this->alias$selected_call";

		//parse endpoint before creating OAuth request
		$parsed = parse_url( $endpoint );
		if ( array_key_exists( "parsed", $parsed ) ) {
			parse_str( $parsed['query'], $params );
		}

		//generate a request from your consumer
		$req_req = \W3tcOAuthRequest::from_consumer_and_token(
			$consumer, NULL, $method_type, $endpoint, $params );

		//sign your OAuth request using hmac_sha1
		$sig_method = new \W3tcOAuthSignatureMethod_HMAC_SHA1();
		$req_req->sign_request( $sig_method, $consumer, NULL );

		$request = array();
		$request['sslverify'] = false;
		$request['method'] = $method_type;

		if ( $method_type == "POST" || $method_type == "PUT" ) {
			$request['body'] = $req_req->to_postdata();
			$request['headers']['Content-Type'] =
				'application/x-www-form-urlencoded; charset=' .
				get_option('blog_charset');

			$url = $req_req->get_normalized_http_url();
		} else {
			// notice GET, PUT and DELETE both needs to be passed in URL
			$url = $req_req->to_url();
		}

		$response = wp_remote_request( $url, $request );

		$json_output = '';
		if ( !is_wp_error( $response ) ) {
		// make call
			$result =  wp_remote_retrieve_body( $response );
			$headers =  wp_remote_retrieve_headers( $response );
			$response_code = wp_remote_retrieve_response_code( $response );
			// $json_output contains the output string
			$json_output = $result;
		} else {
			$response_code = $response->get_error_code();
		}

		remove_filter( 'https_ssl_verify', array( $this, 'https_ssl_verify' ) );
		remove_filter( 'http_request_timeout', array( $this, 'filter_timeout_time' ) );

		// catch errors
		if ( is_wp_error( $response ) ) {
			throw new \W3tcWpHttpException(
				"ERROR: {$response->get_error_message()}, Output: $json_output",
				$response_code, null, $headers );
		}

		return $json_output;
	}

	/**
	 * Increase http request timeout to 60 seconds
	 */
	public function filter_timeout_time($time) {
		return 600;
	}

	/**
	 * Don't check certificate, some users have limited CA list
	 */
	public function https_ssl_verify($v) {
		return false;
	}

	private function execute_await_200( $selected_call, $method_type, $params ) {
		$r = json_decode( $this->execute( $selected_call, $method_type, $params ),
			true );
		if ( !preg_match( '(200|201)', $r['code'] ) ) {
			throw $this->to_exception( $r );
		}
		return $r;
	}

	private function get( $selected_call, $params = array() ) {
		return $this->execute_await_200( $selected_call, 'GET', $params );
	}

	private function post( $selected_call, $params = array() ) {
		return $this->execute_await_200( $selected_call, 'POST', $params );
	}

	private function put( $selected_call, $params = array() ) {
		return $this->execute_await_200( $selected_call, 'PUT', $params );
	}

	private function delete( $selected_call, $params = array() ) {
		return $this->execute_await_200( $selected_call, 'DELETE', $params );
	}

	private function to_exception($response) {
		if ( isset( $response['error']['message'] ) ) {
			$message = $response['error']['message'];
		} else {
			$message = 'Failed to communicate with StackPath';
		}

		if ( isset( $response['data'] ) && isset( $response['data']['errors'] ) ) {
			foreach ( $response['data']['errors'] as $field => $error ) {
				if ( isset( $error['error'] ) ) {
					$message .= '. ' . $field . ': ' . $error['error'];
				} else {
					$message .= '. ' . $field . ': ' . $error;
				}
			}
		}

		return new \W3tcWpHttpException($message);
	}

	public function get_sites() {
		$r = $this->get( '/sites' );
		$zones = array();
		foreach ( $r ['data']['zones'] as $zone ) {
			$zones[] = $zone;
		}

		return $zones;
	}

	public function create_site($zone) {
		$r = $this->post( '/sites', $zone );
		return $r['data']['pullzone'];
	}

	public function update_site( $zone_id, $zone ) {
		$r = $this->put( "/sites/$zone_id", $zone );
		return $r['data']['pullzone'];
	}

	public function get_site( $zone_id ) {
		$r = $this->get( "/sites/$zone_id" );
		return $r['data']['pullzone'];
	}

	public function get_custom_domains($zone_id) {
		$r = $this->get( "/sites/$zone_id/customdomains" );
		$domains = array();
		foreach ($r['data']['customdomains'] as $domain) {
			$domains[] = $domain['custom_domain'];
		}

		return $domains;
	}

	public function delete_site_cache( $zone_id, $files_to_pass = null ) {
		$params = array();
		if ( !empty( $files_to_pass ) ) {
			 $params['files'] = $files_to_pass;
		}

		$r = $this->delete("/sites/$zone_id/cache", $params );
		return true;
	}

	public function get_stats_per_zone($zone_id) {
		$r = $this->get( "/reports/{$zone_id}/stats");
		return $r['data']['summary'];
	}

	public function get_list_of_file_types_per_zone( $zone_id ) {
		$r = $this->get( "/reports/{$zone_id}/filetypes" );
		$stats = array(
			'total' => $r['data']['total'],
			'filetypes' => array()
		);

		foreach( $r['data']['filetypes'] as $filetyp ) {
			$stats['filetypes'][] = $filetyp;
		}
		$stats['summary'] = $r['data']['summary'];
		return $stats;
	}

	public function get_list_of_popularfiles_per_zone($zone_id) {
		$r = $this->get( "/reports/{$zone_id}/popularfiles" );
		return $r['data']['popularfiles'];
	}

	public function get_account() {
		$r = $this->get( "/account" );
		return $r['data']['account'];
	}

	public function create_custom_domain( $zone_id, $custom_domain ) {
		$custom_domain = $this->post( "/sites/$zone_id/customdomains",
			array( 'custom_domain' => $custom_domain) );
		return $custom_domain;
	}
}
