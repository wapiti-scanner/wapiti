<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Jetpack JSON API.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Status;

if ( ! defined( 'WPCOM_JSON_API__DEBUG' ) ) {
	define( 'WPCOM_JSON_API__DEBUG', false );
}

require_once __DIR__ . '/sal/class.json-api-platform.php';

/**
 * Jetpack JSON API.
 */
class WPCOM_JSON_API {
	/**
	 * Static instance.
	 *
	 * @todo This should be private.
	 * @var self|null
	 */
	public static $self = null;

	/**
	 * Registered endpoints.
	 *
	 * @var WPCOM_JSON_API_Endpoint[]
	 */
	public $endpoints = array();

	/**
	 * Endpoint being processed.
	 *
	 * @var WPCOM_JSON_API_Endpoint
	 */
	public $endpoint = null;

	/**
	 * Token details.
	 *
	 * @var array
	 */
	public $token_details = array();

	/**
	 * Request HTTP method.
	 *
	 * @var string
	 */
	public $method = '';

	/**
	 * Request URL.
	 *
	 * @var string
	 */
	public $url = '';

	/**
	 * Path part of the request URL.
	 *
	 * @var string
	 */
	public $path = '';

	/**
	 * Version extracted from the request URL.
	 *
	 * @var string|null
	 */
	public $version = null;

	/**
	 * Parsed query data.
	 *
	 * @var array
	 */
	public $query = array();

	/**
	 * Post body, if the request is a POST.
	 *
	 * @var string|null
	 */
	public $post_body = null;

	/**
	 * Copy of `$_FILES` if the request is a POST.
	 *
	 * @var null|array
	 */
	public $files = null;

	/**
	 * Content type of the request.
	 *
	 * @var string|null
	 */
	public $content_type = null;

	/**
	 * Value of `$_SERVER['HTTP_ACCEPT']`, if any
	 *
	 * @var string
	 */
	public $accept = '';

	/**
	 * Value of `$_SERVER['HTTPS']`, or "--UNset--" if unset.
	 *
	 * @var string
	 */
	public $_server_https; // phpcs:ignore PSR2.Classes.PropertyDeclaration.Underscore

	/**
	 * Whether to exit after serving a response.
	 *
	 * @var bool
	 */
	public $exit = true;

	/**
	 * Public API scheme.
	 *
	 * @var string
	 */
	public $public_api_scheme = 'https';

	/**
	 * Output status code.
	 *
	 * @var int
	 */
	public $output_status_code = 200;

	/**
	 * Trapped error.
	 *
	 * @var null|array
	 */
	public $trapped_error = null;

	/**
	 * Whether output has been done.
	 *
	 * @var bool
	 */
	public $did_output = false;

	/**
	 * Extra HTTP headers.
	 *
	 * @var string
	 */
	public $extra_headers = array();

	/**
	 * AMP source origin.
	 *
	 * @var string
	 */
	public $amp_source_origin = null;

	/**
	 * Initialize.
	 *
	 * @param string|null $method As for `$this->setup_inputs()`.
	 * @param string|null $url As for `$this->setup_inputs()`.
	 * @param string|null $post_body As for `$this->setup_inputs()`.
	 * @return WPCOM_JSON_API instance
	 */
	public static function init( $method = null, $url = null, $post_body = null ) {
		if ( ! self::$self ) {
			$class      = function_exists( 'get_called_class' ) ? get_called_class() : __CLASS__; // phpcs:ignore PHPCompatibility.PHP.NewFunctions.get_called_classFound
			self::$self = new $class( $method, $url, $post_body );
		}
		return self::$self;
	}

	/**
	 * Add an endpoint.
	 *
	 * @param WPCOM_JSON_API_Endpoint $endpoint Endpoint to add.
	 */
	public function add( WPCOM_JSON_API_Endpoint $endpoint ) {
		// @todo Determine if anything depends on this being serialized rather than e.g. JSON.
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- Legacy, possibly depended on elsewhere.
		$path_versions = serialize(
			array(
				$endpoint->path,
				$endpoint->min_version,
				$endpoint->max_version,
			)
		);
		if ( ! isset( $this->endpoints[ $path_versions ] ) ) {
			$this->endpoints[ $path_versions ] = array();
		}
		$this->endpoints[ $path_versions ][ $endpoint->method ] = $endpoint;
	}

	/**
	 * Determine if a string is truthy.
	 *
	 * @param string $value "1", "t", and "true" (case insensitive) are falsey, everything else isn't.
	 * @return bool
	 */
	public static function is_truthy( $value ) {
		switch ( strtolower( (string) $value ) ) {
			case '1':
			case 't':
			case 'true':
				return true;
		}

		return false;
	}

	/**
	 * Determine if a string is falsey.
	 *
	 * @param string $value "0", "f", and "false" (case insensitive) are falsey, everything else isn't.
	 * @return bool
	 */
	public static function is_falsy( $value ) {
		switch ( strtolower( (string) $value ) ) {
			case '0':
			case 'f':
			case 'false':
				return true;
		}

		return false;
	}

	/**
	 * Constructor.
	 *
	 * @todo This should be private.
	 * @param string|null $method As for `$this->setup_inputs()`.
	 * @param string|null $url As for `$this->setup_inputs()`.
	 * @param string|null $post_body As for `$this->setup_inputs()`.
	 */
	public function __construct( $method = null, $url = null, $post_body = null ) {
		$this->setup_inputs( $method, $url, $post_body );
	}

	/**
	 * Setup inputs.
	 *
	 * @param string|null $method Request HTTP method. Fetched from `$_SERVER` if null.
	 * @param string|null $url URL requested. Determined from `$_SERVER` if null.
	 * @param string|null $post_body POST body. Read from `php://input` if null and method is POST.
	 */
	public function setup_inputs( $method = null, $url = null, $post_body = null ) {
		if ( $method === null ) {
			$this->method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( filter_var( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : '';
		} else {
			$this->method = strtoupper( $method );
		}
		if ( $url === null ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sniff misses the esc_url_raw.
			$this->url = esc_url_raw( set_url_scheme( 'http://' . ( isset( $_SERVER['HTTP_HOST'] ) ? wp_unslash( $_SERVER['HTTP_HOST'] ) : '' ) . ( isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '' ) ) );
		} else {
			$this->url = $url;
		}

		$parsed = wp_parse_url( $this->url );
		if ( ! empty( $parsed['path'] ) ) {
			$this->path = $parsed['path'];
		}

		if ( ! empty( $parsed['query'] ) ) {
			wp_parse_str( $parsed['query'], $this->query );
		}

		if ( ! empty( $_SERVER['HTTP_ACCEPT'] ) ) {
			$this->accept = filter_var( wp_unslash( $_SERVER['HTTP_ACCEPT'] ) );
		}

		if ( 'POST' === $this->method ) {
			if ( $post_body === null ) {
				$this->post_body = file_get_contents( 'php://input' );

				if ( ! empty( $_SERVER['HTTP_CONTENT_TYPE'] ) ) {
					$this->content_type = filter_var( wp_unslash( $_SERVER['HTTP_CONTENT_TYPE'] ) );
				} elseif ( ! empty( $_SERVER['CONTENT_TYPE'] ) ) {
					$this->content_type = filter_var( wp_unslash( $_SERVER['CONTENT_TYPE'] ) );
				} elseif ( '{' === $this->post_body[0] ) {
					$this->content_type = 'application/json';
				} else {
					$this->content_type = 'application/x-www-form-urlencoded';
				}

				if ( 0 === strpos( strtolower( $this->content_type ), 'multipart/' ) ) {
					// phpcs:ignore WordPress.Security.NonceVerification.Missing
					$this->post_body    = http_build_query( stripslashes_deep( $_POST ) );
					$this->files        = $_FILES;
					$this->content_type = 'multipart/form-data';
				}
			} else {
				$this->post_body    = $post_body;
				$this->content_type = isset( $this->post_body[0] ) && '{' === $this->post_body[0] ? 'application/json' : 'application/x-www-form-urlencoded';
			}
		} else {
			$this->post_body    = null;
			$this->content_type = null;
		}

		$this->_server_https = array_key_exists( 'HTTPS', $_SERVER ) ? filter_var( wp_unslash( $_SERVER['HTTPS'] ) ) : '--UNset--';
	}

	/**
	 * Initialize.
	 *
	 * @return null|WP_Error (although this implementation always returns null)
	 */
	public function initialize() {
		$this->token_details['blog_id'] = Jetpack_Options::get_option( 'id' );
		return null;
	}

	/**
	 * Checks if the current request is authorized with a blog token.
	 * This method is overridden by a child class in WPCOM.
	 *
	 * @since 9.1.0
	 *
	 * @param  boolean|int $site_id The site id.
	 * @return boolean
	 */
	public function is_jetpack_authorized_for_site( $site_id = false ) {
		if ( ! $this->token_details ) {
			return false;
		}

		$token_details = (object) $this->token_details;

		$site_in_token = (int) $token_details->blog_id;

		if ( $site_in_token < 1 ) {
			return false;
		}

		if ( $site_id && $site_in_token !== (int) $site_id ) {
			return false;
		}

		if ( (int) get_current_user_id() !== 0 ) {
			// If Jetpack blog token is used, no logged-in user should exist.
			return false;
		}

		return true;
	}

	/**
	 * Serve.
	 *
	 * @param bool $exit Whether to exit.
	 * @return string|null Content type (assuming it didn't exit), or null in certain error cases.
	 */
	public function serve( $exit = true ) {
		ini_set( 'display_errors', false ); // phpcs:ignore WordPress.PHP.IniSet.display_errors_Blacklisted

		$this->exit = (bool) $exit;

		// This was causing problems with Jetpack, but is necessary for wpcom
		// @see https://github.com/Automattic/jetpack/pull/2603
		// @see r124548-wpcom .
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			add_filter( 'home_url', array( $this, 'ensure_http_scheme_of_home_url' ), 10, 3 );
		}

		add_filter( 'user_can_richedit', '__return_true' );

		add_filter( 'comment_edit_pre', array( $this, 'comment_edit_pre' ) );

		$initialization = $this->initialize();
		if ( 'OPTIONS' === $this->method ) {
			/**
			 * Fires before the page output.
			 * Can be used to specify custom header options.
			 *
			 * @module json-api
			 *
			 * @since 3.1.0
			 */
			do_action( 'wpcom_json_api_options' );
			return $this->output( 200, '', 'text/plain' );
		}

		if ( is_wp_error( $initialization ) ) {
			$this->output_error( $initialization );
			return;
		}

		// Normalize path and extract API version.
		$this->path = untrailingslashit( $this->path );
		preg_match( '#^/rest/v(\d+(\.\d+)*)#', $this->path, $matches );
		$this->path    = substr( $this->path, strlen( $matches[0] ) );
		$this->version = $matches[1];

		$allowed_methods = array( 'GET', 'POST' );
		$four_oh_five    = false;

		$is_help            = preg_match( '#/help/?$#i', $this->path );
		$matching_endpoints = array();

		if ( $is_help ) {
			$origin = get_http_origin();

			if ( ! empty( $origin ) && 'GET' === $this->method ) {
				header( 'Access-Control-Allow-Origin: ' . esc_url_raw( $origin ) );
			}

			$this->path = substr( rtrim( $this->path, '/' ), 0, -5 );
			// Show help for all matching endpoints regardless of method.
			$methods                     = $allowed_methods;
			$find_all_matching_endpoints = true;
			// How deep to truncate each endpoint's path to see if it matches this help request.
			$depth = substr_count( $this->path, '/' ) + 1;
			if ( false !== stripos( $this->accept, 'javascript' ) || false !== stripos( $this->accept, 'json' ) ) {
				$help_content_type = 'json';
			} else {
				$help_content_type = 'html';
			}
		} elseif ( in_array( $this->method, $allowed_methods, true ) ) {
			// Only serve requested method.
			$methods                     = array( $this->method );
			$find_all_matching_endpoints = false;
		} else {
			// We don't allow this requested method - find matching endpoints and send 405.
			$methods                     = $allowed_methods;
			$find_all_matching_endpoints = true;
			$four_oh_five                = true;
		}

		// Find which endpoint to serve.
		$found = false;
		foreach ( $this->endpoints as $endpoint_path_versions => $endpoints_by_method ) {
			// @todo Determine if anything depends on this being serialized rather than e.g. JSON.
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_unserialize -- Legacy, possibly depended on elsewhere.
			$endpoint_path_versions = unserialize( $endpoint_path_versions );
			$endpoint_path          = $endpoint_path_versions[0];
			$endpoint_min_version   = $endpoint_path_versions[1];
			$endpoint_max_version   = $endpoint_path_versions[2];

			// Make sure max_version is not less than min_version.
			if ( version_compare( $endpoint_max_version, $endpoint_min_version, '<' ) ) {
				$endpoint_max_version = $endpoint_min_version;
			}

			foreach ( $methods as $method ) {
				if ( ! isset( $endpoints_by_method[ $method ] ) ) {
					continue;
				}

				// Normalize.
				$endpoint_path = untrailingslashit( $endpoint_path );
				if ( $is_help ) {
					// Truncate path at help depth.
					$endpoint_path = join( '/', array_slice( explode( '/', $endpoint_path ), 0, $depth ) );
				}

				// Generate regular expression from sprintf().
				$endpoint_path_regex = str_replace( array( '%s', '%d' ), array( '([^/?&]+)', '(\d+)' ), $endpoint_path );

				if ( ! preg_match( "#^$endpoint_path_regex\$#", $this->path, $path_pieces ) ) {
					// This endpoint does not match the requested path.
					continue;
				}

				if ( version_compare( $this->version, $endpoint_min_version, '<' ) || version_compare( $this->version, $endpoint_max_version, '>' ) ) {
					// This endpoint does not match the requested version.
					continue;
				}

				$found = true;

				if ( $find_all_matching_endpoints ) {
					$matching_endpoints[] = array( $endpoints_by_method[ $method ], $path_pieces );
				} else {
					// The method parameters are now in $path_pieces.
					$endpoint = $endpoints_by_method[ $method ];
					break 2;
				}
			}
		}

		if ( ! $found ) {
			return $this->output( 404, '', 'text/plain' );
		}

		if ( $four_oh_five ) {
			$allowed_methods = array();
			foreach ( $matching_endpoints as $matching_endpoint ) {
				$allowed_methods[] = $matching_endpoint[0]->method;
			}

			header( 'Allow: ' . strtoupper( join( ',', array_unique( $allowed_methods ) ) ) );
			return $this->output(
				405,
				array(
					'error'         => 'not_allowed',
					'error_message' => 'Method not allowed',
				)
			);
		}

		if ( $is_help ) {
			/**
			 * Fires before the API output.
			 *
			 * @since 1.9.0
			 *
			 * @param string help.
			 */
			do_action( 'wpcom_json_api_output', 'help' );
			$proxied = function_exists( 'wpcom_is_proxied_request' ) ? wpcom_is_proxied_request() : false;
			if ( 'json' === $help_content_type ) {
				$docs = array();
				foreach ( $matching_endpoints as $matching_endpoint ) {
					if ( $matching_endpoint[0]->is_publicly_documentable() || $proxied || WPCOM_JSON_API__DEBUG ) {
						$docs[] = call_user_func( array( $matching_endpoint[0], 'generate_documentation' ) );
					}
				}
				return $this->output( 200, $docs );
			} else {
				status_header( 200 );
				foreach ( $matching_endpoints as $matching_endpoint ) {
					if ( $matching_endpoint[0]->is_publicly_documentable() || $proxied || WPCOM_JSON_API__DEBUG ) {
						call_user_func( array( $matching_endpoint[0], 'document' ) );
					}
				}
			}
			exit;
		}

		if ( $endpoint->in_testing && ! WPCOM_JSON_API__DEBUG ) {
			return $this->output( 404, '', 'text/plain' );
		}

		/** This action is documented in class.json-api.php */
		do_action( 'wpcom_json_api_output', $endpoint->stat );

		$response = $this->process_request( $endpoint, $path_pieces );

		if ( ! $response && ! is_array( $response ) ) {
			return $this->output( 500, '', 'text/plain' );
		} elseif ( is_wp_error( $response ) ) {
			return $this->output_error( $response );
		}

		$output_status_code = $this->output_status_code;
		$this->set_output_status_code();

		return $this->output( $output_status_code, $response, 'application/json', $this->extra_headers );
	}

	/**
	 * Process a request.
	 *
	 * @param WPCOM_JSON_API_Endpoint $endpoint Endpoint.
	 * @param array                   $path_pieces Path pieces.
	 * @return array|WP_Error Return value from the endpoint's callback.
	 */
	public function process_request( WPCOM_JSON_API_Endpoint $endpoint, $path_pieces ) {
		$this->endpoint = $endpoint;
		return call_user_func_array( array( $endpoint, 'callback' ), $path_pieces );
	}

	/**
	 * Output a response or error without exiting.
	 *
	 * @param int    $status_code HTTP status code.
	 * @param mixed  $response Response data.
	 * @param string $content_type Content type of the response.
	 */
	public function output_early( $status_code, $response = null, $content_type = 'application/json' ) {
		$exit       = $this->exit;
		$this->exit = false;
		if ( is_wp_error( $response ) ) {
			$this->output_error( $response );
		} else {
			$this->output( $status_code, $response, $content_type );
		}
		$this->exit = $exit;
		if ( ! defined( 'XMLRPC_REQUEST' ) || ! XMLRPC_REQUEST ) {
			$this->finish_request();
		}
	}

	/**
	 * Set output status code.
	 *
	 * @param int $code HTTP status code.
	 */
	public function set_output_status_code( $code = 200 ) {
		$this->output_status_code = $code;
	}

	/**
	 * Output a response.
	 *
	 * @param int    $status_code HTTP status code.
	 * @param mixed  $response Response data.
	 * @param string $content_type Content type of the response.
	 * @param array  $extra Additional HTTP headers.
	 * @return string Content type (assuming it didn't exit).
	 */
	public function output( $status_code, $response = null, $content_type = 'application/json', $extra = array() ) {
		$status_code = (int) $status_code;

		// In case output() was called before the callback returned.
		if ( $this->did_output ) {
			if ( $this->exit ) {
				exit;
			}
			return $content_type;
		}
		$this->did_output = true;

		// 400s and 404s are allowed for all origins
		if ( 404 === $status_code || 400 === $status_code ) {
			header( 'Access-Control-Allow-Origin: *' );
		}

		/* Add headers for form submission from <amp-form/> */
		if ( $this->amp_source_origin ) {
			header( 'Access-Control-Allow-Origin: ' . wp_unslash( $this->amp_source_origin ) );
			header( 'Access-Control-Allow-Credentials: true' );
		}

		if ( $response === null ) {
			$response = new stdClass();
		}

		if ( 'text/plain' === $content_type ||
			'text/html' === $content_type ) {
			status_header( (int) $status_code );
			header( 'Content-Type: ' . $content_type );
			foreach ( $extra as $key => $value ) {
				header( "$key: $value" );
			}
			echo $response; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			if ( $this->exit ) {
				exit;
			}

			return $content_type;
		}

		$response = $this->filter_fields( $response );

		if ( isset( $this->query['http_envelope'] ) && self::is_truthy( $this->query['http_envelope'] ) ) {
			$headers = array(
				array(
					'name'  => 'Content-Type',
					'value' => $content_type,
				),
			);

			foreach ( $extra as $key => $value ) {
				$headers[] = array(
					'name'  => $key,
					'value' => $value,
				);
			}

			$response     = array(
				'code'    => (int) $status_code,
				'headers' => $headers,
				'body'    => $response,
			);
			$status_code  = 200;
			$content_type = 'application/json';
		}

		status_header( (int) $status_code );
		header( "Content-Type: $content_type" );
		if ( isset( $this->query['callback'] ) && is_string( $this->query['callback'] ) ) {
			$callback = preg_replace( '/[^a-z0-9_.]/i', '', $this->query['callback'] );
		} else {
			$callback = false;
		}

		if ( $callback ) {
			// Mitigate Rosetta Flash [1] by setting the Content-Type-Options: nosniff header
			// and by prepending the JSONP response with a JS comment.
			// [1] <https://blog.miki.it/2014/7/8/abusing-jsonp-with-rosetta-flash/index.html>.
			echo "/**/$callback("; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- This is JSONP output, not HTML.

		}
		echo $this->json_encode( $response ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- This is JSON or JSONP output, not HTML.
		if ( $callback ) {
			echo ');';
		}

		if ( $this->exit ) {
			exit;
		}

		return $content_type;
	}

	/**
	 * Serialize an error.
	 *
	 * @param WP_Error $error Error.
	 * @return array with 'status_code' and 'errors' data.
	 */
	public static function serializable_error( $error ) {

		$status_code = $error->get_error_data();

		if ( is_array( $status_code ) ) {
			$status_code = $status_code['status_code'];
		}

		if ( ! $status_code ) {
			$status_code = 400;
		}
		$response = array(
			'error'   => $error->get_error_code(),
			'message' => $error->get_error_message(),
		);

		$additional_data = $error->get_error_data( 'additional_data' );
		if ( $additional_data ) {
			$response['data'] = $additional_data;
		}

		return array(
			'status_code' => $status_code,
			'errors'      => $response,
		);
	}

	/**
	 * Output an error.
	 *
	 * @param WP_Error $error Error.
	 * @return string Content type (assuming it didn't exit).
	 */
	public function output_error( $error ) {
		$error_response = $this->serializable_error( $error );

		return $this->output( $error_response['status_code'], $error_response['errors'] );
	}

	/**
	 * Filter fields in a response.
	 *
	 * @param array|object $response Response.
	 * @return array|object Filtered response.
	 */
	public function filter_fields( $response ) {
		if ( empty( $this->query['fields'] ) || ( is_array( $response ) && ! empty( $response['error'] ) ) || ! empty( $this->endpoint->custom_fields_filtering ) ) {
			return $response;
		}

		$fields = array_map( 'trim', explode( ',', $this->query['fields'] ) );

		if ( is_object( $response ) ) {
			$response = (array) $response;
		}

		$has_filtered = false;
		if ( is_array( $response ) && empty( $response['ID'] ) ) {
			$keys_to_filter = array(
				'categories',
				'comments',
				'connections',
				'domains',
				'groups',
				'likes',
				'media',
				'notes',
				'posts',
				'services',
				'sites',
				'suggestions',
				'tags',
				'themes',
				'topics',
				'users',
			);

			foreach ( $keys_to_filter as $key_to_filter ) {
				if ( ! isset( $response[ $key_to_filter ] ) || $has_filtered ) {
					continue;
				}

				foreach ( $response[ $key_to_filter ] as $key => $values ) {
					if ( is_object( $values ) ) {
						if ( is_object( $response[ $key_to_filter ] ) ) {
							// phpcs:ignore Squiz.PHP.DisallowMultipleAssignments.Found -- False positive.
							$response[ $key_to_filter ]->$key = (object) array_intersect_key( ( (array) $values ), array_flip( $fields ) );
						} elseif ( is_array( $response[ $key_to_filter ] ) ) {
							$response[ $key_to_filter ][ $key ] = (object) array_intersect_key( ( (array) $values ), array_flip( $fields ) );
						}
					} elseif ( is_array( $values ) ) {
						$response[ $key_to_filter ][ $key ] = array_intersect_key( $values, array_flip( $fields ) );
					}
				}

				$has_filtered = true;
			}
		}

		if ( ! $has_filtered ) {
			if ( is_object( $response ) ) {
				$response = (object) array_intersect_key( (array) $response, array_flip( $fields ) );
			} elseif ( is_array( $response ) ) {
				$response = array_intersect_key( $response, array_flip( $fields ) );
			}
		}

		return $response;
	}

	/**
	 * Filter for `home_url`.
	 *
	 * If `$original_scheme` is null, turns an https URL to http.
	 *
	 * @param string      $url The complete home URL including scheme and path.
	 * @param string      $path Path relative to the home URL. Blank string if no path is specified.
	 * @param string|null $original_scheme Scheme to give the home URL context. Accepts 'http', 'https', 'relative', 'rest', or null.
	 * @return string URL.
	 */
	public function ensure_http_scheme_of_home_url( $url, $path, $original_scheme ) {
		if ( $original_scheme ) {
			return $url;
		}

		return preg_replace( '#^https:#', 'http:', $url );
	}

	/**
	 * Decode HTML special characters in comment content.
	 *
	 * @param string $comment_content Comment content.
	 * @return string
	 */
	public function comment_edit_pre( $comment_content ) {
		return htmlspecialchars_decode( $comment_content, ENT_QUOTES );
	}

	/**
	 * JSON encode.
	 *
	 * @param mixed $data Data.
	 * @return string|false
	 */
	public function json_encode( $data ) {
		return wp_json_encode( $data );
	}

	/**
	 * Test if a string ends with a string.
	 *
	 * @param string $haystack String to check.
	 * @param string $needle Suffix to check.
	 * @return bool
	 */
	public function ends_with( $haystack, $needle ) {
		return substr( $haystack, -strlen( $needle ) ) === $needle;
	}

	/**
	 * Returns the site's blog_id in the WP.com ecosystem
	 *
	 * @return int
	 */
	public function get_blog_id_for_output() {
		return $this->token_details['blog_id'];
	}

	/**
	 * Returns the site's local blog_id.
	 *
	 * @param int $blog_id Blog ID.
	 * @return int
	 */
	public function get_blog_id( $blog_id ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return $GLOBALS['blog_id'];
	}

	/**
	 * Switch to blog and validate user.
	 *
	 * @param int  $blog_id Blog ID.
	 * @param bool $verify_token_for_blog Whether to verify the token.
	 * @return int Blog ID.
	 */
	public function switch_to_blog_and_validate_user( $blog_id = 0, $verify_token_for_blog = true ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		if ( $this->is_restricted_blog( $blog_id ) ) {
			return new WP_Error( 'unauthorized', 'User cannot access this restricted blog', 403 );
		}
		/**
		 * If this is a private site we check for 2 things:
		 * 1. In case of user based authentication, we need to check if the logged-in user has the 'read' capability.
		 * 2. In case of site based authentication, make sure the endpoint accepts it.
		 */
		if ( ( new Status() )->is_private_site() &&
			! current_user_can( 'read' ) &&
			! $this->endpoint->accepts_site_based_authentication()
		) {
			return new WP_Error( 'unauthorized', 'User cannot access this private blog.', 403 );
		}

		return $blog_id;
	}

	/**
	 * Returns true if the specified blog ID is a restricted blog
	 *
	 * @param int $blog_id Blog ID.
	 * @return bool
	 */
	public function is_restricted_blog( $blog_id ) {
		/**
		 * Filters all REST API access and return a 403 unauthorized response for all Restricted blog IDs.
		 *
		 * @module json-api
		 *
		 * @since 3.4.0
		 *
		 * @param array $array Array of Blog IDs.
		 */
		$restricted_blog_ids = apply_filters( 'wpcom_json_api_restricted_blog_ids', array() );
		return true === in_array( $blog_id, $restricted_blog_ids ); // phpcs:ignore WordPress.PHP.StrictInArray.MissingTrueStrict -- I don't trust filters to return the right types.
	}

	/**
	 * Post like count.
	 *
	 * @param int $blog_id Blog ID.
	 * @param int $post_id Post ID.
	 * @return int
	 */
	public function post_like_count( $blog_id, $post_id ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return 0;
	}

	/**
	 * Is liked?
	 *
	 * @param int $blog_id Blog ID.
	 * @param int $post_id Post ID.
	 * @return bool
	 */
	public function is_liked( $blog_id, $post_id ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return false;
	}

	/**
	 * Is reblogged?
	 *
	 * @param int $blog_id Blog ID.
	 * @param int $post_id Post ID.
	 * @return bool
	 */
	public function is_reblogged( $blog_id, $post_id ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return false;
	}

	/**
	 * Is following?
	 *
	 * @param int $blog_id Blog ID.
	 * @return bool
	 */
	public function is_following( $blog_id ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return false;
	}

	/**
	 * Add global ID.
	 *
	 * @param int $blog_id Blog ID.
	 * @param int $post_id Post ID.
	 * @return string
	 */
	public function add_global_ID( $blog_id, $post_id ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable, WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid
		return '';
	}

	/**
	 * Get avatar URL.
	 *
	 * @param string $email Email.
	 * @param array  $avatar_size Args for `get_avatar_url()`.
	 * @return string|false
	 */
	public function get_avatar_url( $email, $avatar_size = null ) {
		if ( function_exists( 'wpcom_get_avatar_url' ) ) {
			return null === $avatar_size
				? wpcom_get_avatar_url( $email )
				: wpcom_get_avatar_url( $email, $avatar_size );
		} else {
			return null === $avatar_size
				? get_avatar_url( $email )
				: get_avatar_url( $email, $avatar_size );
		}
	}

	/**
	 * Counts the number of comments on a site, including certain comment types.
	 *
	 * @param int $post_id Post ID.
	 * @return array Array of counts, matching the output of https://developer.wordpress.org/reference/functions/get_comment_count/.
	 */
	public function wp_count_comments( $post_id ) {
		global $wpdb;
		if ( 0 !== $post_id ) {
			return wp_count_comments( $post_id );
		}

		$counts = array(
			'total_comments' => 0,
			'all'            => 0,
		);

		/**
		* Exclude certain comment types from comment counts in the REST API.
		*
		* @since 6.9.0
		* @deprecated 11.1
		* @module json-api
		*
		* @param array Array of comment types to exclude (default: 'order_note', 'webhook_delivery', 'review', 'action_log')
		*/
		$exclude = apply_filters_deprecated( 'jetpack_api_exclude_comment_types_count', array( 'order_note', 'webhook_delivery', 'review', 'action_log' ), 'jetpack-11.1', 'jetpack_api_include_comment_types_count' ); // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable

		/**
		* Include certain comment types in comment counts in the REST API.
		* Note: the default array of comment types includes an empty string,
		* to support comments posted before WP 5.5, that used an empty string as comment type.
		*
		* @since 11.1
		* @module json-api
		*
		* @param array Array of comment types to include (default: 'comment', 'pingback', 'trackback')
		*/
		$include = apply_filters(
			'jetpack_api_include_comment_types_count',
			array( 'comment', 'pingback', 'trackback', '' )
		);

		if ( empty( $include ) ) {
			return wp_count_comments( $post_id );
		}

		array_walk( $include, 'esc_sql' );
		$where = sprintf(
			"WHERE comment_type IN ( '%s' )",
			implode( "','", $include )
		);

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- `$where` is built with escaping just above.
		$count = $wpdb->get_results(
			"SELECT comment_approved, COUNT(*) AS num_comments
				FROM $wpdb->comments
				{$where}
				GROUP BY comment_approved
			"
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		$approved = array(
			'0'            => 'moderated',
			'1'            => 'approved',
			'spam'         => 'spam',
			'trash'        => 'trash',
			'post-trashed' => 'post-trashed',
		);

		// <https://developer.wordpress.org/reference/functions/get_comment_count/#source>
		foreach ( $count as $row ) {
			if ( ! in_array( $row->comment_approved, array( 'post-trashed', 'trash', 'spam' ), true ) ) {
				$counts['all']            += $row->num_comments;
				$counts['total_comments'] += $row->num_comments;
			} elseif ( ! in_array( $row->comment_approved, array( 'post-trashed', 'trash' ), true ) ) {
				$counts['total_comments'] += $row->num_comments;
			}
			if ( isset( $approved[ $row->comment_approved ] ) ) {
				$counts[ $approved[ $row->comment_approved ] ] = $row->num_comments;
			}
		}

		foreach ( $approved as $key ) {
			if ( empty( $counts[ $key ] ) ) {
				$counts[ $key ] = 0;
			}
		}

		$counts = (object) $counts;

		return $counts;
	}

	/**
	 * Traps `wp_die()` calls and outputs a JSON response instead.
	 * The result is always output, never returned.
	 *
	 * @param string|null $error_code  Call with string to start the trapping.  Call with null to stop.
	 * @param int         $http_status  HTTP status code, 400 by default.
	 */
	public function trap_wp_die( $error_code = null, $http_status = 400 ) {
		// Determine the filter name; based on the conditionals inside the wp_die function.
		if ( wp_is_json_request() ) {
			$die_handler = 'wp_die_json_handler';
		} elseif ( wp_is_jsonp_request() ) {
			$die_handler = 'wp_die_jsonp_handler';
		} elseif ( wp_is_xml_request() ) {
			$die_handler = 'wp_die_xml_handler';
		} else {
			$die_handler = 'wp_die_handler';
		}

		if ( $error_code === null ) {
			$this->trapped_error = null;
			// Stop trapping.
			remove_filter( $die_handler, array( $this, 'wp_die_handler_callback' ) );
			return;
		}

		// If API called via PHP, bail: don't do our custom wp_die().  Do the normal wp_die().
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			if ( ! defined( 'REST_API_REQUEST' ) || ! REST_API_REQUEST ) {
				return;
			}
		} elseif ( ! defined( 'XMLRPC_REQUEST' ) || ! XMLRPC_REQUEST ) {
			return;
		}

		$this->trapped_error = array(
			'status'  => $http_status,
			'code'    => $error_code,
			'message' => '',
		);
		// Start trapping.
		add_filter( $die_handler, array( $this, 'wp_die_handler_callback' ) );
	}

	/**
	 * Filter function for `wp_die_handler` and similar filters.
	 *
	 * @return callable
	 */
	public function wp_die_handler_callback() {
		return array( $this, 'wp_die_handler' );
	}

	/**
	 * Handler for `wp_die` calls.
	 *
	 * @param string|WP_Error  $message As for `wp_die()`.
	 * @param string|int       $title As for `wp_die()`.
	 * @param string|array|int $args As for `wp_die()`.
	 */
	public function wp_die_handler( $message, $title = '', $args = array() ) {
		// Allow wp_die calls to override HTTP status code...
		$args = wp_parse_args(
			$args,
			array(
				'response' => $this->trapped_error['status'],
			)
		);

		// ... unless it's 500
		if ( 500 !== (int) $args['response'] ) {
			$this->trapped_error['status'] = $args['response'];
		}

		if ( $title ) {
			$message = "$title: $message";
		}

		$this->trapped_error['message'] = wp_kses( $message, array() );

		switch ( $this->trapped_error['code'] ) {
			case 'comment_failure':
				if ( did_action( 'comment_duplicate_trigger' ) ) {
					$this->trapped_error['code'] = 'comment_duplicate';
				} elseif ( did_action( 'comment_flood_trigger' ) ) {
					$this->trapped_error['code'] = 'comment_flood';
				}
				break;
		}

		// We still want to exit so that code execution stops where it should.
		// Attach the JSON output to the WordPress shutdown handler.
		add_action( 'shutdown', array( $this, 'output_trapped_error' ), 0 );
		exit;
	}

	/**
	 * Output the trapped error.
	 */
	public function output_trapped_error() {
		$this->exit = false; // We're already exiting once.  Don't do it twice.
		$this->output(
			$this->trapped_error['status'],
			(object) array(
				'error'   => $this->trapped_error['code'],
				'message' => $this->trapped_error['message'],
			)
		);
	}

	/**
	 * Finish the request.
	 */
	public function finish_request() {
		if ( function_exists( 'fastcgi_finish_request' ) ) {
			return fastcgi_finish_request();
		}
	}
}
