<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Jetpack API endpoint base class.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\Status;

require_once __DIR__ . '/json-api-config.php';
require_once __DIR__ . '/sal/class.json-api-links.php';
require_once __DIR__ . '/sal/class.json-api-metadata.php';
require_once __DIR__ . '/sal/class.json-api-date.php';

/**
 * Endpoint.
 */
abstract class WPCOM_JSON_API_Endpoint {
	/**
	 * The API Object
	 *
	 * @var WPCOM_JSON_API
	 */
	public $api;

	/**
	 * The link-generating utility class
	 *
	 * @var WPCOM_JSON_API_Links
	 */
	public $links;

	/**
	 * Whether to pass wpcom user details.
	 *
	 * @var bool
	 */
	public $pass_wpcom_user_details = false;

	/**
	 * One liner.
	 *
	 * @var string
	 */
	public $description;

	/**
	 * Object Grouping For Documentation (Users, Posts, Comments)
	 *
	 * @var string
	 */
	public $group;

	/**
	 * Stats extra value to bump
	 *
	 * @var mixed
	 */
	public $stat;

	/**
	 * HTTP Method
	 *
	 * @var string
	 */
	public $method = 'GET';

	/**
	 * Minimum version of the api for which to serve this endpoint
	 *
	 * @var string
	 */
	public $min_version = '0';

	/**
	 * Maximum version of the api for which to serve this endpoint
	 *
	 * @var string
	 */
	public $max_version = WPCOM_JSON_API__CURRENT_VERSION;

	/**
	 * Forced endpoint environment when running on WPCOM
	 *
	 * @var string '', 'wpcom', 'secure', or 'jetpack'
	 */
	public $force = '';

	/**
	 * Whether the endpoint is deprecated
	 *
	 * @var bool
	 */
	public $deprecated = false;

	/**
	 * Version of the endpoint this endpoint is deprecated in favor of.
	 *
	 * @var string
	 */
	protected $new_version = WPCOM_JSON_API__CURRENT_VERSION;

	/**
	 * Whether the endpoint is only available on WordPress.com hosted blogs
	 *
	 * @var bool
	 */
	public $jp_disabled = false;

	/**
	 * Path at which to serve this endpoint: sprintf() format.
	 *
	 * @var string
	 */
	public $path = '';

	/**
	 * Identifiers to fill sprintf() formatted $path
	 *
	 * @var array
	 */
	public $path_labels = array();

	/**
	 * Accepted query parameters
	 *
	 * @var array
	 */
	public $query = array(
		// Parameter name.
		'context'       => array(
			// Default value => description.
			'display' => 'Formats the output as HTML for display.  Shortcodes are parsed, paragraph tags are added, etc..',
			// Other possible values => description.
			'edit'    => 'Formats the output for editing.  Shortcodes are left unparsed, significant whitespace is kept, etc..',
		),
		'http_envelope' => array(
			'false' => '',
			'true'  => 'Some environments (like in-browser JavaScript or Flash) block or divert responses with a non-200 HTTP status code.  Setting this parameter will force the HTTP status code to always be 200.  The JSON response is wrapped in an "envelope" containing the "real" HTTP status code and headers.',
		),
		'pretty'        => array(
			'false' => '',
			'true'  => 'Output pretty JSON',
		),
		'meta'          => "(string) Optional. Loads data from the endpoints found in the 'meta' part of the response. Comma-separated list. Example: meta=site,likes",
		'fields'        => '(string) Optional. Returns specified fields only. Comma-separated list. Example: fields=ID,title',
		// Parameter name => description (default value is empty).
		'callback'      => '(string) An optional JSONP callback function.',
	);

	/**
	 * Response format
	 *
	 * @var array
	 */
	public $response_format = array();

	/**
	 * Request format
	 *
	 * @var array
	 */
	public $request_format = array();

	/**
	 * Is this endpoint still in testing phase?  If so, not available to the public.
	 *
	 * @var bool
	 */
	public $in_testing = false;

	/**
	 * Is this endpoint still allowed if the site in question is flagged?
	 *
	 * @var bool
	 */
	public $allowed_if_flagged = false;

	/**
	 * Is this endpoint allowed if the site is red flagged?
	 *
	 * @var bool
	 */
	public $allowed_if_red_flagged = false;

	/**
	 * Is this endpoint allowed if the site is deleted?
	 *
	 * @var bool
	 */
	public $allowed_if_deleted = false;

	/**
	 * Version of the API
	 *
	 * @var string
	 */
	public $version = '';

	/**
	 * Example request to make
	 *
	 * @var string
	 */
	public $example_request = '';

	/**
	 * Example request data (for POST methods)
	 *
	 * @var string
	 */
	public $example_request_data = '';

	/**
	 * Example response from $example_request
	 *
	 * @var string
	 */
	public $example_response = '';

	/**
	 * OAuth2 scope required when running on WPCOM
	 *
	 * @var string
	 */
	public $required_scope = '';

	/**
	 * Set to true if the endpoint implements its own filtering instead of the standard `fields` query method
	 *
	 * @var bool
	 */
	public $custom_fields_filtering = false;

	/**
	 * Set to true if the endpoint accepts all cross origin requests. You probably should not set this flag.
	 *
	 * @var bool
	 */
	public $allow_cross_origin_request = false;

	/**
	 * Set to true if the endpoint can recieve unauthorized POST requests.
	 *
	 * @var bool
	 */
	public $allow_unauthorized_request = false;

	/**
	 * Set to true if the endpoint should accept site based (not user based) authentication.
	 *
	 * @var bool
	 */
	public $allow_jetpack_site_auth = false;

	/**
	 * Set to true if the endpoint should accept auth from an upload token.
	 *
	 * @var bool
	 */
	public $allow_upload_token_auth = false;

	/**
	 * Set to true if the endpoint should require auth from a Rewind auth token.
	 *
	 * @var bool
	 */
	public $require_rewind_auth = false;

	/**
	 * Whether this endpoint allows falling back to a blog token for making requests to remote Jetpack sites.
	 *
	 * @var bool
	 */
	public $allow_fallback_to_jetpack_blog_token = false;

	/**
	 * Constructor.
	 *
	 * @param string|array|object $args Args.
	 */
	public function __construct( $args ) {
		$defaults = array(
			'in_testing'                           => false,
			'allowed_if_flagged'                   => false,
			'allowed_if_red_flagged'               => false,
			'allowed_if_deleted'                   => false,
			'description'                          => '',
			'group'                                => '',
			'method'                               => 'GET',
			'path'                                 => '/',
			'min_version'                          => '0',
			'max_version'                          => WPCOM_JSON_API__CURRENT_VERSION,
			'force'                                => '',
			'deprecated'                           => false,
			'new_version'                          => WPCOM_JSON_API__CURRENT_VERSION,
			'jp_disabled'                          => false,
			'path_labels'                          => array(),
			'request_format'                       => array(),
			'response_format'                      => array(),
			'query_parameters'                     => array(),
			'version'                              => 'v1',
			'example_request'                      => '',
			'example_request_data'                 => '',
			'example_response'                     => '',
			'required_scope'                       => '',
			'pass_wpcom_user_details'              => false,
			'custom_fields_filtering'              => false,
			'allow_cross_origin_request'           => false,
			'allow_unauthorized_request'           => false,
			'allow_jetpack_site_auth'              => false,
			'allow_upload_token_auth'              => false,
			'allow_fallback_to_jetpack_blog_token' => false,
		);

		$args = wp_parse_args( $args, $defaults );

		$this->in_testing = $args['in_testing'];

		$this->allowed_if_flagged     = $args['allowed_if_flagged'];
		$this->allowed_if_red_flagged = $args['allowed_if_red_flagged'];
		$this->allowed_if_deleted     = $args['allowed_if_deleted'];

		$this->description = $args['description'];
		$this->group       = $args['group'];
		$this->stat        = $args['stat'];
		$this->force       = $args['force'];
		$this->jp_disabled = $args['jp_disabled'];

		$this->method      = $args['method'];
		$this->path        = $args['path'];
		$this->path_labels = $args['path_labels'];
		$this->min_version = $args['min_version'];
		$this->max_version = $args['max_version'];
		$this->deprecated  = $args['deprecated'];
		$this->new_version = $args['new_version'];

		// Ensure max version is not less than min version.
		if ( version_compare( $this->min_version, $this->max_version, '>' ) ) {
			$this->max_version = $this->min_version;
		}

		$this->pass_wpcom_user_details = $args['pass_wpcom_user_details'];
		$this->custom_fields_filtering = (bool) $args['custom_fields_filtering'];

		$this->allow_cross_origin_request           = (bool) $args['allow_cross_origin_request'];
		$this->allow_unauthorized_request           = (bool) $args['allow_unauthorized_request'];
		$this->allow_jetpack_site_auth              = (bool) $args['allow_jetpack_site_auth'];
		$this->allow_upload_token_auth              = (bool) $args['allow_upload_token_auth'];
		$this->allow_fallback_to_jetpack_blog_token = (bool) $args['allow_fallback_to_jetpack_blog_token'];
		$this->require_rewind_auth                  = isset( $args['require_rewind_auth'] ) ? (bool) $args['require_rewind_auth'] : false;

		$this->version = $args['version'];

		$this->required_scope = $args['required_scope'];

		if ( $this->request_format ) {
			$this->request_format = array_filter( array_merge( $this->request_format, $args['request_format'] ) );
		} else {
			$this->request_format = $args['request_format'];
		}

		if ( $this->response_format ) {
			$this->response_format = array_filter( array_merge( $this->response_format, $args['response_format'] ) );
		} else {
			$this->response_format = $args['response_format'];
		}

		if ( false === $args['query_parameters'] ) {
			$this->query = array();
		} elseif ( is_array( $args['query_parameters'] ) ) {
			$this->query = array_filter( array_merge( $this->query, $args['query_parameters'] ) );
		}

		$this->api   = WPCOM_JSON_API::init(); // Auto-add to WPCOM_JSON_API.
		$this->links = WPCOM_JSON_API_Links::getInstance();

		/** Example Request/Response */

		// Examples for endpoint documentation request.
		$this->example_request      = $args['example_request'];
		$this->example_request_data = $args['example_request_data'];
		$this->example_response     = $args['example_response'];

		$this->api->add( $this );
	}

	/**
	 * Get all query args. Prefill with defaults.
	 *
	 * @param bool $return_default_values Whether to include default values in the response.
	 * @param bool $cast_and_filter Whether to cast and filter input according to the documentation.
	 * @return array
	 */
	public function query_args( $return_default_values = true, $cast_and_filter = true ) {
		$args = array_intersect_key( $this->api->query, $this->query );

		if ( ! $cast_and_filter ) {
			return $args;
		}

		return $this->cast_and_filter( $args, $this->query, $return_default_values );
	}

	/**
	 * Get POST body data.
	 *
	 * @param bool $return_default_values Whether to include default values in the response.
	 * @param bool $cast_and_filter Whether to cast and filter input according to the documentation.
	 * @return mixed
	 */
	public function input( $return_default_values = true, $cast_and_filter = true ) {
		$input        = trim( (string) $this->api->post_body );
		$content_type = (string) $this->api->content_type;
		if ( $content_type ) {
			list ( $content_type ) = explode( ';', $content_type );
		}
		$content_type = trim( $content_type );
		switch ( $content_type ) {
			case 'application/json':
			case 'application/x-javascript':
			case 'text/javascript':
			case 'text/x-javascript':
			case 'text/x-json':
			case 'text/json':
				$return = json_decode( $input, true );

				if ( function_exists( 'json_last_error' ) ) {
					if ( JSON_ERROR_NONE !== json_last_error() ) { // phpcs:ignore PHPCompatibility
						return null;
					}
				} elseif ( $return === null && wp_json_encode( null ) !== $input ) {
					return null;
				}

				break;
			case 'multipart/form-data':
				// phpcs:ignore WordPress.Security.NonceVerification.Missing
				$return = array_merge( stripslashes_deep( $_POST ), $_FILES );
				break;
			case 'application/x-www-form-urlencoded':
				// attempt JSON first, since probably a curl command.
				$return = json_decode( $input, true );

				if ( $return === null ) {
					wp_parse_str( $input, $return );
				}

				break;
			default:
				wp_parse_str( $input, $return );
				break;
		}

		if ( isset( $this->api->query['force'] )
			&& 'secure' === $this->api->query['force']
			&& isset( $return['secure_key'] ) ) {
			$this->api->post_body      = $this->get_secure_body( $return['secure_key'] );
			$this->api->query['force'] = false;
			return $this->input( $return_default_values, $cast_and_filter );
		}

		if ( $cast_and_filter ) {
			$return = $this->cast_and_filter( $return, $this->request_format, $return_default_values );
		}
		return $return;
	}

	/**
	 * Fetch a body via secure request.
	 *
	 * @param string $secure_key Key for the request.
	 * @return mixed|null API response, or null if the request failed.
	 */
	protected function get_secure_body( $secure_key ) {
		$response = Client::wpcom_json_api_request_as_blog(
			sprintf( '/sites/%d/secure-request', Jetpack_Options::get_option( 'id' ) ),
			'1.1',
			array( 'method' => 'POST' ),
			array( 'secure_key' => $secure_key )
		);
		if ( 200 !== $response['response']['code'] ) {
			return null;
		}
		return json_decode( $response['body'], true );
	}

	/**
	 * Cast and filter data.
	 *
	 * @param mixed $data Data to cast and filter.
	 * @param array $documentation Documentation for keys in `$data` to keep and cast.
	 * @param bool  $return_default_values Set default values from `$documentation` to process.
	 * @param bool  $for_output See `$this->cast_and_filter_item()`.
	 * @return mixed Filtered data.
	 */
	public function cast_and_filter( $data, $documentation, $return_default_values = false, $for_output = false ) {
		$return_as_object = false;
		if ( is_object( $data ) ) {
			// @todo this should probably be a deep copy if $data can ever have nested objects
			$data             = (array) $data;
			$return_as_object = true;
		} elseif ( ! is_array( $data ) ) {
			return $data;
		}

		$boolean_arg = array( 'false', 'true' );
		$naeloob_arg = array( 'true', 'false' );

		$return = array();

		foreach ( $documentation as $key => $description ) {
			if ( is_array( $description ) ) {
				// String or boolean array keys only.
				$whitelist = array_keys( $description );

				if ( $whitelist === $boolean_arg || $whitelist === $naeloob_arg ) {
					// Truthiness.
					if ( isset( $data[ $key ] ) ) {
						$return[ $key ] = (bool) WPCOM_JSON_API::is_truthy( $data[ $key ] );
					} elseif ( $return_default_values ) {
						$return[ $key ] = $whitelist === $naeloob_arg; // Default to true for naeloob_arg and false for boolean_arg.
					}
				} elseif ( isset( $data[ $key ] ) && isset( $description[ $data[ $key ] ] ) ) {
					// String Key.
					$return[ $key ] = (string) $data[ $key ];
				} elseif ( $return_default_values ) {
					// Default value.
					$return[ $key ] = (string) current( $whitelist );
				}

				continue;
			}

			$types = $this->parse_types( $description );
			$type  = array_shift( $types );

			// Explicit default - string and int only for now.  Always set these reguardless of $return_default_values.
			if ( isset( $type['default'] ) ) {
				if ( ! isset( $data[ $key ] ) ) {
					$data[ $key ] = $type['default'];
				}
			}

			if ( ! isset( $data[ $key ] ) ) {
				continue;
			}

			$this->cast_and_filter_item( $return, $type, $key, $data[ $key ], $types, $for_output );
		}

		if ( $return_as_object ) {
			return (object) $return;
		}

		return $return;
	}

	/**
	 * Casts $value according to $type.
	 * Handles fallbacks for certain values of $type when $value is not that $type
	 * Currently, only handles fallback between string <-> array (two way), from string -> false (one way), and from object -> false (one way),
	 * and string -> object (one way)
	 *
	 * Handles "child types" - array:URL, object:category
	 * array:URL means an array of URLs
	 * object:category means a hash of categories
	 *
	 * Handles object typing - object>post means an object of type post
	 *
	 * @param array        $return Array to assign the value into.
	 * @param string|array $type Type to cast.
	 * @param string|int   $key Key in `$return` to assign the value to.
	 * @param mixed        $value Value to cast.
	 * @param array        $types Fallback types.
	 * @param bool         $for_output Appears to affect formatting of 'date' types.
	 */
	public function cast_and_filter_item( &$return, $type, $key, $value, $types = array(), $for_output = false ) {
		if ( is_string( $type ) ) {
			$type = compact( 'type' );
		}

		switch ( $type['type'] ) {
			case 'false':
				$return[ $key ] = false;
				break;
			case 'url':
				if ( is_object( $value ) && isset( $value->url ) && false !== strpos( $value->url, 'https://videos.files.wordpress.com/' ) ) {
					$value = $value->url;
				}
				// Check for string since esc_url_raw() expects one.
				if ( ! is_string( $value ) ) {
					break;
				}
				$return[ $key ] = (string) esc_url_raw( $value );
				break;
			case 'string':
				// Fallback string -> array, or for string -> object.
				if ( is_array( $value ) || is_object( $value ) ) {
					if ( ! empty( $types[0] ) ) {
						$next_type = array_shift( $types );
						return $this->cast_and_filter_item( $return, $next_type, $key, $value, $types, $for_output );
					}
				}

				// Fallback string -> false.
				if ( ! is_string( $value ) ) {
					if ( ! empty( $types[0] ) && 'false' === $types[0]['type'] ) {
						$next_type = array_shift( $types );
						return $this->cast_and_filter_item( $return, $next_type, $key, $value, $types, $for_output );
					}
				}
				$return[ $key ] = (string) $value;
				break;
			case 'html':
				$return[ $key ] = (string) $value;
				break;
			case 'safehtml':
				$return[ $key ] = wp_kses( (string) $value, wp_kses_allowed_html() );
				break;
			case 'zip':
			case 'media':
				if ( is_array( $value ) ) {
					if ( isset( $value['name'] ) && is_array( $value['name'] ) ) {
						// It's a $_FILES array
						// Reformat into array of $_FILES items.
						$files = array();

						foreach ( $value['name'] as $k => $v ) {
							$files[ $k ] = array();
							foreach ( array_keys( $value ) as $file_key ) {
								$files[ $k ][ $file_key ] = $value[ $file_key ][ $k ];
							}
						}

						$return[ $key ] = $files;
						break;
					}
				}
				// no break - treat as 'array'.
			case 'array':
				// Fallback array -> string.
				if ( is_string( $value ) ) {
					if ( ! empty( $types[0] ) ) {
						$next_type = array_shift( $types );
						return $this->cast_and_filter_item( $return, $next_type, $key, $value, $types, $for_output );
					}
				}

				if ( isset( $type['children'] ) ) {
					$children = array();
					foreach ( (array) $value as $k => $child ) {
						$this->cast_and_filter_item( $children, $type['children'], $k, $child, array(), $for_output );
					}
					$return[ $key ] = (array) $children;
					break;
				}

				$return[ $key ] = (array) $value;
				break;
			case 'iso 8601 datetime':
			case 'datetime':
				// (string)s
				$dates = $this->parse_date( (string) $value );
				if ( $for_output ) {
					$return[ $key ] = $this->format_date( $dates[1], $dates[0] );
				} else {
					list( $return[ $key ], $return[ "{$key}_gmt" ] ) = $dates;
				}
				break;
			case 'float':
				$return[ $key ] = (float) $value;
				break;
			case 'int':
			case 'integer':
				$return[ $key ] = (int) $value;
				break;
			case 'bool':
			case 'boolean':
				$return[ $key ] = (bool) WPCOM_JSON_API::is_truthy( $value );
				break;
			case 'object':
				// Fallback object -> false.
				if ( is_scalar( $value ) || $value === null ) {
					if ( ! empty( $types[0] ) && 'false' === $types[0]['type'] ) {
						return $this->cast_and_filter_item( $return, 'false', $key, $value, $types, $for_output );
					}
				}

				if ( isset( $type['children'] ) ) {
					$children = array();
					foreach ( (array) $value as $k => $child ) {
						$this->cast_and_filter_item( $children, $type['children'], $k, $child, array(), $for_output );
					}
					$return[ $key ] = (object) $children;
					break;
				}

				if ( isset( $type['subtype'] ) ) {
					return $this->cast_and_filter_item( $return, $type['subtype'], $key, $value, $types, $for_output );
				}

				$return[ $key ] = (object) $value;
				break;
			case 'post':
				$return[ $key ] = (object) $this->cast_and_filter( $value, $this->post_object_format, false, $for_output );
				break;
			case 'comment':
				$return[ $key ] = (object) $this->cast_and_filter( $value, $this->comment_object_format, false, $for_output );
				break;
			case 'tag':
			case 'category':
				$docs = array(
					'ID'          => '(int)',
					'name'        => '(string)',
					'slug'        => '(string)',
					'description' => '(HTML)',
					'post_count'  => '(int)',
					'feed_url'    => '(string)',
					'meta'        => '(object)',
				);
				if ( 'category' === $type['type'] ) {
					$docs['parent'] = '(int)';
				}
				$return[ $key ] = (object) $this->cast_and_filter( $value, $docs, false, $for_output );
				break;
			case 'post_reference':
			case 'comment_reference':
				$docs           = array(
					'ID'    => '(int)',
					'type'  => '(string)',
					'title' => '(string)',
					'link'  => '(URL)',
				);
				$return[ $key ] = (object) $this->cast_and_filter( $value, $docs, false, $for_output );
				break;
			case 'geo':
				$docs           = array(
					'latitude'  => '(float)',
					'longitude' => '(float)',
					'address'   => '(string)',
				);
				$return[ $key ] = (object) $this->cast_and_filter( $value, $docs, false, $for_output );
				break;
			case 'author':
				$docs           = array(
					'ID'             => '(int)',
					'user_login'     => '(string)',
					'login'          => '(string)',
					'email'          => '(string|false)',
					'name'           => '(string)',
					'first_name'     => '(string)',
					'last_name'      => '(string)',
					'nice_name'      => '(string)',
					'URL'            => '(URL)',
					'avatar_URL'     => '(URL)',
					'profile_URL'    => '(URL)',
					'is_super_admin' => '(bool)',
					'roles'          => '(array:string)',
					'ip_address'     => '(string|false)',
				);
				$return[ $key ] = (object) $this->cast_and_filter( $value, $docs, false, $for_output );
				break;
			case 'role':
				$docs           = array(
					'name'         => '(string)',
					'display_name' => '(string)',
					'capabilities' => '(object:boolean)',
				);
				$return[ $key ] = (object) $this->cast_and_filter( $value, $docs, false, $for_output );
				break;
			case 'attachment':
				$docs           = array(
					'ID'        => '(int)',
					'URL'       => '(URL)',
					'guid'      => '(string)',
					'mime_type' => '(string)',
					'width'     => '(int)',
					'height'    => '(int)',
					'duration'  => '(int)',
				);
				$return[ $key ] = (object) $this->cast_and_filter(
					$value,
					/**
					* Filter the documentation returned for a post attachment.
					*
					* @module json-api
					*
					* @since 1.9.0
					*
					* @param array $docs Array of documentation about a post attachment.
					*/
					apply_filters( 'wpcom_json_api_attachment_cast_and_filter', $docs ),
					false,
					$for_output
				);
				break;
			case 'metadata':
				$docs           = array(
					'id'             => '(int)',
					'key'            => '(string)',
					'value'          => '(string|false|float|int|array|object)',
					'previous_value' => '(string)',
					'operation'      => '(string)',
				);
				$return[ $key ] = (object) $this->cast_and_filter(
					$value,
					/** This filter is documented in class.json-api-endpoints.php */
					apply_filters( 'wpcom_json_api_attachment_cast_and_filter', $docs ),
					false,
					$for_output
				);
				break;
			case 'plugin':
				$docs           = array(
					'id'           => '(safehtml) The plugin\'s ID',
					'slug'         => '(safehtml) The plugin\'s Slug',
					'active'       => '(boolean)  The plugin status.',
					'update'       => '(object)   The plugin update info.',
					'name'         => '(safehtml) The name of the plugin.',
					'plugin_url'   => '(url)      Link to the plugin\'s web site.',
					'version'      => '(safehtml) The plugin version number.',
					'description'  => '(safehtml) Description of what the plugin does and/or notes from the author',
					'author'       => '(safehtml) The plugin author\'s name',
					'author_url'   => '(url)      The plugin author web site address',
					'network'      => '(boolean)  Whether the plugin can only be activated network wide.',
					'autoupdate'   => '(boolean)  Whether the plugin is auto updated',
					'log'          => '(array:safehtml) An array of update log strings.',
					'action_links' => '(array) An array of action links that the plugin uses.',
				);
				$return[ $key ] = (object) $this->cast_and_filter(
					$value,
					/**
					* Filter the documentation returned for a plugin.
					*
					* @module json-api
					*
					* @since 3.1.0
					*
					* @param array $docs Array of documentation about a plugin.
					*/
					apply_filters( 'wpcom_json_api_plugin_cast_and_filter', $docs ),
					false,
					$for_output
				);
				break;
			case 'plugin_v1_2':
				$docs           = class_exists( 'Jetpack_JSON_API_Get_Plugins_v1_2_Endpoint' )
				? Jetpack_JSON_API_Get_Plugins_v1_2_Endpoint::$_response_format
				: Jetpack_JSON_API_Plugins_Endpoint::$_response_format_v1_2;
				$return[ $key ] = (object) $this->cast_and_filter(
					$value,
					/**
					* Filter the documentation returned for a plugin.
					*
					* @module json-api
					*
					* @since 3.1.0
					*
					* @param array $docs Array of documentation about a plugin.
					*/
					apply_filters( 'wpcom_json_api_plugin_cast_and_filter', $docs ),
					false,
					$for_output
				);
				break;
			case 'file_mod_capabilities':
				$docs           = array(
					'reasons_modify_files_unavailable' => '(array) The reasons why files can\'t be modified',
					'reasons_autoupdate_unavailable'   => '(array) The reasons why autoupdates aren\'t allowed',
					'modify_files'                     => '(boolean) true if files can be modified',
					'autoupdate_files'                 => '(boolean) true if autoupdates are allowed',
				);
				$return[ $key ] = (array) $this->cast_and_filter( $value, $docs, false, $for_output );
				break;
			case 'jetpackmodule':
				$docs           = array(
					'id'          => '(string)   The module\'s ID',
					'active'      => '(boolean)  The module\'s status.',
					'name'        => '(string)   The module\'s name.',
					'description' => '(safehtml) The module\'s description.',
					'sort'        => '(int)      The module\'s display order.',
					'introduced'  => '(string)   The Jetpack version when the module was introduced.',
					'changed'     => '(string)   The Jetpack version when the module was changed.',
					'free'        => '(boolean)  The module\'s Free or Paid status.',
					'module_tags' => '(array)    The module\'s tags.',
					'override'    => '(string)   The module\'s override. Empty if no override, otherwise \'active\' or \'inactive\'',
				);
				$return[ $key ] = (object) $this->cast_and_filter(
					$value,
					/** This filter is documented in class.json-api-endpoints.php */
					apply_filters( 'wpcom_json_api_plugin_cast_and_filter', $docs ),
					false,
					$for_output
				);
				break;
			case 'sharing_button':
				$docs           = array(
					'ID'         => '(string)',
					'name'       => '(string)',
					'URL'        => '(string)',
					'icon'       => '(string)',
					'enabled'    => '(bool)',
					'visibility' => '(string)',
				);
				$return[ $key ] = (array) $this->cast_and_filter( $value, $docs, false, $for_output );
				break;
			case 'sharing_button_service':
				$docs           = array(
					'ID'               => '(string) The service identifier',
					'name'             => '(string) The service name',
					'class_name'       => '(string) Class name for custom style sharing button elements',
					'genericon'        => '(string) The Genericon unicode character for the custom style sharing button icon',
					'preview_smart'    => '(string) An HTML snippet of a rendered sharing button smart preview',
					'preview_smart_js' => '(string) An HTML snippet of the page-wide initialization scripts used for rendering the sharing button smart preview',
				);
				$return[ $key ] = (array) $this->cast_and_filter( $value, $docs, false, $for_output );
				break;
			case 'site_keyring':
				$docs           = array(
					'keyring_id'       => '(int) Keyring ID',
					'service'          => '(string) The service name',
					'external_user_id' => '(string) External user id for the service',
				);
				$return[ $key ] = (array) $this->cast_and_filter( $value, $docs, false, $for_output );
				break;
			case 'taxonomy':
				$docs           = array(
					'name'         => '(string) The taxonomy slug',
					'label'        => '(string) The taxonomy human-readable name',
					'labels'       => '(object) Mapping of labels for the taxonomy',
					'description'  => '(string) The taxonomy description',
					'hierarchical' => '(bool) Whether the taxonomy is hierarchical',
					'public'       => '(bool) Whether the taxonomy is public',
					'capabilities' => '(object) Mapping of current user capabilities for the taxonomy',
				);
				$return[ $key ] = (array) $this->cast_and_filter( $value, $docs, false, $for_output );
				break;
			case 'visibility':
				// This is needed to fix a bug in WPAndroid where `public: "PUBLIC"` is sent in place of `public: 1`.
				if ( 'public' === strtolower( $value ) ) {
					$return[ $key ] = 1;
				} elseif ( 'private' === strtolower( $value ) ) {
					$return[ $key ] = -1;
				} else {
					$return[ $key ] = (int) $value;
				}
				break;
			case 'dropdown_page':
				$return[ $key ] = (array) $this->cast_and_filter( $value, $this->dropdown_page_object_format, false, $for_output );
				break;
			default:
				$method_name = $type['type'] . '_docs';
				if ( method_exists( 'WPCOM_JSON_API_Jetpack_Overrides', $method_name ) ) {
					$docs = WPCOM_JSON_API_Jetpack_Overrides::$method_name();
				}

				if ( ! empty( $docs ) ) {
					$return[ $key ] = (object) $this->cast_and_filter(
						$value,
						/** This filter is documented in class.json-api-endpoints.php */
						apply_filters( 'wpcom_json_api_plugin_cast_and_filter', $docs ),
						false,
						$for_output
					);
				} else {
					// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_trigger_error, WordPress.Security.EscapeOutput.OutputNotEscaped
					trigger_error( "Unknown API casting type {$type['type']}", E_USER_WARNING );
				}
		}
	}

	/**
	 * Parse types from text.
	 *
	 * @param string $text Text.
	 * @return array Types.
	 */
	public function parse_types( $text ) {
		if ( ! preg_match( '#^\(([^)]+)\)#', ltrim( $text ), $matches ) ) {
			return 'none';
		}

		$types  = explode( '|', strtolower( $matches[1] ) );
		$return = array();
		foreach ( $types as $type ) {
			foreach ( array(
				':' => 'children',
				'>' => 'subtype',
				'=' => 'default',
			) as $operator => $meaning ) {
				if ( false !== strpos( $type, $operator ) ) {
					$item     = explode( $operator, $type, 2 );
					$return[] = array(
						'type'   => $item[0],
						$meaning => $item[1],
					);
					continue 2;
				}
			}
			$return[] = compact( 'type' );
		}

		return $return;
	}

	/**
	 * Checks if the endpoint is publicly displayable
	 *
	 * @return bool
	 */
	public function is_publicly_documentable() {
		return '__do_not_document' !== $this->group && true !== $this->in_testing;
	}

	/**
	 * Auto generates documentation based on description, method, path, path_labels, and query parameters.
	 * Echoes HTML.
	 *
	 * @param bool $show_description Whether to show the description.
	 */
	public function document( $show_description = true ) {
		global $wpdb;
		$original_post = isset( $GLOBALS['post'] ) ? $GLOBALS['post'] : 'unset';
		unset( $GLOBALS['post'] );

		$doc = $this->generate_documentation();

		if ( $show_description ) :
			?>
<caption>
	<h1><?php echo wp_kses_post( $doc['method'] ); ?> <?php echo wp_kses_post( $doc['path_labeled'] ); ?></h1>
	<p><?php echo wp_kses_post( $doc['description'] ); ?></p>
</caption>

<?php endif; ?>

		<?php if ( true === $this->deprecated ) { ?>
<p><strong>This endpoint is deprecated in favor of version <?php echo (float) $this->new_version; ?></strong></p>
<?php } ?>

<section class="resource-info">
	<h2 id="apidoc-resource-info">Resource Information</h2>

	<table class="api-doc api-doc-resource-parameters api-doc-resource">

	<thead>
		<tr>
			<th class="api-index-title" scope="column">&nbsp;</th>
			<th class="api-index-title" scope="column">&nbsp;</th>
		</tr>
	</thead>
	<tbody>

		<tr class="api-index-item">
			<th scope="row" class="parameter api-index-item-title">Method</th>
			<td class="type api-index-item-title"><?php echo wp_kses_post( $doc['method'] ); ?></td>
		</tr>

		<tr class="api-index-item">
			<th scope="row" class="parameter api-index-item-title">URL</th>
			<?php
			$version = WPCOM_JSON_API__CURRENT_VERSION;
			if ( ! empty( $this->max_version ) ) {
				$version = $this->max_version;
			}
			?>
			<td class="type api-index-item-title">https://public-api.wordpress.com/rest/v<?php echo (float) $version; ?><?php echo wp_kses_post( $doc['path_labeled'] ); ?></td>
		</tr>

		<tr class="api-index-item">
			<th scope="row" class="parameter api-index-item-title">Requires authentication?</th>
			<?php
			$requires_auth = $wpdb->get_row( $wpdb->prepare( 'SELECT requires_authentication FROM rest_api_documentation WHERE `version` = %s AND `path` = %s AND `method` = %s LIMIT 1', $version, untrailingslashit( $doc['path_labeled'] ), $doc['method'] ) );
			?>
			<td class="type api-index-item-title"><?php echo ( true === (bool) $requires_auth->requires_authentication ? 'Yes' : 'No' ); ?></td>
		</tr>

	</tbody>
	</table>

</section>

		<?php

		foreach ( array(
			'path'     => 'Method Parameters',
			'query'    => 'Query Parameters',
			'body'     => 'Request Parameters',
			'response' => 'Response Parameters',
		) as $doc_section_key => $label ) :
			$doc_section = 'response' === $doc_section_key ? $doc['response']['body'] : $doc['request'][ $doc_section_key ];
			if ( ! $doc_section ) {
				continue;
			}

			$param_label = strtolower( str_replace( ' ', '-', $label ) );
			?>

<section class="<?php echo esc_attr( $param_label ); ?>">

<h2 id="apidoc-<?php echo esc_attr( $doc_section_key ); ?>"><?php echo wp_kses_post( $label ); ?></h2>

<table class="api-doc api-doc-<?php echo esc_attr( $param_label ); ?>-parameters api-doc-<?php echo esc_attr( strtolower( str_replace( ' ', '-', $doc['group'] ) ) ); ?>">

<thead>
	<tr>
		<th class="api-index-title" scope="column">Parameter</th>
		<th class="api-index-title" scope="column">Type</th>
		<th class="api-index-title" scope="column">Description</th>
	</tr>
</thead>
<tbody>

			<?php foreach ( $doc_section as $key => $item ) : ?>

	<tr class="api-index-item">
		<th scope="row" class="parameter api-index-item-title"><?php echo wp_kses_post( $key ); ?></th>
		<td class="type api-index-item-title"><?php echo wp_kses_post( $item['type'] ); // @todo auto-link? ?></td>
		<td class="description api-index-item-body">
				<?php

				$this->generate_doc_description( $item['description'] );

				?>
		</td>
	</tr>

			<?php endforeach; ?>
</tbody>
</table>
</section>
<?php endforeach; ?>

		<?php
		if ( 'unset' !== $original_post ) {
			$GLOBALS['post'] = $original_post; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		}
	}

	/**
	 * `preg_replace_callback` callback to add http_build_query to php content example.
	 *
	 * @todo Is this used anywhere?
	 *
	 * @param array $matches Matches.
	 * @return string
	 */
	public function add_http_build_query_to_php_content_example( $matches ) {
		$trimmed_match = ltrim( $matches[0] );
		$pad           = substr( $matches[0], 0, -1 * strlen( $trimmed_match ) );
		$pad           = ltrim( $pad, ' ' );
		$return        = '  ' . str_replace( "\n", "\n  ", $matches[0] );
		return " http_build_query({$return}{$pad})";
	}

	/**
	 * Recursively generates the <dl>'s to document item descriptions.
	 * Echoes HTML.
	 *
	 * @param string|array $item Post data to output, or an array of key => data mappings.
	 */
	public function generate_doc_description( $item ) {
		if ( is_array( $item ) ) :
			?>

		<dl>
			<?php	foreach ( $item as $description_key => $description_value ) : ?>

			<dt><?php echo wp_kses_post( $description_key . ':' ); ?></dt>
			<dd><?php $this->generate_doc_description( $description_value ); ?></dd>

			<?php	endforeach; ?>

		</dl>

			<?php
		else :
			echo wp_kses_post( $item );
		endif;
	}

	/**
	 * Auto generates documentation based on description, method, path, path_labels, and query parameters.
	 * Echoes HTML.
	 */
	public function generate_documentation() {
		$format       = str_replace( '%d', '%s', $this->path );
		$path_labeled = $format;
		if ( ! empty( $this->path_labels ) ) {
			$path_labeled = vsprintf( $format, array_keys( $this->path_labels ) );
		}
		$boolean_arg = array( 'false', 'true' );
		$naeloob_arg = array( 'true', 'false' );

		$doc = array(
			'description'  => $this->description,
			'method'       => $this->method,
			'path_format'  => $this->path,
			'path_labeled' => $path_labeled,
			'group'        => $this->group,
			'request'      => array(
				'path'  => array(),
				'query' => array(),
				'body'  => array(),
			),
			'response'     => array(
				'body' => array(),
			),
		);

		foreach ( array(
			'path_labels'     => 'path',
			'query'           => 'query',
			'request_format'  => 'body',
			'response_format' => 'body',
		) as $_property => $doc_item ) {
			foreach ( (array) $this->$_property as $key => $description ) {
				if ( is_array( $description ) ) {
					$description_keys = array_keys( $description );
					if ( $boolean_arg === $description_keys || $naeloob_arg === $description_keys ) {
						$type = '(bool)';
					} else {
						$type = '(string)';
					}

					if ( 'response_format' !== $_property ) {
						// hack - don't show "(default)" in response format.
						reset( $description );
						$description_key                 = key( $description );
						$description[ $description_key ] = "(default) {$description[$description_key]}";
					}
				} else {
					$types   = $this->parse_types( $description );
					$type    = array();
					$default = '';

					if ( 'none' === $types ) {
						$types           = array();
						$types[]['type'] = 'none';
					}

					foreach ( $types as $type_array ) {
						$type[] = $type_array['type'];
						if ( isset( $type_array['default'] ) ) {
							$default = $type_array['default'];
							if ( 'string' === $type_array['type'] ) {
								$default = "'$default'";
							}
						}
					}
					$type                  = '(' . join( '|', $type ) . ')';
					list( , $description ) = explode( ')', $description, 2 );
					$description           = trim( $description );
					if ( $default ) {
						$description .= " Default: $default.";
					}
				}

				$item = compact( 'type', 'description' );

				if ( 'response_format' === $_property ) {
					$doc['response'][ $doc_item ][ $key ] = $item;
				} else {
					$doc['request'][ $doc_item ][ $key ] = $item;
				}
			}
		}

		return $doc;
	}

	/**
	 * Can the user view the post?
	 *
	 * @param int $post_id Post ID.
	 * @return bool|WP_Error
	 */
	public function user_can_view_post( $post_id ) {
		$post = get_post( $post_id );
		if ( ! $post || is_wp_error( $post ) ) {
			return false;
		}

		if ( 'inherit' === $post->post_status ) {
			$parent_post     = get_post( $post->post_parent );
			$post_status_obj = get_post_status_object( $parent_post->post_status );
		} else {
			$post_status_obj = get_post_status_object( $post->post_status );
		}

		if ( ! $post_status_obj->public ) {
			if ( is_user_logged_in() ) {
				if ( $post_status_obj->protected ) {
					if ( ! current_user_can( 'edit_post', $post->ID ) ) {
						return new WP_Error( 'unauthorized', 'User cannot view post', 403 );
					}
				} elseif ( $post_status_obj->private ) {
					if ( ! current_user_can( 'read_post', $post->ID ) ) {
						return new WP_Error( 'unauthorized', 'User cannot view post', 403 );
					}
				} elseif ( in_array( $post->post_status, array( 'inherit', 'trash' ), true ) ) {
					if ( ! current_user_can( 'edit_post', $post->ID ) ) {
						return new WP_Error( 'unauthorized', 'User cannot view post', 403 );
					}
				} elseif ( 'auto-draft' === $post->post_status ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedElseif
					// allow auto-drafts.
				} else {
					return new WP_Error( 'unauthorized', 'User cannot view post', 403 );
				}
			} else {
				return new WP_Error( 'unauthorized', 'User cannot view post', 403 );
			}
		}

		if (
			( new Status() )->is_private_site() &&
			/**
			 * Filter access to a specific post.
			 *
			 * @module json-api
			 *
			 * @since 3.4.0
			 *
			 * @param bool current_user_can( 'read_post', $post->ID ) Can the current user access the post.
			 * @param WP_Post $post Post data.
			 */
			! apply_filters(
				'wpcom_json_api_user_can_view_post',
				current_user_can( 'read_post', $post->ID ),
				$post
			)
		) {
			return new WP_Error(
				'unauthorized',
				'User cannot view post',
				array(
					'status_code' => 403,
					'error'       => 'private_blog',
				)
			);
		}

		if ( strlen( $post->post_password ) && ! current_user_can( 'edit_post', $post->ID ) ) {
			return new WP_Error(
				'unauthorized',
				'User cannot view password protected post',
				array(
					'status_code' => 403,
					'error'       => 'password_protected',
				)
			);
		}

		return true;
	}

	/**
	 * Returns author object.
	 *
	 * @param object $author user ID, user row, WP_User object, comment row, post row.
	 * @param bool   $show_email_and_ip output the author's email address and IP address?.
	 *
	 * @return object
	 */
	public function get_author( $author, $show_email_and_ip = false ) {
		$ip_address = isset( $author->comment_author_IP ) ? $author->comment_author_IP : '';

		if ( isset( $author->comment_author_email ) ) {
			$id          = ( isset( $author->user_id ) && $author->user_id ) ? $author->user_id : 0;
			$login       = '';
			$email       = $author->comment_author_email;
			$name        = $author->comment_author;
			$first_name  = '';
			$last_name   = '';
			$url         = $author->comment_author_url;
			$avatar_url  = $this->api->get_avatar_url( $author );
			$profile_url = 'https://en.gravatar.com/' . md5( strtolower( trim( $email ) ) );
			$nice        = '';
			$site_id     = -1;

			// Comment author URLs and Emails are sent through wp_kses() on save, which replaces "&" with "&amp;"
			// "&" is the only email/URL character altered by wp_kses().
			foreach ( array( 'email', 'url' ) as $field ) {
				$$field = str_replace( '&amp;', '&', $$field );
			}
		} else {
			if ( isset( $author->user_id ) && $author->user_id ) {
				$author = $author->user_id;
			} elseif ( isset( $author->user_email ) ) {
				$author = $author->ID;
			} elseif ( isset( $author->post_author ) ) {
				// then $author is a Post Object.
				if ( ! $author->post_author ) {
					return null;
				}
				/**
				 * Filter whether the current site is a Jetpack site.
				 *
				 * @module json-api
				 *
				 * @since 3.3.0
				 *
				 * @param bool false Is the current site a Jetpack site. Default to false.
				 * @param int get_current_blog_id() Blog ID.
				 */
				$is_jetpack = true === apply_filters( 'is_jetpack_site', false, get_current_blog_id() );
				$post_id    = $author->ID;
				if ( $is_jetpack && ( defined( 'IS_WPCOM' ) && IS_WPCOM ) ) {
					$id         = get_post_meta( $post_id, '_jetpack_post_author_external_id', true );
					$email      = get_post_meta( $post_id, '_jetpack_author_email', true );
					$login      = '';
					$name       = get_post_meta( $post_id, '_jetpack_author', true );
					$first_name = '';
					$last_name  = '';
					$url        = '';
					$nice       = '';
				} else {
					$author = $author->post_author;
				}
			}

			if ( ! isset( $id ) ) {
				$user = get_user_by( 'id', $author );
				if ( ! $user || is_wp_error( $user ) ) {
					trigger_error( 'Unknown user', E_USER_WARNING ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_trigger_error

					return null;
				}
				$id         = $user->ID;
				$email      = $user->user_email;
				$login      = $user->user_login;
				$name       = $user->display_name;
				$first_name = $user->first_name;
				$last_name  = $user->last_name;
				$url        = $user->user_url;
				$nice       = $user->user_nicename;
			}
			if ( defined( 'IS_WPCOM' ) && IS_WPCOM && ! $is_jetpack ) {
				$active_blog = get_active_blog_for_user( $id );
				$site_id     = $active_blog->blog_id;
				if ( $site_id > -1 ) {
					$site_visible = (
						-1 !== (int) $active_blog->public ||
						is_private_blog_user( $site_id, get_current_user_id() )
					);
				}
				$profile_url = "https://en.gravatar.com/{$login}";
			} else {
				$profile_url = 'https://en.gravatar.com/' . md5( strtolower( trim( $email ) ) );
				$site_id     = -1;
			}

			$avatar_url = $this->api->get_avatar_url( $email );
		}

		if ( $show_email_and_ip ) {
			$email      = (string) $email;
			$ip_address = (string) $ip_address;
		} else {
			$email      = false;
			$ip_address = false;
		}

		$author = array(
			'ID'          => (int) $id,
			'login'       => (string) $login,
			'email'       => $email, // string|bool.
			'name'        => (string) $name,
			'first_name'  => (string) $first_name,
			'last_name'   => (string) $last_name,
			'nice_name'   => (string) $nice,
			'URL'         => (string) esc_url_raw( $url ),
			'avatar_URL'  => (string) esc_url_raw( $avatar_url ),
			'profile_URL' => (string) esc_url_raw( $profile_url ),
			'ip_address'  => $ip_address, // string|bool.
		);

		if ( $site_id > -1 ) {
			$author['site_ID']      = (int) $site_id;
			$author['site_visible'] = $site_visible;
		}

		return (object) $author;
	}

	/**
	 * Get a media item.
	 *
	 * @param int $media_id Media post ID.
	 * @return object|WP_Error Media item data, or WP_Error.
	 */
	public function get_media_item( $media_id ) {
		$media_item = get_post( $media_id );

		if ( ! $media_item || is_wp_error( $media_item ) ) {
			return new WP_Error( 'unknown_media', 'Unknown Media', 404 );
		}

		$response = array(
			'id'          => (string) $media_item->ID,
			'date'        => (string) $this->format_date( $media_item->post_date_gmt, $media_item->post_date ),
			'parent'      => $media_item->post_parent,
			'link'        => wp_get_attachment_url( $media_item->ID ),
			'title'       => $media_item->post_title,
			'caption'     => $media_item->post_excerpt,
			'description' => $media_item->post_content,
			'metadata'    => wp_get_attachment_metadata( $media_item->ID ),
		);

		if ( defined( 'IS_WPCOM' ) && IS_WPCOM && is_array( $response['metadata'] ) && ! empty( $response['metadata']['file'] ) ) {
			remove_filter( '_wp_relative_upload_path', 'wpcom_wp_relative_upload_path', 10 );
			$response['metadata']['file'] = _wp_relative_upload_path( $response['metadata']['file'] );
			add_filter( '_wp_relative_upload_path', 'wpcom_wp_relative_upload_path', 10, 2 );
		}

		$response['meta'] = (object) array(
			'links' => (object) array(
				'self' => (string) $this->links->get_media_link( $this->api->get_blog_id_for_output(), $media_id ),
				'help' => (string) $this->links->get_media_link( $this->api->get_blog_id_for_output(), $media_id, 'help' ),
				'site' => (string) $this->links->get_site_link( $this->api->get_blog_id_for_output() ),
			),
		);

		return (object) $response;
	}

	/**
	 * Get a v1.1 media item.
	 *
	 * @param int          $media_id Media post ID.
	 * @param WP_Post|null $media_item Media item.
	 * @param string|null  $file File path.
	 * @return object|WP_Error Media item data, or WP_Error.
	 */
	public function get_media_item_v1_1( $media_id, $media_item = null, $file = null ) {

		if ( ! $media_item ) {
			$media_item = get_post( $media_id );
		}

		if ( ! $media_item || is_wp_error( $media_item ) ) {
			return new WP_Error( 'unknown_media', 'Unknown Media', 404 );
		}

		$attachment_file = get_attached_file( $media_item->ID );

		$file      = basename( $attachment_file ? $attachment_file : $file );
		$file_info = pathinfo( $file );
		$ext       = isset( $file_info['extension'] ) ? $file_info['extension'] : null;

		// File operations are handled differently on WordPress.com.
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$attachment_metadata = wp_get_attachment_metadata( $media_item->ID );
			$filesize            = ! empty( $attachment_metadata['filesize'] )
				? $attachment_metadata['filesize']
				: 0;
		} else {
			// For VideoPress videos, $attachment_file is the video URL.
			$filesize = file_exists( $attachment_file )
				? filesize( $attachment_file )
				: 0;
		}

		$response = array(
			'ID'          => $media_item->ID,
			'URL'         => wp_get_attachment_url( $media_item->ID ),
			'guid'        => $media_item->guid,
			'date'        => (string) $this->format_date( $media_item->post_date_gmt, $media_item->post_date ),
			'post_ID'     => $media_item->post_parent,
			'author_ID'   => (int) $media_item->post_author,
			'file'        => $file,
			'mime_type'   => $media_item->post_mime_type,
			'extension'   => $ext,
			'title'       => $media_item->post_title,
			'caption'     => $media_item->post_excerpt,
			'description' => $media_item->post_content,
			'alt'         => get_post_meta( $media_item->ID, '_wp_attachment_image_alt', true ),
			'icon'        => wp_mime_type_icon( $media_item->ID ),
			'size'        => size_format( (int) $filesize, 2 ),
			'thumbnails'  => array(),
		);

		if ( in_array( $ext, array( 'jpg', 'jpeg', 'png', 'gif', 'webp' ), true ) ) {
			$metadata = wp_get_attachment_metadata( $media_item->ID );
			if ( isset( $metadata['height'], $metadata['width'] ) ) {
				$response['height'] = $metadata['height'];
				$response['width']  = $metadata['width'];
			}

			if ( isset( $metadata['sizes'] ) ) {
				/**
				 * Filter the thumbnail sizes available for each attachment ID.
				 *
				 * @module json-api
				 *
				 * @since 3.9.0
				 *
				 * @param array $metadata['sizes'] Array of thumbnail sizes available for a given attachment ID.
				 * @param string $media_id Attachment ID.
				 */
				$sizes = apply_filters( 'rest_api_thumbnail_sizes', $metadata['sizes'], $media_item->ID );
				if ( is_array( $sizes ) ) {
					foreach ( $sizes as $size => $size_details ) {
						$response['thumbnails'][ $size ] = dirname( $response['URL'] ) . '/' . $size_details['file'];
					}
					/**
					 * Filter the thumbnail URLs for attachment files.
					 *
					 * @module json-api
					 *
					 * @since 7.1.0
					 *
					 * @param array $metadata['sizes'] Array with thumbnail sizes as keys and URLs as values.
					 */
					$response['thumbnails'] = apply_filters( 'rest_api_thumbnail_size_urls', $response['thumbnails'] );
				}
			}

			if ( isset( $metadata['image_meta'] ) ) {
				$response['exif'] = $metadata['image_meta'];
			}
		}

		if ( in_array( $ext, array( 'mp3', 'm4a', 'wav', 'ogg' ), true ) ) {
			$metadata           = wp_get_attachment_metadata( $media_item->ID );
			$response['length'] = $metadata['length'];
			$response['exif']   = $metadata;
		}

		$is_video = false;

		if (
			in_array( $ext, array( 'ogv', 'mp4', 'mov', 'wmv', 'avi', 'mpg', '3gp', '3g2', 'm4v' ), true )
			|| 'video/videopress' === $response['mime_type']
		) {
			$is_video = true;
		}

		if ( $is_video ) {
			$metadata = wp_get_attachment_metadata( $media_item->ID );

			if ( isset( $metadata['height'], $metadata['width'] ) ) {
				$response['height'] = $metadata['height'];
				$response['width']  = $metadata['width'];
			}

			if ( isset( $metadata['length'] ) ) {
				$response['length'] = $metadata['length'];
			}

			// add VideoPress info.
			if ( function_exists( 'video_get_info_by_blogpostid' ) ) {
				$info = video_get_info_by_blogpostid( $this->api->get_blog_id_for_output(), $media_item->ID );

				// If we failed to get VideoPress info, but it exists in the meta data (for some reason)
				// then let's use that.
				if ( false === $info && isset( $metadata['videopress'] ) ) {
					$info = (object) $metadata['videopress'];
				}

				if ( isset( $info->rating ) ) {
					$response['rating'] = $info->rating;
				}

				if ( isset( $info->display_embed ) ) {
					$response['display_embed'] = (string) (int) $info->display_embed;
					// If not, default to metadata (for WPCOM).
				} elseif ( isset( $metadata['videopress']['display_embed'] ) ) {
					// We convert it to int then to string so that (bool) false to become "0".
					$response['display_embed'] = (string) (int) $metadata['videopress']['display_embed'];
				}

				if ( isset( $info->allow_download ) ) {
					$response['allow_download'] = (string) (int) $info->allow_download;
				} elseif ( isset( $metadata['videopress']['allow_download'] ) ) {
					// We convert it to int then to string so that (bool) false to become "0".
					$response['allow_download'] = (string) (int) $metadata['videopress']['allow_download'];
				}

				if ( isset( $info->thumbnail_generating ) ) {
					$response['thumbnail_generating'] = (bool) intval( $info->thumbnail_generating );
				} elseif ( isset( $metadata['videopress']['thumbnail_generating'] ) ) {
					$response['thumbnail_generating'] = (bool) intval( $metadata['videopress']['thumbnail_generating'] );
				}

				if ( isset( $info->privacy_setting ) ) {
					$response['privacy_setting'] = (int) $info->privacy_setting;
				} elseif ( isset( $metadata['videopress']['privacy_setting'] ) ) {
					$response['privacy_setting'] = (int) $metadata['videopress']['privacy_setting'];
				}

				$thumbnail_query_data = array();
				if ( function_exists( 'video_is_private' ) && video_is_private( $info ) ) {
					$thumbnail_query_data['metadata_token'] = video_generate_auth_token( $info );
				}

				// Thumbnails.
				if ( function_exists( 'video_format_done' ) && function_exists( 'video_image_url_by_guid' ) ) {
					$response['thumbnails'] = array(
						'fmt_hd'  => '',
						'fmt_dvd' => '',
						'fmt_std' => '',
					);
					foreach ( $response['thumbnails'] as $size => $thumbnail_url ) {
						if ( video_format_done( $info, $size ) ) {
							$response['thumbnails'][ $size ] = \add_query_arg( $thumbnail_query_data, \video_image_url_by_guid( $info->guid, $size ) );
						} else {
							unset( $response['thumbnails'][ $size ] );
						}
					}
				}

				if ( isset( $info->title ) ) {
					$response['title'] = $info->title;
				}

				// If we didn't get VideoPress information (for some reason) then let's
				// not try and include it in the response.
				if ( isset( $info->guid ) ) {
					$response['videopress_guid']            = $info->guid;
					$response['videopress_processing_done'] = true;
					if ( '0000-00-00 00:00:00' === $info->finish_date_gmt ) {
						$response['videopress_processing_done'] = false;
					}
				}
			}
		}

		$response['thumbnails'] = (object) $response['thumbnails'];

		$response['meta'] = (object) array(
			'links' => (object) array(
				'self' => (string) $this->links->get_media_link( $this->api->get_blog_id_for_output(), $media_item->ID ),
				'help' => (string) $this->links->get_media_link( $this->api->get_blog_id_for_output(), $media_item->ID, 'help' ),
				'site' => (string) $this->links->get_site_link( $this->api->get_blog_id_for_output() ),
			),
		);

		// add VideoPress link to the meta.
		if ( isset( $response['videopress_guid'] ) ) {
			if ( function_exists( 'video_get_info_by_blogpostid' ) ) {
				$response['meta']->links->videopress = (string) $this->links->get_link( '/videos/%s', $response['videopress_guid'], '' );
			}
		}

		if ( $media_item->post_parent > 0 ) {
			$response['meta']->links->parent = (string) $this->links->get_post_link( $this->api->get_blog_id_for_output(), $media_item->post_parent );
		}

		return (object) $response;
	}

	/**
	 * Get a formatted taxonomy.
	 *
	 * @param int    $taxonomy_id Taxonomy ID.
	 * @param string $taxonomy_type Name of taxonomy.
	 * @param string $context Context, 'edit' or 'display'.
	 * @return object|WP_Error
	 */
	public function get_taxonomy( $taxonomy_id, $taxonomy_type, $context ) {

		$taxonomy = get_term_by( 'slug', $taxonomy_id, $taxonomy_type );
		// keep updating this function.
		if ( ! $taxonomy || is_wp_error( $taxonomy ) ) {
			return new WP_Error( 'unknown_taxonomy', 'Unknown taxonomy', 404 );
		}

		return $this->format_taxonomy( $taxonomy, $taxonomy_type, $context );
	}

	/**
	 * Format a taxonomy.
	 *
	 * @param WP_Term $taxonomy Taxonomy.
	 * @param string  $taxonomy_type Name of taxonomy.
	 * @param string  $context Context, 'edit' or 'display'.
	 * @return object|WP_Error
	 */
	public function format_taxonomy( $taxonomy, $taxonomy_type, $context ) {
		// Permissions.
		switch ( $context ) {
			case 'edit':
				$tax = get_taxonomy( $taxonomy_type );
				if ( ! current_user_can( $tax->cap->edit_terms ) ) {
					return new WP_Error( 'unauthorized', 'User cannot edit taxonomy', 403 );
				}
				break;
			case 'display':
				if ( ( new Status() )->is_private_site() && ! current_user_can( 'read' ) ) {
					return new WP_Error( 'unauthorized', 'User cannot view taxonomy', 403 );
				}
				break;
			default:
				return new WP_Error( 'invalid_context', 'Invalid API CONTEXT', 400 );
		}

		$response                = array();
		$response['ID']          = (int) $taxonomy->term_id;
		$response['name']        = (string) $taxonomy->name;
		$response['slug']        = (string) $taxonomy->slug;
		$response['description'] = (string) $taxonomy->description;
		$response['post_count']  = (int) $taxonomy->count;
		$response['feed_url']    = get_term_feed_link( $taxonomy->term_id, $taxonomy_type );

		if ( is_taxonomy_hierarchical( $taxonomy_type ) ) {
			$response['parent'] = (int) $taxonomy->parent;
		}

		$response['meta'] = (object) array(
			'links' => (object) array(
				'self' => (string) $this->links->get_taxonomy_link( $this->api->get_blog_id_for_output(), $taxonomy->slug, $taxonomy_type ),
				'help' => (string) $this->links->get_taxonomy_link( $this->api->get_blog_id_for_output(), $taxonomy->slug, $taxonomy_type, 'help' ),
				'site' => (string) $this->links->get_site_link( $this->api->get_blog_id_for_output() ),
			),
		);

		return (object) $response;
	}

	/**
	 * Returns ISO 8601 formatted datetime: 2011-12-08T01:15:36-08:00
	 *
	 * @param string $date_gmt GMT datetime string.
	 * @param string $date Optional. Used to calculate the offset from GMT.
	 * @return string
	 */
	public function format_date( $date_gmt, $date = null ) {
		return WPCOM_JSON_API_Date::format_date( $date_gmt, $date );
	}

	/**
	 * Parses a date string and returns the local and GMT representations
	 * of that date & time in 'YYYY-MM-DD HH:MM:SS' format without
	 * timezones or offsets. If the parsed datetime was not localized to a
	 * particular timezone or offset we will assume it was given in GMT
	 * relative to now and will convert it to local time using either the
	 * timezone set in the options table for the blog or the GMT offset.
	 *
	 * @param datetime string $date_string Date to parse.
	 *
	 * @return array( $local_time_string, $gmt_time_string )
	 */
	public function parse_date( $date_string ) {
		$date_string_info = date_parse( $date_string );
		if ( is_array( $date_string_info ) && 0 === $date_string_info['error_count'] ) {
			// Check if it's already localized. Can't just check is_localtime because date_parse('oppossum') returns true; WTF, PHP.
			if ( isset( $date_string_info['zone'] ) && true === $date_string_info['is_localtime'] ) {
				$dt_utc   = new DateTime( $date_string );
				$dt_local = clone $dt_utc;
				$dt_utc->setTimezone( new DateTimeZone( 'UTC' ) );
				return array(
					(string) $dt_local->format( 'Y-m-d H:i:s' ),
					(string) $dt_utc->format( 'Y-m-d H:i:s' ),
				);
			}

			// It's parseable but no TZ info so assume UTC.
			$dt_utc   = new DateTime( $date_string, new DateTimeZone( 'UTC' ) );
			$dt_local = clone $dt_utc;
		} else {
			// Could not parse time, use now in UTC.
			$dt_utc   = new DateTime( 'now', new DateTimeZone( 'UTC' ) );
			$dt_local = clone $dt_utc;
		}

		$dt_local->setTimezone( wp_timezone() );

		return array(
			(string) $dt_local->format( 'Y-m-d H:i:s' ),
			(string) $dt_utc->format( 'Y-m-d H:i:s' ),
		);
	}

	/**
	 * Load the functions.php file for the current theme to get its post formats, CPTs, etc.
	 */
	public function load_theme_functions() {
		if ( false === defined( 'STYLESHEETPATH' ) ) {
			wp_templating_constants();
		}

		// bail if we've done this already (can happen when calling /batch endpoint).
		if ( defined( 'REST_API_THEME_FUNCTIONS_LOADED' ) ) {
			return;
		}

		// VIP context loading is handled elsewhere, so bail to prevent
		// duplicate loading. See `switch_to_blog_and_validate_user()`.
		if ( defined( 'WPCOM_IS_VIP_ENV' ) && WPCOM_IS_VIP_ENV ) {
			return;
		}

		$do_check_theme =
			defined( 'REST_API_TEST_REQUEST' ) && REST_API_TEST_REQUEST ||
			defined( 'IS_WPCOM' ) && IS_WPCOM;

		if ( $do_check_theme && ! wpcom_should_load_theme_files_on_rest_api() ) {
			return;
		}

		define( 'REST_API_THEME_FUNCTIONS_LOADED', true );

		// the theme info we care about is found either within functions.php or one of the jetpack files.
		$function_files = array( '/functions.php', '/inc/jetpack.compat.php', '/inc/jetpack.php', '/includes/jetpack.compat.php' );

		$copy_dirs = array( get_template_directory() );

		// Is this a child theme? Load the child theme's functions file.
		if ( get_stylesheet_directory() !== get_template_directory() && wpcom_is_child_theme() ) {
			foreach ( $function_files as $function_file ) {
				if ( file_exists( get_stylesheet_directory() . $function_file ) ) {
					require_once get_stylesheet_directory() . $function_file;
				}
			}
			$copy_dirs[] = get_stylesheet_directory();
		}

		foreach ( $function_files as $function_file ) {
			if ( file_exists( get_template_directory() . $function_file ) ) {
				require_once get_template_directory() . $function_file;
			}
		}

		// add inc/wpcom.php and/or includes/wpcom.php.
		wpcom_load_theme_compat_file();

		// Enable including additional directories or files in actions to be copied.
		$copy_dirs = apply_filters( 'restapi_theme_action_copy_dirs', $copy_dirs );

		// since the stuff we care about (CPTS, post formats, are usually on setup or init hooks, we want to load those).
		$this->copy_hooks( 'after_setup_theme', 'restapi_theme_after_setup_theme', $copy_dirs );

		/**
		 * Fires functions hooked onto `after_setup_theme` by the theme for the purpose of the REST API.
		 *
		 * The REST API does not load the theme when processing requests.
		 * To enable theme-based functionality, the API will load the '/functions.php',
		 * '/inc/jetpack.compat.php', '/inc/jetpack.php', '/includes/jetpack.compat.php files
		 * of the theme (parent and child) and copy functions hooked onto 'after_setup_theme' within those files.
		 *
		 * @module json-api
		 *
		 * @since 3.2.0
		 */
		do_action( 'restapi_theme_after_setup_theme' );
		$this->copy_hooks( 'init', 'restapi_theme_init', $copy_dirs );

		/**
		 * Fires functions hooked onto `init` by the theme for the purpose of the REST API.
		 *
		 * The REST API does not load the theme when processing requests.
		 * To enable theme-based functionality, the API will load the '/functions.php',
		 * '/inc/jetpack.compat.php', '/inc/jetpack.php', '/includes/jetpack.compat.php files
		 * of the theme (parent and child) and copy functions hooked onto 'init' within those files.
		 *
		 * @module json-api
		 *
		 * @since 3.2.0
		 */
		do_action( 'restapi_theme_init' );
	}

	/**
	 * Copy hook functions.
	 *
	 * @param string $from_hook Hook to copy from.
	 * @param string $to_hook Hook to copy to.
	 * @param array  $base_paths Only copy hooks defined in the specified paths.
	 */
	public function copy_hooks( $from_hook, $to_hook, $base_paths ) {
		global $wp_filter;
		foreach ( $wp_filter as $hook => $actions ) {

			if ( $from_hook !== $hook ) {
				continue;
			}
			if ( ! has_action( $hook ) ) {
				continue;
			}

			foreach ( $actions as $priority => $callbacks ) {
				foreach ( $callbacks as $callback_data ) {
					$callback = $callback_data['function'];

					// use reflection api to determine filename where function is defined.
					$reflection = $this->get_reflection( $callback );

					if ( false !== $reflection ) {
						$file_name = $reflection->getFileName();
						foreach ( $base_paths as $base_path ) {

							// only copy hooks with functions which are part of the specified files.
							if ( 0 === strpos( $file_name, $base_path ) ) {
								add_action(
									$to_hook,
									$callback_data['function'],
									$priority,
									$callback_data['accepted_args']
								);
							}
						}
					}
				}
			}
		}
	}

	/**
	 * Get a ReflectionMethod or ReflectionFunction for the callback.
	 *
	 * @param callable $callback Callback.
	 * @return ReflectionMethod|ReflectionFunction|false
	 */
	public function get_reflection( $callback ) {
		if ( is_array( $callback ) ) {
			list( $class, $method ) = $callback;
			return new ReflectionMethod( $class, $method );
		}

		if ( is_string( $callback ) && strpos( $callback, '::' ) !== false ) {
			list( $class, $method ) = explode( '::', $callback );
			return new ReflectionMethod( $class, $method );
		}

		if ( method_exists( $callback, '__invoke' ) ) {
			return new ReflectionMethod( $callback, '__invoke' );
		}

		if ( is_string( $callback ) && strpos( $callback, '::' ) === false && function_exists( $callback ) ) {
			return new ReflectionFunction( $callback );
		}

		return false;
	}

	/**
	 * Check whether a user can view or edit a post type.
	 *
	 * @param string $post_type post type to check.
	 * @param string $context   'display' or 'edit'.
	 * @return bool
	 */
	public function current_user_can_access_post_type( $post_type, $context = 'display' ) {
		$post_type_object = get_post_type_object( $post_type );
		if ( ! $post_type_object ) {
			return false;
		}

		switch ( $context ) {
			case 'edit':
				return current_user_can( $post_type_object->cap->edit_posts );
			case 'display':
				return $post_type_object->public || current_user_can( $post_type_object->cap->read_private_posts );
			default:
				return false;
		}
	}

	/**
	 * Is the post type allowed?
	 *
	 * @param string $post_type Post type.
	 * @return bool
	 */
	public function is_post_type_allowed( $post_type ) {
		// if the post type is empty, that's fine, WordPress will default to post.
		if ( empty( $post_type ) ) {
			return true;
		}

		// allow special 'any' type.
		if ( 'any' === $post_type ) {
			return true;
		}

		// check for allowed types.
		if ( in_array( $post_type, $this->_get_whitelisted_post_types(), true ) ) {
			return true;
		}

		$post_type_object = get_post_type_object( $post_type );
		if ( $post_type_object ) {
			if ( ! empty( $post_type_object->show_in_rest ) ) {
				return $post_type_object->show_in_rest;
			}
			if ( ! empty( $post_type_object->publicly_queryable ) ) {
				return $post_type_object->publicly_queryable;
			}
		}

		return ! empty( $post_type_object->public );
	}

	/**
	 * Gets the whitelisted post types that JP should allow access to.
	 *
	 * @return array Whitelisted post types.
	 */
	protected function _get_whitelisted_post_types() { // phpcs:ignore PSR2.Methods.MethodDeclaration.Underscore -- Legacy.
		$allowed_types = array( 'post', 'page', 'revision' );

		/**
		 * Filter the post types Jetpack has access to, and can synchronize with WordPress.com.
		 *
		 * @module json-api
		 *
		 * @since 2.2.3
		 *
		 * @param array $allowed_types Array of whitelisted post types. Default to `array( 'post', 'page', 'revision' )`.
		 */
		$allowed_types = apply_filters( 'rest_api_allowed_post_types', $allowed_types );

		return array_unique( $allowed_types );
	}

	/**
	 * Mobile apps are allowed free video uploads, but limited to 5 minutes in length.
	 *
	 * @param array $media_item the media item to evaluate.
	 *
	 * @return bool true if the media item is a video that was uploaded via the mobile
	 * app that is longer than 5 minutes.
	 */
	public function media_item_is_free_video_mobile_upload_and_too_long( $media_item ) {
		if ( ! $media_item ) {
			return false;
		}

		// Verify file is a video.
		$is_video = preg_match( '@^video/@', $media_item['type'] );
		if ( ! $is_video ) {
			return false;
		}

		// Check if the request is from a mobile app, where we allow free video uploads at limited length.
		if ( ! in_array( $this->api->token_details['client_id'], VIDEOPRESS_ALLOWED_REST_API_CLIENT_IDS, true ) ) {
			return false;
		}

		// We're only worried about free sites.
		require_once WP_CONTENT_DIR . '/admin-plugins/wpcom-billing.php';
		$current_plan = WPCOM_Store_API::get_current_plan( get_current_blog_id() );
		if ( ! $current_plan['is_free'] ) {
			return false;
		}

		// Check if video is longer than 5 minutes.
		$video_meta = wp_read_video_metadata( $media_item['tmp_name'] );
		if (
			false !== $video_meta &&
			isset( $video_meta['length'] ) &&
			5 * MINUTE_IN_SECONDS < $video_meta['length']
		) {
			videopress_log(
				'videopress_app_upload_length_block',
				'Mobile app upload on free site blocked because length was longer than 5 minutes.',
				null,
				null,
				null,
				null,
				array(
					'blog_id' => get_current_blog_id(),
					'user_id' => get_current_user_id(),
				)
			);
			return true;
		}

		return false;
	}

	/**
	 * Handle a v1.1 media creation.
	 *
	 * Only one of $media_files and $media_urls should be non-empty.
	 *
	 * @param array     $media_files File upload data.
	 * @param array     $media_urls URLs to fetch.
	 * @param array     $media_attrs Attributes corresponding to each entry in `$media_files`/`$media_urls`.
	 * @param int|false $force_parent_id Force the parent ID, overriding `$media_attrs[]['parent_id']`.
	 * @return array Two items:
	 *  - media_ids: IDs created, by index in `$media_files`/`$media_urls`.
	 *  - errors: Errors encountered, by index in `$media_files`/`$media_urls`.
	 */
	public function handle_media_creation_v1_1( $media_files, $media_urls, $media_attrs = array(), $force_parent_id = false ) {

		add_filter( 'upload_mimes', array( $this, 'allow_video_uploads' ) );

		$media_ids             = array();
		$errors                = array();
		$user_can_upload_files = current_user_can( 'upload_files' ) || $this->api->is_authorized_with_upload_token();
		$media_attrs           = array_values( $media_attrs ); // reset the keys.
		$i                     = 0;

		if ( ! empty( $media_files ) ) {
			$this->api->trap_wp_die( 'upload_error' );
			foreach ( $media_files as $media_item ) {
				$_FILES['.api.media.item.'] = $media_item;

				if ( ! $user_can_upload_files ) {
					$media_id = new WP_Error( 'unauthorized', 'User cannot upload media.', 403 );
				} elseif ( $this->media_item_is_free_video_mobile_upload_and_too_long( $media_item ) ) {
					$media_id = new WP_Error( 'upload_video_length', 'Video uploads longer than 5 minutes require a paid plan.', 400 );
				} else {
					if ( $force_parent_id ) {
						$parent_id = absint( $force_parent_id );
					} elseif ( ! empty( $media_attrs[ $i ] ) && ! empty( $media_attrs[ $i ]['parent_id'] ) ) {
						$parent_id = absint( $media_attrs[ $i ]['parent_id'] );
					} else {
						$parent_id = 0;
					}
					$media_id = media_handle_upload( '.api.media.item.', $parent_id );
				}
				if ( is_wp_error( $media_id ) ) {
					$errors[ $i ]['file']    = $media_item['name'];
					$errors[ $i ]['error']   = $media_id->get_error_code();
					$errors[ $i ]['message'] = $media_id->get_error_message();
				} else {
					$media_ids[ $i ] = $media_id;
				}

				++$i;
			}
			$this->api->trap_wp_die( null );
			unset( $_FILES['.api.media.item.'] );
		}

		if ( ! empty( $media_urls ) ) {
			foreach ( $media_urls as $url ) {
				if ( ! $user_can_upload_files ) {
					$media_id = new WP_Error( 'unauthorized', 'User cannot upload media.', 403 );
				} else {
					if ( $force_parent_id ) {
						$parent_id = absint( $force_parent_id );
					} elseif ( ! empty( $media_attrs[ $i ] ) && ! empty( $media_attrs[ $i ]['parent_id'] ) ) {
						$parent_id = absint( $media_attrs[ $i ]['parent_id'] );
					} else {
						$parent_id = 0;
					}
					$media_id = $this->handle_media_sideload( $url, $parent_id );
				}
				if ( is_wp_error( $media_id ) ) {
					$errors[ $i ] = array(
						'file'    => $url,
						'error'   => $media_id->get_error_code(),
						'message' => $media_id->get_error_message(),
					);
				} elseif ( ! empty( $media_id ) ) {
					$media_ids[ $i ] = $media_id;
				}

				++$i;
			}
		}

		if ( ! empty( $media_attrs ) ) {
			foreach ( $media_ids as $index => $media_id ) {
				if ( empty( $media_attrs[ $index ] ) ) {
					continue;
				}

				$attrs  = $media_attrs[ $index ];
				$insert = array();

				// Attributes: Title, Caption, Description.

				if ( isset( $attrs['title'] ) ) {
					$insert['post_title'] = $attrs['title'];
				}

				if ( isset( $attrs['caption'] ) ) {
					$insert['post_excerpt'] = $attrs['caption'];
				}

				if ( isset( $attrs['description'] ) ) {
					$insert['post_content'] = $attrs['description'];
				}

				if ( ! empty( $insert ) ) {
					$insert['ID'] = $media_id;
					wp_update_post( (object) $insert );
				}

				// Attributes: Alt.

				if ( isset( $attrs['alt'] ) ) {
					$alt = wp_strip_all_tags( $attrs['alt'], true );
					update_post_meta( $media_id, '_wp_attachment_image_alt', $alt );
				}

				// Attributes: Artist, Album.

				$id3_meta = array();

				foreach ( array( 'artist', 'album' ) as $key ) {
					if ( isset( $attrs[ $key ] ) ) {
						$id3_meta[ $key ] = wp_strip_all_tags( $attrs[ $key ], true );
					}
				}

				if ( ! empty( $id3_meta ) ) {
					// Before updating metadata, ensure that the item is audio.
					$item = $this->get_media_item_v1_1( $media_id );
					if ( 0 === strpos( $item->mime_type, 'audio/' ) ) {
						wp_update_attachment_metadata( $media_id, $id3_meta );
					}
				}

				// Attributes: Meta
				if ( isset( $attrs['meta'] ) && isset( $attrs['meta']['vertical_id'] ) ) {
					update_post_meta( $media_id, 'vertical_id', $attrs['meta']['vertical_id'] );
				}
			}
		}

		return array(
			'media_ids' => $media_ids,
			'errors'    => $errors,
		);
	}

	/**
	 * Handle a media sideload.
	 *
	 * @param string $url URL.
	 * @param int    $parent_post_id Parent post ID.
	 * @param string $type Type.
	 * @return int|WP_Error|false Media post ID, or error, or false if nothing was sideloaded.
	 */
	public function handle_media_sideload( $url, $parent_post_id = 0, $type = 'any' ) {
		if ( ! function_exists( 'download_url' ) || ! function_exists( 'media_handle_sideload' ) ) {
			return false;
		}

		// if we didn't get a URL, let's bail.
		$parsed = wp_parse_url( $url );
		if ( empty( $parsed ) ) {
			return false;
		}

		$tmp = download_url( $url );
		if ( is_wp_error( $tmp ) ) {
			return $tmp;
		}

		// First check to see if we get a mime-type match by file, otherwise, check to
		// see if WordPress supports this file as an image. If neither, then it is not supported.
		if ( ! $this->is_file_supported_for_sideloading( $tmp ) || 'image' === $type && ! file_is_displayable_image( $tmp ) ) {
			@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			return new WP_Error( 'invalid_input', 'Invalid file type.', 403 );
		}

		// emulate a $_FILES entry.
		$file_array = array(
			'name'     => basename( wp_parse_url( $url, PHP_URL_PATH ) ),
			'tmp_name' => $tmp,
		);

		$id = media_handle_sideload( $file_array, $parent_post_id );
		if ( file_exists( $tmp ) ) {
			@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		}

		if ( is_wp_error( $id ) ) {
			return $id;
		}

		if ( ! $id || ! is_int( $id ) ) {
			return false;
		}

		return $id;
	}

	/**
	 * Checks that the mime type of the specified file is among those in a filterable list of mime types.
	 *
	 * @param string $file Path to file to get its mime type.
	 *
	 * @return bool
	 */
	protected function is_file_supported_for_sideloading( $file ) {
		return jetpack_is_file_supported_for_sideloading( $file );
	}

	/**
	 * Filter for `upload_mimes`.
	 *
	 * @param array $mimes Allowed mime types.
	 * @return array Allowed mime types.
	 */
	public function allow_video_uploads( $mimes ) {
		// if we are on Jetpack, bail - Videos are already allowed.
		if ( ! defined( 'IS_WPCOM' ) || ! IS_WPCOM ) {
			return $mimes;
		}

		// extra check that this filter is only ever applied during REST API requests.
		if ( ! defined( 'REST_API_REQUEST' ) || ! REST_API_REQUEST ) {
			return $mimes;
		}

		// bail early if they already have the upgrade..
		if ( wpcom_site_has_videopress() ) {
			return $mimes;
		}

		// lets whitelist to only specific clients right now.
		$clients_allowed_video_uploads = array();
		/**
		 * Filter the list of whitelisted video clients.
		 *
		 * @module json-api
		 *
		 * @since 3.2.0
		 *
		 * @param array $clients_allowed_video_uploads Array of whitelisted Video clients.
		 */
		$clients_allowed_video_uploads = apply_filters( 'rest_api_clients_allowed_video_uploads', $clients_allowed_video_uploads );
		if ( ! in_array( $this->api->token_details['client_id'], $clients_allowed_video_uploads ) ) { // phpcs:ignore WordPress.PHP.StrictInArray.MissingTrueStrict -- Check what types are expected here.
			return $mimes;
		}

		$mime_list = wp_get_mime_types();

		$video_exts = explode( ' ', get_site_option( 'video_upload_filetypes', false, false ) );
		/**
		 * Filter the video filetypes allowed on the site.
		 *
		 * @module json-api
		 *
		 * @since 3.2.0
		 *
		 * @param array $video_exts Array of video filetypes allowed on the site.
		 */
		$video_exts  = apply_filters( 'video_upload_filetypes', $video_exts );
		$video_mimes = array();

		if ( ! empty( $video_exts ) ) {
			foreach ( $video_exts as $ext ) {
				foreach ( $mime_list as $ext_pattern => $mime ) {
					if ( '' !== $ext && strpos( $ext_pattern, $ext ) !== false ) {
						$video_mimes[ $ext_pattern ] = $mime;
					}
				}
			}

			$mimes = array_merge( $mimes, $video_mimes );
		}

		return $mimes;
	}

	/**
	 * Is the current site multi-user?
	 *
	 * @return bool
	 */
	public function is_current_site_multi_user() {
		$users = wp_cache_get( 'site_user_count', 'WPCOM_JSON_API_Endpoint' );
		if ( false === $users ) {
			$user_query = new WP_User_Query(
				array(
					'blog_id' => get_current_blog_id(),
					'fields'  => 'ID',
				)
			);
			$users      = (int) $user_query->get_total();
			wp_cache_set( 'site_user_count', $users, 'WPCOM_JSON_API_Endpoint', DAY_IN_SECONDS );
		}
		return $users > 1;
	}

	/**
	 * Whether cross-origin requests are allowed.
	 *
	 * @return bool
	 */
	public function allows_cross_origin_requests() {
		return 'GET' === $this->method || $this->allow_cross_origin_request;
	}

	/**
	 * Whether unauthorized requests are allowed.
	 *
	 * @param string   $origin Origin.
	 * @param string[] $complete_access_origins Access origins.
	 * @return bool
	 */
	public function allows_unauthorized_requests( $origin, $complete_access_origins ) {
		return 'GET' === $this->method || ( $this->allow_unauthorized_request && in_array( $origin, $complete_access_origins, true ) );
	}

	/**
	 * Whether this endpoint accepts site based authentication for the current request.
	 *
	 * @since 9.1.0
	 *
	 * @return bool true, if Jetpack blog token is used and `allow_jetpack_site_auth` is true,
	 * false otherwise.
	 */
	public function accepts_site_based_authentication() {
		return $this->allow_jetpack_site_auth &&
			$this->api->is_jetpack_authorized_for_site();
	}

	/**
	 * Get platform.
	 *
	 * @return WPORG_Platform
	 */
	public function get_platform() {
		return wpcom_get_sal_platform( $this->api->token_details );
	}

	/**
	 * Allows the endpoint to perform logic to allow it to decide whether-or-not it should force a
	 * response from the WPCOM API, or potentially go to the Jetpack blog.
	 *
	 * Override this method if you want to do something different.
	 *
	 * @param int $blog_id Blog ID.
	 * @return bool
	 */
	public function force_wpcom_request( $blog_id ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return false;
	}

	/**
	 * Get an array of all valid AMP origins for a blog's siteurl.
	 *
	 * @param string $siteurl Origin url of the API request.
	 * @return array
	 */
	public function get_amp_cache_origins( $siteurl ) {
		$host = wp_parse_url( $siteurl, PHP_URL_HOST );

		/*
		 * From AMP docs:
		 * "When possible, the Google AMP Cache will create a subdomain for each AMP document's domain by first converting it
		 * from IDN (punycode) to UTF-8. The caches replaces every - (dash) with -- (2 dashes) and replace every . (dot) with
		 * - (dash). For example, pub.com will map to pub-com.cdn.ampproject.org."
		 */
		if ( function_exists( 'idn_to_utf8' ) ) {
			// The third parameter is set explicitly to prevent issues with newer PHP versions compiled with an old ICU version.
			// phpcs:ignore PHPCompatibility.Constants.RemovedConstants.intl_idna_variant_2003Deprecated, PHPCompatibility.Constants.RemovedConstants.intl_idna_variant_2003DeprecatedRemoved
			$host = idn_to_utf8( $host, IDNA_DEFAULT, defined( 'INTL_IDNA_VARIANT_UTS46' ) ? INTL_IDNA_VARIANT_UTS46 : INTL_IDNA_VARIANT_2003 );
		}
		$subdomain = str_replace( array( '-', '.' ), array( '--', '-' ), $host );
		return array(
			$siteurl,
			// Google AMP Cache (legacy).
			'https://cdn.ampproject.org',
			// Google AMP Cache subdomain.
			sprintf( 'https://%s.cdn.ampproject.org', $subdomain ),
			// Cloudflare AMP Cache.
			sprintf( 'https://%s.amp.cloudflare.com', $subdomain ),
			// Bing AMP Cache.
			sprintf( 'https://%s.bing-amp.com', $subdomain ),
		);
	}

	/**
	 * Return endpoint response
	 *
	 * @param string $path ... determined by ->$path.
	 *
	 * @return array|WP_Error
	 *  falsy: HTTP 500, no response body
	 *  WP_Error( $error_code, $error_message, $http_status_code ): HTTP $status_code, json_encode( array( 'error' => $error_code, 'message' => $error_message ) ) response body
	 *  $data: HTTP 200, json_encode( $data ) response body
	 */
	abstract public function callback( $path = '' );

}

require_once __DIR__ . '/json-endpoints.php';
