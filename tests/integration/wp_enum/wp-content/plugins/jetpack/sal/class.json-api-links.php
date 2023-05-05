<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * WPCOM_JSON_API_Links class.
 *
 * @package automattic/jetpack
 */

require_once __DIR__ . '/../class.json-api.php';

/**
 * Base class for WPCOM_JSON_API_Links.
 */
class WPCOM_JSON_API_Links {

	/**
	 * An instance of the WPCOM_JSON_API.
	 *
	 * @var WPCOM_JSON_API
	 */
	private $api;

	/**
	 * A WPCOM_JSON_API_Links instance.
	 *
	 * @var WPCOM_JSON_API_Links
	 */
	private static $instance;

	/**
	 * An array of the closest supported version of an endpoint to the current endpoint.
	 *
	 * @var array
	 */
	private $closest_endpoint_cache_by_version = array();

	/**
	 * An array including the current api endpoint as well as the max versions found if that endpoint doesn't exist.
	 *
	 * @var array
	 */
	private $matches_by_version = array();

	/**
	 * An array including the cached endpoint path versions.
	 *
	 * @var array
	 */
	private $cache_result = null;

	/**
	 * Creates a new instance of the WPCOM_JSON_API_Links class.
	 *
	 * @return WPCOM_JSON_API_Links
	 */
	public static function getInstance() { // phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * WPCOM_JSON_API_Links constructor.
	 *
	 * Method protected for singleton.
	 */
	protected function __construct() {
		$this->api = WPCOM_JSON_API::init();
	}

	/**
	 * An empty, private __clone method to prohibit cloning of this instance.
	 */
	private function __clone() { }

	/**
	 * Overriding PHP's default __wakeup method to prvent unserializing of the instance, and return an error message.
	 */
	public function __wakeup() {
		die( "Please don't __wakeup WPCOM_JSON_API_Links" );
	}

	/**
	 * Generate a URL to an endpoint
	 *
	 * Used to construct meta links in API responses
	 *
	 * @param mixed ...$args Optional arguments to be appended to URL.
	 * @return string Endpoint URL
	 **/
	public function get_link( ...$args ) {
		$format = array_shift( $args );
		$base   = WPCOM_JSON_API__BASE;

		$path = array_pop( $args );

		if ( $path ) {
			$path = '/' . ltrim( $path, '/' );
			// tack the path onto the end of the format string.
			// have to escape %'s in the path as %% because
			// we're about to pass it through sprintf and we don't
			// want it to see the % as a placeholder.
			$format .= str_replace( '%', '%%', $path );
		}

		// Escape any % in args before using sprintf.
		$escaped_args = array();
		foreach ( $args as $arg_key => $arg_value ) {
			$escaped_args[ $arg_key ] = str_replace( '%', '%%', $arg_value );
		}

		$relative_path = vsprintf( $format, $escaped_args );

		if ( ! wp_startswith( $relative_path, '.' ) ) {
			// Generic version. Match the requested version as best we can.
			$api_version = $this->get_closest_version_of_endpoint( $format, $relative_path );
			$base        = substr( $base, 0, - 1 ) . $api_version;
		}

		// escape any % in the relative path before running it through sprintf again.
		$relative_path = str_replace( '%', '%%', $relative_path );
		// http, WPCOM_JSON_API__BASE, ...    , path.
		// %s  , %s                  , $format, %s.
		return esc_url_raw( sprintf( "https://%s$relative_path", $base ) );
	}

	/**
	 * Generate the /me prefixed endpoint URL
	 *
	 * Used to construct meta links in API responses, specific to WordPress.com user account pages.
	 *
	 * @param string $path Optional path to be appended to the URL.
	 * @return string /me endpoint URL
	 **/
	public function get_me_link( $path = '' ) {
		return $this->get_link( '/me', $path );
	}

	/**
	 * Generate the endpoint URL for taxonomies
	 *
	 * Used to construct meta links in API responses, specific to taxonomies.
	 *
	 * @param int    $blog_id The site's Jetpack blog ID.
	 * @param int    $taxonomy_id The taxonomy ID (for example of the category, tag).
	 * @param string $taxonomy_type The taxonomy type (for example category, tag).
	 * @param string $path Optional path to be appended to the URL.
	 * @return string Endpoint URL including taxonomy information.
	 **/
	public function get_taxonomy_link( $blog_id, $taxonomy_id, $taxonomy_type, $path = '' ) {
		switch ( $taxonomy_type ) {
			case 'category':
				return $this->get_link( '/sites/%d/categories/slug:%s', $blog_id, $taxonomy_id, $path );

			case 'post_tag':
				return $this->get_link( '/sites/%d/tags/slug:%s', $blog_id, $taxonomy_id, $path );

			default:
				return $this->get_link( '/sites/%d/taxonomies/%s/terms/slug:%s', $blog_id, $taxonomy_type, $taxonomy_id, $path );
		}
	}

	/**
	 * Generate the endpoint URL for media links
	 *
	 * Used to construct meta links in API responses, specific to media links.
	 *
	 * @param int    $blog_id The site's Jetpack blog ID.
	 * @param int    $media_id The media item ID.
	 * @param string $path Optional path to be appended to the URL.
	 * @return string Endpoint URL including media information.
	 **/
	public function get_media_link( $blog_id, $media_id, $path = '' ) {
		return $this->get_link( '/sites/%d/media/%d', $blog_id, $media_id, $path );
	}

	/**
	 * Generate the site link endpoint URL
	 *
	 * Used to construct meta links in API responses, specific to /site links.
	 *
	 * @param int    $blog_id The site's Jetpack blog ID.
	 * @param string $path Optional path to be appended to the URL.
	 * @return string Endpoint URL including site information.
	 **/
	public function get_site_link( $blog_id, $path = '' ) {
		return $this->get_link( '/sites/%d', $blog_id, $path );
	}

	/**
	 * Generate the posts endpoint URL
	 *
	 * Used to construct meta links in API responses, specific to posts links.
	 *
	 * @param int    $blog_id The site's Jetpack blog ID.
	 * @param int    $post_id The post ID.
	 * @param string $path Optional path to be appended to the URL.
	 * @return string Endpoint URL including post information.
	 **/
	public function get_post_link( $blog_id, $post_id, $path = '' ) {
		return $this->get_link( '/sites/%d/posts/%d', $blog_id, $post_id, $path );
	}

	/**
	 * Generate the comments endpoint URL
	 *
	 * Used to construct meta links in API responses, specific to comments links.
	 *
	 * @param int    $blog_id The site's Jetpack blog ID.
	 * @param int    $comment_id The comment ID.
	 * @param string $path Optional path to be appended to the URL.
	 * @return string Endpoint URL including comment information.
	 **/
	public function get_comment_link( $blog_id, $comment_id, $path = '' ) {
		return $this->get_link( '/sites/%d/comments/%d', $blog_id, $comment_id, $path );
	}

	/**
	 * Generate the endpoint URL for Publicize connections
	 *
	 * Used to construct meta links in API responses, specific to Publicize connections.
	 *
	 * @param int    $blog_id The site's Jetpack blog ID.
	 * @param int    $publicize_connection_id The ID of the Publicize connection.
	 * @param string $path Optional path to be appended to the URL.
	 * @return string Endpoint URL including Publicize connection information.
	 **/
	public function get_publicize_connection_link( $blog_id, $publicize_connection_id, $path = '' ) {
		return $this->get_link( '.1/sites/%d/publicize-connections/%d', $blog_id, $publicize_connection_id, $path );
	}

	/**
	 * Generate the endpoint URL for a single Publicize connection including a Keyring connection
	 *
	 * Used to construct meta links in API responses, specific to a single Publicize and Keyring connection.
	 *
	 * @param int    $keyring_token_id The ID of the Keyring connection.
	 * @param string $path Optional path to be appended to the URL.
	 * @return string Endpoint URL including specific Keyring connection information for a specific Publicize connection.
	 **/
	public function get_publicize_connections_link( $keyring_token_id, $path = '' ) {
		return $this->get_link( '.1/me/publicize-connections/?keyring_connection_ID=%d', $keyring_token_id, $path );
	}

	/**
	 * Generate the endpoint URL for a single Keyring connection
	 *
	 * Used to construct meta links in API responses, specific to a Keyring connections.
	 *
	 * @param int    $keyring_token_id The ID of the Keyring connection.
	 * @param string $path Optional path to be appended to the URL.
	 * @return string Endpoint URL including specific Keyring connection.
	 **/
	public function get_keyring_connection_link( $keyring_token_id, $path = '' ) {
		return $this->get_link( '.1/me/keyring-connections/%d', $keyring_token_id, $path );
	}

	/**
	 * Generate the endpoint URL for an external service that can be integrated with via Keyring
	 *
	 * Used to construct meta links in API responses, specific to an external service.
	 *
	 * @param int    $external_service The ID of the external service.
	 * @param string $path Optional path to be appended to the URL.
	 * @return string Endpoint URL including information about an external service that WordPress.com or Jetpack sites can integrate with via keyring.
	 **/
	public function get_external_service_link( $external_service, $path = '' ) {
		return $this->get_link( '.1/meta/external-services/%s', $external_service, $path );
	}

	/**
	 * Try to find the closest supported version of an endpoint to the current endpoint
	 *
	 * For example, if we were looking at the path /animals/panda:
	 * - if the current endpoint is v1.3 and there is a v1.3 of /animals/%s available, we return 1.3
	 * - if the current endpoint is v1.3 and there is no v1.3 of /animals/%s known, we fall back to the
	 *   maximum available version of /animals/%s, e.g. 1.1
	 *
	 * This method is used in get_link() to construct meta links for API responses.
	 *
	 * @param string $template_path The generic endpoint path, e.g. /sites/%s .
	 * @param string $path The current endpoint path, relative to the version, e.g. /sites/12345 .
	 * @param string $request_method Request method used to access the endpoint path .
	 * @return string The current version, or otherwise the maximum version available
	 */
	public function get_closest_version_of_endpoint( $template_path, $path, $request_method = 'GET' ) {
		$closest_endpoint_cache_by_version = & $this->closest_endpoint_cache_by_version;

		$closest_endpoint_cache = & $closest_endpoint_cache_by_version[ $this->api->version ];
		if ( ! $closest_endpoint_cache ) {
			$closest_endpoint_cache_by_version[ $this->api->version ] = array();
			$closest_endpoint_cache                                   = & $closest_endpoint_cache_by_version[ $this->api->version ];
		}

		if ( ! isset( $closest_endpoint_cache[ $template_path ] ) ) {
			$closest_endpoint_cache[ $template_path ] = array();
		} elseif ( isset( $closest_endpoint_cache[ $template_path ][ $request_method ] ) ) {
			return $closest_endpoint_cache[ $template_path ][ $request_method ];
		}

		$path = untrailingslashit( $path );

		// /help is a special case - always use the current request version
		if ( wp_endswith( $path, '/help' ) ) {
			$closest_endpoint_cache[ $template_path ][ $request_method ] = $this->api->version;
			return $this->api->version;
		}

		$matches_by_version = & $this->matches_by_version;

		// try to match out of saved matches.
		if ( ! isset( $matches_by_version[ $this->api->version ] ) ) {
			$matches_by_version[ $this->api->version ] = array();
		}
		foreach ( $matches_by_version[ $this->api->version ] as $match ) {
			$regex = $match->regex;
			if ( preg_match( "#^$regex\$#", $path ) ) {
				$closest_endpoint_cache[ $template_path ][ $request_method ] = $match->version;
				return $match->version;
			}
		}

		$endpoint_path_versions = $this->get_endpoint_path_versions();
		$last_path_segment      = $this->get_last_segment_of_relative_path( $path );
		$max_version_found      = null;

		foreach ( $endpoint_path_versions as $endpoint_last_path_segment => $endpoints ) {

			// Does the last part of the path match the path key? (e.g. 'posts')
			// If the last part contains a placeholder (e.g. %s), we want to carry on.
			// phpcs:ignore Universal.Operators.StrictComparisons.LooseNotEqual
			if ( $last_path_segment != $endpoint_last_path_segment && ! strstr( $endpoint_last_path_segment, '%' ) ) {
				continue;
			}

			foreach ( $endpoints as $endpoint ) {
				// Does the request method match?
				if ( ! in_array( $request_method, $endpoint['request_methods'], true ) ) {
					continue;
				}

				$endpoint_path       = untrailingslashit( $endpoint['path'] );
				$endpoint_path_regex = str_replace( array( '%s', '%d' ), array( '([^/?&]+)', '(\d+)' ), $endpoint_path );

				if ( ! preg_match( "#^$endpoint_path_regex\$#", $path ) ) {
					continue;
				}

				// Make sure the endpoint exists at the same version.
				if ( null !== $this->api->version &&
					version_compare( $this->api->version, $endpoint['min_version'], '>=' ) &&
					version_compare( $this->api->version, $endpoint['max_version'], '<=' )
				) {
					array_push(
						$matches_by_version[ $this->api->version ],
						(object) array(
							'version' => $this->api->version,
							'regex'   => $endpoint_path_regex,
						)
					);
					$closest_endpoint_cache[ $template_path ][ $request_method ] = $this->api->version;
					return $this->api->version;
				}

				// If the endpoint doesn't exist at the same version, record the max version we found.
				if ( empty( $max_version_found ) || version_compare( $max_version_found['version'], $endpoint['max_version'], '<' ) ) {
					$max_version_found = array(
						'version' => $endpoint['max_version'],
						'regex'   => $endpoint_path_regex,
					);
				}
			}
		}

		// If the endpoint version is less than the requested endpoint version, return the max version found.
		if ( ! empty( $max_version_found ) ) {
			array_push(
				$matches_by_version[ $this->api->version ],
				(object) $max_version_found
			);
			$closest_endpoint_cache[ $template_path ][ $request_method ] = $max_version_found['version'];
			return $max_version_found['version'];
		}

		// Otherwise, use the API version of the current request.
		return $this->api->version;
	}

	/**
	 * Get an array of endpoint paths with their associated versions
	 *
	 * @return array Array of endpoint paths, min_versions and max_versions, keyed by last segment of path
	 **/
	protected function get_endpoint_path_versions() {

		if ( ! empty( $this->cache_result ) ) {
			return $this->cache_result;
		}

		/*
		 * Create a map of endpoints and their min/max versions keyed by the last segment of the path (e.g. 'posts')
		 * This reduces the search space when finding endpoint matches in get_closest_version_of_endpoint()
		 */
		$endpoint_path_versions = array();

		foreach ( $this->api->endpoints as $key => $endpoint_objects ) {

			// @todo As with the todo in class.json-api.php, we need to determine if anything depends on this being serialized and hence unserialized, rather than e.g. JSON.
			// The key contains a serialized path, min_version and max_version.
			list( $path, $min_version, $max_version ) = unserialize( $key );         // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_unserialize -- Legacy, see serialization at class.json-api.php.

			// Grab the last component of the relative path to use as the top-level key.
			$last_path_segment = $this->get_last_segment_of_relative_path( $path );

			$endpoint_path_versions[ $last_path_segment ][] = array(
				'path'            => $path,
				'min_version'     => $min_version,
				'max_version'     => $max_version,
				'request_methods' => array_keys( $endpoint_objects ),
			);
		}

		$this->cache_result = $endpoint_path_versions;

		return $endpoint_path_versions;
	}

	/**
	 * Grab the last segment of a relative path
	 *
	 * @param string $path Path.
	 * @return string Last path segment
	 */
	protected function get_last_segment_of_relative_path( $path ) {
		$path_parts = array_filter( explode( '/', $path ) );

		if ( empty( $path_parts ) ) {
			return null;
		}

		return end( $path_parts );
	}
}
