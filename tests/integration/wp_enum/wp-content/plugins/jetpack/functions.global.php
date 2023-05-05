<?php
/**
 * This file is meant to be the home for any generic & reusable functions
 * that can be accessed anywhere within Jetpack.
 *
 * This file is loaded whether Jetpack is active.
 *
 * Please namespace with jetpack_
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\Redirect;
use Automattic\Jetpack\Status\Host;
use Automattic\Jetpack\Sync\Functions;

/**
 * Disable direct access.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once __DIR__ . '/functions.is-mobile.php';

/**
 * Hook into Core's _deprecated_function
 * Add more details about when a deprecated function will be removed.
 *
 * @since 8.8.0
 *
 * @param string $function    The function that was called.
 * @param string $replacement Optional. The function that should have been called. Default null.
 * @param string $version     The version of Jetpack that deprecated the function.
 */
function jetpack_deprecated_function( $function, $replacement, $version ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
	// Bail early for non-Jetpack deprecations.
	if ( 0 !== strpos( $version, 'jetpack-' ) ) {
		return;
	}

	// Look for when a function will be removed based on when it was deprecated.
	$removed_version = jetpack_get_future_removed_version( $version );

	// If we could find a version, let's log a message about when removal will happen.
	if (
		! empty( $removed_version )
		&& ( defined( 'WP_DEBUG' ) && WP_DEBUG )
		/** This filter is documented in core/src/wp-includes/functions.php */
		&& apply_filters( 'deprecated_function_trigger_error', true )
	) {
		error_log( // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			sprintf(
				/* Translators: 1. Function name. 2. Jetpack version number. */
				__( 'The %1$s function will be removed from the Jetpack plugin in version %2$s.', 'jetpack' ),
				$function,
				$removed_version
			)
		);

	}
}
add_action( 'deprecated_function_run', 'jetpack_deprecated_function', 10, 3 );

/**
 * Hook into Core's _deprecated_file
 * Add more details about when a deprecated file will be removed.
 *
 * @since 8.8.0
 *
 * @param string $file        The file that was called.
 * @param string $replacement The file that should have been included based on ABSPATH.
 * @param string $version     The version of WordPress that deprecated the file.
 * @param string $message     A message regarding the change.
 */
function jetpack_deprecated_file( $file, $replacement, $version, $message ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
	// Bail early for non-Jetpack deprecations.
	if ( 0 !== strpos( $version, 'jetpack-' ) ) {
		return;
	}

	// Look for when a file will be removed based on when it was deprecated.
	$removed_version = jetpack_get_future_removed_version( $version );

	// If we could find a version, let's log a message about when removal will happen.
	if (
		! empty( $removed_version )
		&& ( defined( 'WP_DEBUG' ) && WP_DEBUG )
		/** This filter is documented in core/src/wp-includes/functions.php */
		&& apply_filters( 'deprecated_file_trigger_error', true )
	) {
		error_log( // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			sprintf(
				/* Translators: 1. File name. 2. Jetpack version number. */
				__( 'The %1$s file will be removed from the Jetpack plugin in version %2$s.', 'jetpack' ),
				$file,
				$removed_version
			)
		);

	}
}
add_action( 'deprecated_file_included', 'jetpack_deprecated_file', 10, 4 );

/**
 * Get the major version number of Jetpack 6 months after provided version.
 * Useful to indicate when a deprecated function will be removed from Jetpack.
 *
 * @since 8.8.0
 *
 * @param string $version The version of WordPress that deprecated the function.
 *
 * @return bool|float Return a Jetpack Major version number, or false.
 */
function jetpack_get_future_removed_version( $version ) {
	/*
	 * Extract the version number from a deprecation notice.
	 * (let's only keep the first decimal, e.g. 8.8 and not 8.8.0)
	 */
	preg_match( '#(([0-9]+\.([0-9]+))(?:\.[0-9]+)*)#', $version, $matches );

	if ( isset( $matches[2], $matches[3] ) ) {
		$deprecated_version = (float) $matches[2];
		$deprecated_minor   = (float) $matches[3];

		/*
		 * If the detected minor version number
		 * (e.g. "7" in "8.7")
		 * is higher than 9, we know the version number is malformed.
		 * Jetpack does not use semver yet.
		 * Bail.
		 */
		if ( 10 <= $deprecated_minor ) {
			return false;
		}

		// We'll remove the function from the code 6 months later, thus 6 major versions later.
		$removed_version = $deprecated_version + 0.6;

		return (float) $removed_version;
	}

	return false;
}

/**
 * Determine if this site is an WoA site or not by looking for presence of the wpcomsh plugin.
 *
 * @since 4.8.1
 * @deprecated 10.3.0
 *
 * @return bool
 */
function jetpack_is_atomic_site() {
	jetpack_deprecated_function( __FUNCTION__, 'Automattic/Jetpack/Status/Host::is_woa_site', 'jetpack-10.3.0' );
	return ( new Host() )->is_woa_site();
}

/**
 * Register post type for migration.
 *
 * @since 5.2
 */
function jetpack_register_migration_post_type() {
	register_post_type(
		'jetpack_migration',
		array(
			'supports'     => array(),
			'taxonomies'   => array(),
			'hierarchical' => false,
			'public'       => false,
			'has_archive'  => false,
			'can_export'   => true,
		)
	);
}

/**
 * Checks whether the Post DB threat currently exists on the site.
 *
 * @since 12.0
 *
 * @param string $option_name  Option name.
 *
 * @return WP_Post|bool
 */
function jetpack_migration_post_exists( $option_name ) {
	$query = new WP_Query(
		array(
			'post_type'              => 'jetpack_migration',
			'title'                  => $option_name,
			'post_status'            => 'all',
			'posts_per_page'         => 1,
			'no_found_rows'          => true,
			'ignore_sticky_posts'    => true,
			'update_post_term_cache' => false,
			'update_post_meta_cache' => false,
			'orderby'                => 'post_date ID',
			'order'                  => 'ASC',
		)
	);
	if ( ! empty( $query->post ) ) {
		return $query->post;
	}

	return false;
}

/**
 * Stores migration data in the database.
 *
 * @since 5.2
 *
 * @param string $option_name  Option name.
 * @param bool   $option_value Option value.
 *
 * @return int|WP_Error
 */
function jetpack_store_migration_data( $option_name, $option_value ) {
	jetpack_register_migration_post_type();

	$insert = array(
		'post_title'            => $option_name,
		'post_content_filtered' => $option_value,
		'post_type'             => 'jetpack_migration',
		'post_date'             => gmdate( 'Y-m-d H:i:s', time() ),
	);

	$migration_post = jetpack_migration_post_exists( $option_name );
	if ( $migration_post ) {
		$insert['ID'] = $migration_post->ID;
	}

	return wp_insert_post( $insert, true );
}

/**
 * Retrieves legacy image widget data.
 *
 * @since 5.2
 *
 * @param string $option_name Option name.
 *
 * @return mixed|null
 */
function jetpack_get_migration_data( $option_name ) {
	$post = jetpack_migration_post_exists( $option_name );

	return null !== $post ? maybe_unserialize( $post->post_content_filtered ) : null;
}

/**
 * Prints a TOS blurb used throughout the connection prompts.
 *
 * Note: custom ToS messages are also defined in Jetpack_Pre_Connection_JITMs->get_raw_messages()
 *
 * @since 5.3
 *
 * @echo string
 */
function jetpack_render_tos_blurb() {
	printf(
		wp_kses(
			/* Translators: placeholders are links. */
			__( 'By clicking the <strong>Set up Jetpack</strong> button, you agree to our <a href="%1$s" target="_blank" rel="noopener noreferrer">Terms of Service</a> and to <a href="%2$s" target="_blank" rel="noopener noreferrer">share details</a> with WordPress.com.', 'jetpack' ),
			array(
				'a'      => array(
					'href'   => array(),
					'target' => array(),
					'rel'    => array(),
				),
				'strong' => true,
			)
		),
		esc_url( Redirect::get_url( 'wpcom-tos' ) ),
		esc_url( Redirect::get_url( 'jetpack-support-what-data-does-jetpack-sync' ) )
	);
}

/**
 * Intervene upgrade process so Jetpack themes are downloaded with credentials.
 *
 * @since 5.3
 *
 * @param bool   $preempt Whether to preempt an HTTP request's return value. Default false.
 * @param array  $r       HTTP request arguments.
 * @param string $url     The request URL.
 *
 * @return array|bool|WP_Error
 */
function jetpack_theme_update( $preempt, $r, $url ) {
	if ( 0 === stripos( $url, JETPACK__WPCOM_JSON_API_BASE . '/rest/v1/themes/download' ) ) {
		$file = $r['filename'];
		if ( ! $file ) {
			return new WP_Error( 'problem_creating_theme_file', esc_html__( 'Problem creating file for theme download', 'jetpack' ) );
		}
		$theme = pathinfo( wp_parse_url( $url, PHP_URL_PATH ), PATHINFO_FILENAME );

		// Remove filter to avoid endless loop since wpcom_json_api_request_as_blog uses this too.
		remove_filter( 'pre_http_request', 'jetpack_theme_update' );
		$result = Client::wpcom_json_api_request_as_blog(
			"themes/download/$theme.zip",
			'1.1',
			array(
				'stream'   => true,
				'filename' => $file,
			)
		);

		if ( 200 !== wp_remote_retrieve_response_code( $result ) ) {
			return new WP_Error( 'problem_fetching_theme', esc_html__( 'Problem downloading theme', 'jetpack' ) );
		}
		return $result;
	}
	return $preempt;
}

/**
 * Add the filter when a upgrade is going to be downloaded.
 *
 * @since 5.3
 *
 * @param bool $reply Whether to bail without returning the package. Default false.
 *
 * @return bool
 */
function jetpack_upgrader_pre_download( $reply ) {
	add_filter( 'pre_http_request', 'jetpack_theme_update', 10, 3 );
	return $reply;
}

add_filter( 'upgrader_pre_download', 'jetpack_upgrader_pre_download' );

/**
 * Wraps data in a way so that we can distinguish between objects and array and also prevent object recursion.
 *
 * @since 6.1.0

 * @deprecated Automattic\Jetpack\Sync\Functions::json_wrap
 *
 * @param array|obj $any        Source data to be cleaned up.
 * @param array     $seen_nodes Built array of nodes.
 *
 * @return array
 */
function jetpack_json_wrap( &$any, $seen_nodes = array() ) {
	_deprecated_function( __METHOD__, 'jetpack-9.5', 'Automattic\Jetpack\Sync\Functions' );

	return Functions::json_wrap( $any, $seen_nodes );
}

/**
 * Checks if the mime_content_type function is available and return it if so.
 *
 * The function mime_content_type is enabled by default in PHP, but can be disabled. We attempt to
 * enforce this via composer.json, but that won't be checked in majority of cases where
 * this would be happening.
 *
 * @since 7.8.0
 *
 * @param string $file File location.
 *
 * @return string|false MIME type or false if functionality is not available.
 */
function jetpack_mime_content_type( $file ) {
	if ( function_exists( 'mime_content_type' ) ) {
		return mime_content_type( $file );
	}

	return false;
}

/**
 * Checks that the mime type of the specified file is among those in a filterable list of mime types.
 *
 * @since 7.8.0
 *
 * @param string $file Path to file to get its mime type.
 *
 * @return bool
 */
function jetpack_is_file_supported_for_sideloading( $file ) {
	$type = jetpack_mime_content_type( $file );

	if ( ! $type ) {
		return false;
	}

	/**
	 * Filter the list of supported mime types for media sideloading.
	 *
	 * @since 4.0.0
	 *
	 * @module json-api
	 *
	 * @param array $supported_mime_types Array of the supported mime types for media sideloading.
	 */
	$supported_mime_types = apply_filters(
		'jetpack_supported_media_sideload_types',
		array(
			'image/png',
			'image/jpeg',
			'image/gif',
			'image/bmp',
			'image/webp',
			'video/quicktime',
			'video/mp4',
			'video/mpeg',
			'video/ogg',
			'video/3gpp',
			'video/3gpp2',
			'video/h261',
			'video/h262',
			'video/h264',
			'video/x-msvideo',
			'video/x-ms-wmv',
			'video/x-ms-asf',
		)
	);

	// If the type returned was not an array as expected, then we know we don't have a match.
	if ( ! is_array( $supported_mime_types ) ) {
		return false;
	}

	return in_array( $type, $supported_mime_types, true );
}

/**
 * Go through headers and get a list of Vary headers to add,
 * including a Vary Accept header if necessary.
 *
 * @since 12.2-a.0
 *
 * @param array $headers The headers to be sent.
 *
 * @return array $vary_header_parts Vary Headers to be sent.
 */
function jetpack_get_vary_headers( $headers = array() ) {
	$vary_header_parts = array( 'accept', 'content-type' );

	foreach ( $headers as $header ) {
		// Check for a Vary header.
		if ( 'vary:' !== substr( strtolower( $header ), 0, 5 ) ) {
			continue;
		}

		// If the header is a wildcard, we'll return that.
		if ( false !== strpos( $header, '*' ) ) {
			$vary_header_parts = array( '*' );
			break;
		}

		// Remove the Vary: part of the header.
		$header = preg_replace( '/^vary\:\s?/i', '', $header );

		// Remove spaces from the header.
		$header = str_replace( ' ', '', $header );

		// Break the header into parts.
		$header_parts = explode( ',', strtolower( $header ) );

		// Build an array with the Accept header and what was already there.
		$vary_header_parts = array_values( array_unique( array_merge( $vary_header_parts, $header_parts ) ) );
	}

	return $vary_header_parts;
}

/**
 * Determine whether the current request is for accessing the frontend.
 * Also update Vary headers to indicate that the response may vary by Accept header.
 *
 * @return bool True if it's a frontend request, false otherwise.
 */
function jetpack_is_frontend() {
	$is_frontend        = true;
	$is_varying_request = true;

	if (
		is_admin()
		|| wp_doing_ajax()
		|| wp_is_jsonp_request()
		|| is_feed()
		|| ( defined( 'REST_REQUEST' ) && REST_REQUEST )
		|| ( defined( 'REST_API_REQUEST' ) && REST_API_REQUEST )
		|| ( defined( 'WP_CLI' ) && WP_CLI )
	) {
		$is_frontend        = false;
		$is_varying_request = false;
	} elseif (
		wp_is_json_request()
		|| wp_is_xml_request()
	) {
		$is_frontend = false;
	}

	/*
	 * Check existing headers for the request.
	 * If there is no existing Vary Accept header, add one.
	 */
	if ( $is_varying_request && ! headers_sent() ) {
		$headers           = headers_list();
		$vary_header_parts = jetpack_get_vary_headers( $headers );

		header( 'Vary: ' . implode( ', ', $vary_header_parts ) );
	}

	/**
	 * Filter whether the current request is for accessing the frontend.
	 *
	 * @since  9.0.0
	 *
	 * @param bool $is_frontend Whether the current request is for accessing the frontend.
	 */
	return (bool) apply_filters( 'jetpack_is_frontend', $is_frontend );
}

/**
 * Build a list of Mastodon instance hosts.
 * That list can be extended via a filter.
 *
 * @since 11.8
 *
 * @return array
 */
function jetpack_mastodon_get_instance_list() {
	$mastodon_instance_list = array(
		// Regex pattern to match any .tld for the mastodon host name.
		'#https?:\/\/(www\.)?mastodon\.(\w+)(\.\w+)?#',
		// Regex pattern to match any .tld for the mstdn host name.
		'#https?:\/\/(www\.)?mstdn\.(\w+)(\.\w+)?#',
		'counter.social',
		'fosstodon.org',
		'gc2.jp',
		'hachyderm.io',
		'infosec.exchange',
		'mas.to',
		'pawoo.net',
	);

	/**
	 * Filter the list of Mastodon instances.
	 *
	 * @since 11.8
	 *
	 * @module widgets, theme-tools
	 *
	 * @param array $mastodon_instance_list Array of Mastodon instances.
	 */
	return (array) apply_filters( 'jetpack_mastodon_instance_list', $mastodon_instance_list );
}
