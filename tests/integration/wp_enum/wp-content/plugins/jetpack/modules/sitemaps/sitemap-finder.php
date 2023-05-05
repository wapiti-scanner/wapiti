<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * The functions in this class provide an API for handling
 * sitemap related URIs.
 *
 * @package automattic/jetpack
 * @since 4.8.0
 * @author Automattic
 */

/**
 * The Jetpack_Sitemap_Finder object deals with constructing
 * sitemap URIs.
 *
 * @since 4.8.0
 */
class Jetpack_Sitemap_Finder {

	/**
	 * Construct the complete URL of a sitemap file. Depends on
	 * permalink settings.
	 *
	 * @access public
	 * @since 4.8.0
	 * @since 4.8.1 Call jetpack_sitemap_uri()
	 *
	 * @param string $filename The filename of the sitemap.
	 *
	 * @return string Complete URI of the given sitemap file.
	 */
	public function construct_sitemap_url( $filename ) {
		$url = jetpack_sitemap_uri( $filename );

		if ( pathinfo( $filename, PATHINFO_EXTENSION ) === 'xsl' ) {
			// Strip scheme for sites where sitemap could be access via http or https.
			$url = preg_replace( '/^https?:/', '', $url );
		}

		return $url;
	}

	/**
	 * Path and query prefix of sitemap files. Depends on permalink
	 * settings.
	 *
	 * @access public
	 * @since 4.8.0
	 *
	 * @return string The path+query prefix.
	 */
	public function the_jetpack_sitemap_path_and_query_prefix() {
		global $wp_rewrite;

		// Get path fragment from home_url().
		$home = wp_parse_url( home_url() );
		if ( isset( $home['path'] ) ) {
			$home_path = $home['path'];
		} else {
			$home_path = '';
		}

		// Get additional path fragment from filter.
		$location = Jetpack_Options::get_option_and_ensure_autoload(
			'jetpack_sitemap_location',
			''
		);

		if ( $wp_rewrite->using_index_permalinks() ) {
			return $home_path . '/index.php' . $location . '/';
		} elseif ( $wp_rewrite->using_permalinks() ) {
			return $home_path . $location . '/';
		} else {
			return $home_path . $location . '/?jetpack-sitemap=';
		}
	}

	/**
	 * Examine a path+query URI fragment looking for a sitemap request.
	 *
	 * @access public
	 * @since 4.8.0
	 *
	 * @param string $raw_uri A URI (path+query only) to test for sitemap-ness.
	 *
	 * @return array @args {
	 *   @type string $sitemap_name The recognized sitemap name (or null).
	 * }
	 */
	public function recognize_sitemap_uri( $raw_uri ) {
		// The path+query where sitemaps are served.
		$sitemap_path = $this->the_jetpack_sitemap_path_and_query_prefix();

		// A regex which detects $sitemap_path at the beginning of a string.
		$path_regex = '/^' . preg_quote( $sitemap_path, '/' ) . '/';

		// Check that the request URI begins with the sitemap path.
		if ( preg_match( $path_regex, $raw_uri ) ) {
			// Strip off the $sitemap_path and any trailing slash.
			$stripped_uri = preg_replace( $path_regex, '', rtrim( $raw_uri, '/' ) );
		} else {
			$stripped_uri = '';
		}

		// Check that the stripped uri begins with one of the sitemap prefixes.
		if ( preg_match( '/^sitemap|^image-s|^news-s|^video-s/', $stripped_uri ) ) {
			$filename = $stripped_uri;
		} else {
			$filename = null;
		}

		return array(
			'sitemap_name' => $filename,
		);
	}

}
