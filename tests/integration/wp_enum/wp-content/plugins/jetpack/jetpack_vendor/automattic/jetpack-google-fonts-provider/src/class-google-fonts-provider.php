<?php
/**
 * WordPress webfonts provider for Google Fonts
 *
 * @package automattic/jetpack-google-fonts-provider
 * @since 0.1.0
 */

namespace Automattic\Jetpack\Fonts;

if ( ! class_exists( '\WP_Webfonts_Provider' ) ) {
	return;
}

/**
 * Google Font Provider
 */
class Google_Fonts_Provider extends \WP_Webfonts_Provider {
	/**
	 * Font provider ID.
	 *
	 * @var string
	 */
	protected $id = 'jetpack-google-fonts';

	/**
	 * The provider's root URL for retrieving font CSS.
	 *
	 * @var string
	 */
	protected $root_url = 'https://fonts.googleapis.com/css2';

	/**
	 * Prints out a preconnect link for improving performance when downloading
	 * Google Font files.
	 *
	 * Hook this function into `wp_head` to enable the preconnect link.
	 *
	 * @deprecated 0.2.0 Use Automattic\Jetpack\Fonts\Utils::font_source_resource_hint() instead.
	 *
	 * @return void
	 */
	public static function preconnect_font_source() {
		_deprecated_function( __METHOD__, '0.2.0', 'Automattic\\Jetpack\\Fonts\\Utils::font_source_resource_hint' );

		$fonts_url = \set_url_scheme( 'https://fonts.gstatic.com' ); ?>
<link rel="preconnect" href="<?php echo esc_url( $fonts_url ); ?>" crossorigin>
		<?php
	}

	/**
	 * Gets cached CSS from a remote URL.
	 *
	 * @param string $id   An ID used to cache the styles.
	 * @param string $url  The URL to fetch.

	 * @return string The styles.
	 */
	protected function get_cached_remote_styles( $id, $url ) {
		$css = \get_site_transient( $id );

		// Get remote response and cache the CSS if it hasn't been cached already.
		if ( false === $css ) {
			$css = $this->get_remote_styles( $url );

			/*
			* Early return if the request failed.
			* Cache an empty string for 60 seconds to avoid bottlenecks.
			*/
			if ( empty( $css ) ) {
				\set_site_transient( $id, '', MINUTE_IN_SECONDS );
				return '';
			}

			// Cache the CSS for a month.
			\set_site_transient( $id, $css, MONTH_IN_SECONDS );
		}

		return $css;
	}

	/**
	 * Gets styles from the remote font service via the given URL.
	 *
	 * @param string $url  The URL to fetch.

	 * @return string The styles on success. Empty string on failure.
	 */
	protected function get_remote_styles( $url ) {
		// Use a modern user-agent, to get woff2 files.
		$args = array( 'user-agent' => 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:73.0) Gecko/20100101 Firefox/73.0' );

		// Get the remote URL contents.
		$response = \wp_safe_remote_get( $url, $args );

		// Early return if the request failed.
		if ( \is_wp_error( $response ) || 200 !== \wp_remote_retrieve_response_code( $response ) ) {
			return '';
		}

		// Get the response body.
		return \wp_remote_retrieve_body( $response );
	}

	/**
	 * Gets the `@font-face` CSS styles for Google Fonts.
	 *
	 * This method does the following processing tasks:
	 *    1. Orchestrates an optimized Google Fonts API URL for each font-family.
	 *    2. Caches each URL, if not already cached.
	 *    3. Does a remote request to the Google Fonts API service to fetch the styles.
	 *    4. Generates the `@font-face` for all its webfonts.
	 *
	 * @return string The `@font-face` CSS.
	 */
	public function get_css() {
		$css  = '';
		$urls = $this->build_collection_api_urls();

		foreach ( $urls as $url ) {
			$css .= $this->get_cached_remote_styles( 'jetpack_google_fonts_' . md5( $url ), $url );
		}

		return $css;
	}

	/**
	 * Builds the Google Fonts URL for a collection of webfonts.
	 *
	 * For example, if given the following webfonts:
	 * ```
	 * array(
	 *      array(
	 *          'font-family' => 'Source Serif Pro',
	 *          'font-style'  => 'normal',
	 *          'font-weight' => '200 400',
	 *      ),
	 *      array(
	 *          'font-family' => 'Source Serif Pro',
	 *          'font-style'  => 'italic',
	 *          'font-weight' => '400 600',
	 *      ),
	 * )
	 * ```
	 * then the returned collection would be:
	 * ```
	 * array(
	 *      'https://fonts.googleapis.com/css2?family=Source+Serif+Pro:ital,wght@0,200;0,300;0,400;1,400;1,500;1,600&display=fallback'
	 * )
	 * ```
	 *
	 * @return array Collection of font-family urls.
	 */
	private function build_collection_api_urls() {
		$font_families_urls = array();

		/**
		 * Filters the Google Fonts API URL.
		 *
		 * @since 0.4.0
		 *
		 * @param string $url The Google Fonts API URL.
		 */
		$root_url = \esc_url( apply_filters( 'jetpack_google_fonts_api_url', $this->root_url ) );

		/*
		* Iterate over each font-family group to build the Google Fonts API URL
		* for that specific family. Each is added to the collection of URLs to be
		* returned to the `get_css()` method for making the remote request.
		*/
		foreach ( $this->organize_webfonts() as $font_display => $font_families ) {
			$url_parts = array();
			foreach ( $font_families as $font_family => $webfonts ) {
				list( $normal_weights, $italic_weights ) = $this->collect_font_weights( $webfonts );

				// Build the font-style with its font-weights.
				$url_part = rawurlencode( $font_family );
				if ( empty( $italic_weights ) && ! empty( $normal_weights ) ) {
					$url_part .= ':wght@' . implode( ';', $normal_weights );
				} elseif ( ! empty( $italic_weights ) && empty( $normal_weights ) ) {
					$url_part .= ':ital,wght@1,' . implode( ';', $normal_weights );
				} elseif ( ! empty( $italic_weights ) && ! empty( $normal_weights ) ) {
					$url_part .= ':ital,wght@0,' . implode( ';0,', $normal_weights ) . ';1,' . implode( ';1,', $italic_weights );
				}

				// Add it to the collection.
				$url_parts[] = $url_part;
			}

			// Build the URL for this font-family and add it to the collection.
			$font_families_urls[] = $root_url . '?family=' . implode( '&family=', $url_parts ) . '&display=' . $font_display;
		}

		return $font_families_urls;
	}

	/**
	 * Organizes the webfonts by font-display and then font-family.
	 *
	 * To optimizing building the URL for the Google Fonts API request,
	 * this method organizes the webfonts first by font-display and then
	 * by font-family.
	 *
	 * For example, if given the following webfonts:
	 * ```
	 * array(
	 *      array(
	 *          'font-family' => 'Source Serif Pro',
	 *          'font-style'  => 'normal',
	 *          'font-weight' => '200 400',
	 *      ),
	 *      array(
	 *          'font-family' => 'Source Serif Pro',
	 *          'font-style'  => 'italic',
	 *          'font-weight' => '400 600',
	 *      ),
	 * )
	 * ```
	 * then the returned collection would be:
	 * ```
	 * array(
	 *      'fallback' => array(
	 *          'Source Serif Pro' => array(
	 *              array(
	 *                  'font-family' => 'Source Serif Pro',
	 *                  'font-style'  => 'normal',
	 *                  'font-weight' => '200 400',
	 *              ),
	 *              array(
	 *                  'font-family' => 'Source Serif Pro',
	 *                  'font-style'  => 'italic',
	 *                  'font-weight' => '400 600',
	 *              ),
	 *         ),
	 *      ),
	 * )
	 *
	 * @return array[][] Webfonts organized by font-display and then font-family.
	 */
	private function organize_webfonts() {
		$font_display_groups = array();

		/*
		* Group by font-display.
		* Each font-display will need to be a separate request.
		*/
		foreach ( $this->webfonts as $webfont ) {
			if ( ! isset( $font_display_groups[ $webfont['font-display'] ] ) ) {
				$font_display_groups[ $webfont['font-display'] ] = array();
			}
			$font_display_groups[ $webfont['font-display'] ][] = $webfont;
		}

		/*
		* Iterate over each font-display group and group by font-family.
		* Multiple font-families can be combined in the same request,
		* but their params need to be grouped.
		*/
		foreach ( $font_display_groups as $font_display => $font_display_group ) {
			$font_families = array();

			foreach ( $font_display_group as $webfont ) {
				if ( ! isset( $font_families[ $webfont['font-family'] ] ) ) {
					$font_families[ $webfont['font-family'] ] = array();
				}
				$font_families[ $webfont['font-family'] ][] = $webfont;
			}

			$font_display_groups[ $font_display ] = $font_families;
		}

		return $font_display_groups;
	}

	/**
	 * Collects all font-weights grouped by 'normal' and 'italic' font-style.
	 *
	 * For example, if given the following webfonts:
	 * ```
	 * array(
	 *      array(
	 *          'font-family' => 'Source Serif Pro',
	 *          'font-style'  => 'normal',
	 *          'font-weight' => '200 400',
	 *      ),
	 *      array(
	 *          'font-family' => 'Source Serif Pro',
	 *          'font-style'  => 'italic',
	 *          'font-weight' => '400 600',
	 *      ),
	 * )
	 * ```
	 * Then the returned collection would be:
	 * ```
	 * array(
	 *      array( 200, 300, 400 ),
	 *      array( 400, 500, 600 ),
	 * )
	 * ```
	 *
	 * @param array $webfonts Webfonts to process.
	 * @return array[] {
	 *    The font-weights grouped by font-style.
	 *
	 *    @type array $normal_weights  Individual font-weight values for 'normal' font-style.
	 *    @type array $italic_weights  Individual font-weight values for 'italic' font-style.
	 * }
	 */
	private function collect_font_weights( array $webfonts ) {
		$normal_weights = array();
		$italic_weights = array();

		foreach ( $webfonts as $webfont ) {
			$font_weights = $this->get_font_weights( $webfont['font-weight'] );
			// Skip this webfont if it does not have a font-weight defined.
			if ( empty( $font_weights ) ) {
				continue;
			}

			// Add the individual font-weights to the end of font-style array.
			if ( 'italic' === $webfont['font-style'] ) {
				array_push( $italic_weights, ...$font_weights );
			} else {
				array_push( $normal_weights, ...$font_weights );
			}
		}

		// Remove duplicates.
		$normal_weights = array_unique( $normal_weights );
		$italic_weights = array_unique( $italic_weights );

		return array( $normal_weights, $italic_weights );
	}

	/**
	 * Converts the given string of font-weight into an array of individual weight values.
	 *
	 * When given a single font-weight, the value is wrapped into an array.
	 *
	 * A range of font-weights is specified as '400 600' with the lightest value first,
	 * a space, and then the heaviest value last.
	 *
	 * When given a range of font-weight values, the range is converted into individual
	 * font-weight values. For example, a range of '400 600' is converted into
	 * `array( 400, 500, 600 )`.
	 *
	 * @param string $font_weights The font-weights string.
	 * @return array The font-weights array.
	 */
	private function get_font_weights( $font_weights ) {
		$font_weights = trim( $font_weights );

		// A single font-weight.
		if ( false === strpos( $font_weights, ' ' ) ) {
			return array( $font_weights );
		}

		// Process a range of font-weight values that are delimited by ' '.
		$font_weights = explode( ' ', $font_weights );

		// If there are 2 values, treat them as a range.
		if ( 2 === count( $font_weights ) ) {
			$font_weights = range( (int) $font_weights[0], (int) $font_weights[1], 100 );
		}

		return $font_weights;
	}
}
