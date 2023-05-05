<?php
/**
 * Google Fonts package Global Styles fonts introspector class file.
 *
 * @package automattic/jetpack-google-fonts-provider
 */

namespace Automattic\Jetpack\Fonts\Introspectors;

use Automattic\Jetpack\Fonts\Utils;

/**
 * Global Styles fonts introspector.
 */
class Global_Styles {
	/**
	 * Enqueue fonts used in global styles settings.
	 *
	 * @return void
	 */
	public static function enqueue_global_styles_fonts() {
		if ( is_admin() || ! function_exists( 'wp_enqueue_webfont' ) ) {
			return;
		}

		$global_styles_fonts = self::collect_fonts_from_global_styles();

		foreach ( $global_styles_fonts as $font ) {
			$font_is_registered = Utils::is_font_family_registered( $font );

			if ( $font_is_registered ) {
				wp_enqueue_webfont( $font );
			}
		}
	}

	/**
	 * Collect fonts set in Global Styles settings.
	 *
	 * @return array Font faces from Global Styles settings.
	 */
	public static function collect_fonts_from_global_styles() {
		if ( ! function_exists( 'gutenberg_get_global_styles' ) && ! function_exists( 'wp_get_global_styles' ) ) {
			return array();
		}

		$global_styles = function_exists( 'wp_get_global_styles' ) ?
			wp_get_global_styles() : gutenberg_get_global_styles();

		$found_webfonts = array();

		// Look for fonts in block presets...
		if ( isset( $global_styles['blocks'] ) ) {
			foreach ( $global_styles['blocks'] as $setting ) {
				$font_slug = self::extract_font_slug_from_setting( $setting );

				if ( $font_slug ) {
					$found_webfonts[] = $font_slug;
				}
			}
		}

		// Look for fonts in HTML element presets...
		if ( isset( $global_styles['elements'] ) ) {
			foreach ( $global_styles['elements'] as $setting ) {
				$font_slug = self::extract_font_slug_from_setting( $setting );

				if ( $font_slug ) {
					$found_webfonts[] = $font_slug;
				}
			}
		}

		// Check if a global typography setting was defined.
		$font_slug = self::extract_font_slug_from_setting( $global_styles );

		if ( $font_slug ) {
			$found_webfonts[] = $font_slug;
		}

		return $found_webfonts;
	}

	/**
	 * Extract the font family slug from a settings array.
	 *
	 * @param array $setting The settings object.
	 *
	 * @return string|null
	 */
	protected static function extract_font_slug_from_setting( $setting ) {
		if ( ! isset( $setting['typography']['fontFamily'] ) ) {
			return null;
		}

		$font_family = $setting['typography']['fontFamily'];

		// Full string: var(--wp--preset--font-family--slug).
		// We do not care about the origin of the font, only its slug.
		preg_match( '/font-family--(?P<slug>.+)\)$/', $font_family, $matches );

		if ( isset( $matches['slug'] ) ) {
			return $matches['slug'];
		}

		// Full string: var:preset|font-family|slug
		// We do not care about the origin of the font, only its slug.
		preg_match( '/font-family\|(?P<slug>.+)$/', $font_family, $matches );

		if ( isset( $matches['slug'] ) ) {
			return $matches['slug'];
		}

		return $font_family;
	}
}
