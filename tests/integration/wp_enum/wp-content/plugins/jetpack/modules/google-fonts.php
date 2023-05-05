<?php
/**
 * Module Name: Google Fonts (Beta)
 * Module Description: A selection of Google fonts for block enabled themes. This feature is still being developed.
 * Sort Order: 1
 * Recommendation Order: 2
 * First Introduced: 10.8.0
 * Requires Connection: No
 * Auto Activate: No
 * Module Tags: Fonts, Recommended
 * Feature: Writing
 * Additional Search Queries: fonts, webfonts, typography
 *
 * @package automattic/jetpack
 */

/**
 * Curated list of Google Fonts
 * See https://wp.me/p9Jlb4-22P
 */
const JETPACK_GOOGLE_FONTS_LIST = array(
	'Albert Sans',
	'Alegreya',
	'Arvo',
	'Bodoni Moda',
	'Cabin',
	'Chivo',
	'Commissioner',
	'Cormorant',
	'Courier Prime',
	'Crimson Pro',
	'DM Mono',
	'DM Sans',
	'Domine',
	'EB Garamond',
	'Epilogue',
	'Figtree',
	'Fira Sans',
	'Fraunces',
	'IBM Plex Mono',
	'IBM Plex Sans',
	'Inter',
	'Josefin Sans',
	'Jost',
	'Libre Baskerville',
	'Libre Franklin',
	'Literata',
	'Lora',
	'Merriweather',
	'Montserrat',
	'Newsreader',
	'Nunito',
	'Open Sans',
	'Overpass',
	'Petrona',
	'Piazzolla',
	'Playfair Display',
	'Plus Jakarta Sans',
	'Poppins',
	'Raleway',
	'Roboto Slab',
	'Roboto',
	'Rubik',
	'Sora',
	'Source Sans Pro',
	'Source Serif Pro',
	'Space Mono',
	'Texturina',
	'Work Sans',
);

/**
 * Register a curated selection of Google Fonts.
 *
 * @return void
 */
function jetpack_add_google_fonts_provider() {
	if ( ! function_exists( 'wp_register_webfont_provider' ) || ! function_exists( 'wp_register_webfonts' ) ) {
		return;
	}

	wp_register_webfont_provider( 'jetpack-google-fonts', '\Automattic\Jetpack\Fonts\Google_Fonts_Provider' );

	/**
	 * Curated list of Google Fonts.
	 *
	 * @module google-fonts
	 *
	 * @since 10.8
	 *
	 * @param array $fonts_to_register Array of Google Font names to register.
	 */
	$fonts_to_register = apply_filters( 'jetpack_google_fonts_list', JETPACK_GOOGLE_FONTS_LIST );

	foreach ( $fonts_to_register as $font_family ) {
		$fonts = array();

		$font_italic = array(
			'font-family'  => $font_family,
			'font-weight'  => '100 900',
			'font-style'   => 'normal',
			'font-display' => 'fallback',
			'provider'     => 'jetpack-google-fonts',
		);

		$font_normal = array(
			'font-family'  => $font_family,
			'font-weight'  => '100 900',
			'font-style'   => 'italic',
			'font-display' => 'fallback',
			'provider'     => 'jetpack-google-fonts',
		);

		// New WP Fonts API format since Gutenberg 14.9 requires keyed array
		// See https://github.com/Automattic/jetpack/issues/28063
		// Remove conditional once WP 6.2 is the minimum version (must confirm this made it into 6.2)
		if ( class_exists( 'WP_Fonts' ) ) {
			$fonts = array(
				$font_family => array( $font_normal, $font_italic ),
			);
		} elseif ( class_exists( 'WP_Webfonts' ) ) {
			$fonts = array( $font_normal, $font_italic );
		}

		// New fonts register function since Gutenberg 15.0 or 15.1
		// See https://github.com/Automattic/jetpack/issues/28063#issuecomment-1387090575
		// Remove conditional once WP 6.2 is the minimum version (must confirm this made it into 6.2)
		if ( function_exists( 'wp_register_fonts' ) ) {
			wp_register_fonts( $fonts );
		} else {
			wp_register_webfonts( $fonts );
		}
	}
}
add_action( 'after_setup_theme', 'jetpack_add_google_fonts_provider' );

add_filter( 'wp_resource_hints', '\Automattic\Jetpack\Fonts\Utils::font_source_resource_hint', 10, 2 );
add_filter( 'pre_render_block', '\Automattic\Jetpack\Fonts\Introspectors\Blocks::enqueue_block_fonts', 10, 2 );
// The priority for the next hook is is set to 22 because it needs to run after Gutenberg's
// re-registration (at priority 22) of the core blocks it de-registers (at the default priority 10),
// otherwise Gutenberg caches an incorrect state.
add_action( 'init', '\Automattic\Jetpack\Fonts\Introspectors\Global_Styles::enqueue_global_styles_fonts', 22 );
