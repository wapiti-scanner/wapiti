<?php
/**
 * Google Fonts package Blocks fonts introspector class file.
 *
 * @package automattic/jetpack-google-fonts-provider
 */

namespace Automattic\Jetpack\Fonts\Introspectors;

use Automattic\Jetpack\Fonts\Utils;

/**
 * Blocks fonts introspector.
 */
class Blocks {
	/**
	 * Enqueue fonts used for block typography settings.
	 *
	 * @filter pre_render_block
	 *
	 * @param string|null $content The pre-rendered content. Default null.
	 * @param array       $parsed_block The block being rendered.
	 */
	public static function enqueue_block_fonts( $content, $parsed_block ) {
		if ( ! is_admin() && isset( $parsed_block['attrs']['fontFamily'] ) ) {

			$block_font_family  = $parsed_block['attrs']['fontFamily'];
			$font_is_registered = Utils::is_font_family_registered( $block_font_family );

			if ( $font_is_registered ) {
				wp_enqueue_webfont( $block_font_family );
			}
		}

		return $content;
	}
}
