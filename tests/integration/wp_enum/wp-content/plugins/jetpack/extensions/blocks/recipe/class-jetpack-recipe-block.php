<?php
/**
 * Jetpack Recipe Block
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\Recipe;

use Jetpack_Gutenberg;

/**
 * Jetpack Recipe Block class.
 *
 * Helper class that lets us add schema attributes dynamically because they are not something that is store with the content.
 * Due to the limitations of wp_kses.
 *
 * @since 11.1
 */
class Jetpack_Recipe_Block {
	/**
	 * Adds recipe schema attributes.
	 *
	 * @param array  $attr    Array containing the recipe block attributes.
	 * @param string $content String containing the recipe block content.
	 *
	 * @return string
	 */
	public static function render( $attr, $content ) {
		Jetpack_Gutenberg::load_assets_as_required( 'recipe' );

		$find    = array(
			'/(class="wp-block-jetpack-recipe(\s|"))/',
			'/(class="wp-block-jetpack-recipe-title(\s|"))/',
			'/(class="wp-block-jetpack-recipe-description(\s|"))/',
		);
		$replace = array(
			'itemscope itemtype="https://schema.org/Recipe" ${1}',
			'itemprop="name" ${1}',
			'itemprop="description" ${1}',
		);

		return preg_replace( $find, $replace, $content );
	}

	/**
	 * Adds recipe hero schema attributes.
	 *
	 * @param array  $attr    Array containing the recipe-hero block attributes.
	 * @param string $content String containing the recipe-hero block content.
	 *
	 * @return string
	 */
	public static function render_hero( $attr, $content ) {
		$find    = array(
			'<img',
		);
		$replace = array(
			'<img itemprop="image" ',
		);

		return str_replace( $find, $replace, $content );
	}

	/**
	 * Adds recipe step schema attributes.
	 *
	 * @param array  $attr    Array containing the recipe-step block attributes.
	 * @param string $content String containing the recipe-step block content.
	 *
	 * @return string
	 */
	public static function render_step( $attr, $content ) {
		$find    = array(
			'class="wp-block-jetpack-recipe-step-name"',
			'class="wp-block-jetpack-recipe-step-desc"',
			'class="wp-image',
		);
		$replace = array(
			'itemprop="name" class="wp-block-jetpack-recipe-step-name"',
			'itemprop="text" class="wp-block-jetpack-recipe-step-desc"',
			'itemprop="image" class="wp-image',
		);

		return str_replace( $find, $replace, $content );
	}
}
