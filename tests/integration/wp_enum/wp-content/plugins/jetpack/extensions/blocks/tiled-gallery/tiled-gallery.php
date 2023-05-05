<?php //phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Tiled Gallery block.
 * Relies on Photon, but can be used even when the module is not active.
 *
 * @since 6.9.0
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions;

use Automattic\Jetpack\Blocks;
use Automattic\Jetpack\Status;
use Jetpack;
use Jetpack_Gutenberg;
use Jetpack_Plan;

/**
 * Jetpack Tiled Gallery Block class
 *
 * @since 7.3
 */
class Tiled_Gallery {
	const FEATURE_NAME = 'tiled-gallery';
	const BLOCK_NAME   = 'jetpack/' . self::FEATURE_NAME;

	/* Values for building srcsets */
	const IMG_SRCSET_WIDTH_MAX  = 2000;
	const IMG_SRCSET_WIDTH_MIN  = 600;
	const IMG_SRCSET_WIDTH_STEP = 300;

	/**
	 * Register the block
	 */
	public static function register() {
		if (
			( defined( 'IS_WPCOM' ) && IS_WPCOM )
			|| Jetpack::is_connection_ready()
			|| ( new Status() )->is_offline_mode()
		) {
			Blocks::jetpack_register_block(
				self::BLOCK_NAME,
				array(
					'render_callback' => array( __CLASS__, 'render' ),
				)
			);
		}
	}

	/**
	 * Tiled gallery block registration
	 *
	 * @param array  $attr    Array containing the block attributes.
	 * @param string $content String containing the block content.
	 *
	 * @return string
	 */
	public static function render( $attr, $content ) {
		Jetpack_Gutenberg::load_assets_as_required( self::FEATURE_NAME );

		$is_squareish_layout = self::is_squareish_layout( $attr );

		// Jetpack_Plan::get does not exist on WordPress.com.
		if ( method_exists( 'Jetpack_Plan', 'get' ) ) {
			$jetpack_plan = Jetpack_Plan::get();
			wp_localize_script( 'jetpack-gallery-settings', 'jetpack_plan', array( 'data' => $jetpack_plan['product_slug'] ) );
		}

		if ( preg_match_all( '/<img [^>]+>/', $content, $images ) ) {
			/**
			 * This block processes all of the images that are found and builds $find and $replace.
			 *
			 * The original img is added to the $find array and the replacement is made and added
			 * to the $replace array. This is so that the same find and replace operations can be
			 * made on the entire $content.
			 */
			$find    = array();
			$replace = array();

			foreach ( $images[0] as $image_html ) {
				if (
					preg_match( '/data-width="([0-9]+)"/', $image_html, $img_width )
					&& preg_match( '/data-height="([0-9]+)"/', $image_html, $img_height )
					&& preg_match( '/src="([^"]+)"/', $image_html, $img_src )
				) {
					// Drop img src query string so it can be used as a base to add photon params
					// for the srcset.
					$src_parts   = explode( '?', $img_src[1], 2 );
					$orig_src    = $src_parts[0];
					$orig_height = absint( $img_height[1] );
					$orig_width  = absint( $img_width[1] );

					// Because URLs are already "photon", the photon function used short-circuits
					// before ssl is added. Detect ssl and add is if necessary.
					$is_ssl = ! empty( $src_parts[1] ) && false !== strpos( $src_parts[1], 'ssl=1' );

					if ( ! $orig_width || ! $orig_height || ! $orig_src ) {
						continue;
					}

					$srcset_parts = array();
					if ( $is_squareish_layout ) {
						$min_width = min( self::IMG_SRCSET_WIDTH_MIN, $orig_width, $orig_height );
						$max_width = min( self::IMG_SRCSET_WIDTH_MAX, $orig_width, $orig_height );

						for ( $w = $min_width; $w <= $max_width; $w = min( $max_width, $w + self::IMG_SRCSET_WIDTH_STEP ) ) {
							$srcset_src = add_query_arg(
								array(
									'resize' => $w . ',' . $w,
									'strip'  => 'info',
								),
								$orig_src
							);
							if ( $is_ssl ) {
								$srcset_src = add_query_arg( 'ssl', '1', $srcset_src );
							}
							$srcset_parts[] = esc_url( $srcset_src ) . ' ' . $w . 'w';
							if ( $w >= $max_width ) {
								break;
							}
						}
					} else {
						$min_width = min( self::IMG_SRCSET_WIDTH_MIN, $orig_width );
						$max_width = min( self::IMG_SRCSET_WIDTH_MAX, $orig_width );

						for ( $w = $min_width; $w <= $max_width; $w = min( $max_width, $w + self::IMG_SRCSET_WIDTH_STEP ) ) {
							$srcset_src = add_query_arg(
								array(
									'strip' => 'info',
									'w'     => $w,
								),
								$orig_src
							);
							if ( $is_ssl ) {
								$srcset_src = add_query_arg( 'ssl', '1', $srcset_src );
							}
							$srcset_parts[] = esc_url( $srcset_src ) . ' ' . $w . 'w';
							if ( $w >= $max_width ) {
								break;
							}
						}
					}

					if ( ! empty( $srcset_parts ) ) {
						$srcset = 'srcset="' . esc_attr( implode( ',', $srcset_parts ) ) . '"';

						$find[]    = $image_html;
						$replace[] = str_replace( '<img', '<img ' . $srcset, $image_html );
					}
				}
			}

			if ( ! empty( $find ) ) {
				$content = str_replace( $find, $replace, $content );
			}
		}

		/**
		 * Filter the output of the Tiled Galleries content.
		 *
		 * @module tiled-gallery
		 *
		 * @since 6.9.0
		 *
		 * @param string $content Tiled Gallery block content.
		 */
		return apply_filters( 'jetpack_tiled_galleries_block_content', $content );
	}

	/**
	 * Determines whether a Tiled Gallery block uses square or circle images (1:1 ratio)
	 *
	 * Layouts are block styles and will be available as `is-style-[LAYOUT]` in the className
	 * attribute. The default (rectangular) will be omitted.
	 *
	 * @param  {Array} $attr Attributes key/value array.
	 * @return {boolean} True if layout is squareish, otherwise false.
	 */
	private static function is_squareish_layout( $attr ) {
		return isset( $attr['className'] )
			&& (
				'is-style-square' === $attr['className']
				|| 'is-style-circle' === $attr['className']
			);
	}
}

Tiled_Gallery::register();
