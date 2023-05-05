<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * The Lazy Images package.
 *
 * @since 1.0.0
 * @since-jetpack 8.8.0
 *
 * This package has been lifted from the Jetpack modules folder and adapted to be
 * an standalone package reusable outside Jetpack.
 *
 * @package automattic/jetpack-lazy-images
 */

/**
 * This package relies heavily upon the Lazy Load plugin which was worked on by
 * Mohammad Jangda (batmoo), the WordPress.com VIP team, the TechCrunch 2011
 * redesign team, and Jake Goldman of 10up LLC.
 *
 * The JavaScript has been updated to rely on InterSection observer instead of
 * jQuery Sonar. Many thanks to Dean Hume (deanhume) and his example:
 * https://github.com/deanhume/lazy-observer-load
 */

namespace Automattic\Jetpack;

/**
 * Class Automattic\Jetpack\Jetpack_Lazy_Images
 *
 * @since 1.0.0
 * @since-jetpack 8.8.0
 */
class Jetpack_Lazy_Images {

	/**
	 * Class instance.
	 *
	 * @since 1.0.0
	 * @since-jetpack 5.6.0
	 *
	 * @var null
	 */
	private static $instance = null;

	/**
	 * Singleton implementation.
	 *
	 * @since 1.0.0
	 * @since-jetpack 5.6.0
	 *
	 * @return object The class instance.
	 */
	public static function instance() {
		if ( self::$instance === null ) {
			self::$instance = new Jetpack_Lazy_Images();
		}

		return self::$instance;
	}

	/**
	 * Check if the request is a AMP request.
	 *
	 * @since 1.0.0
	 * @since-jetpack 8.8.0
	 *
	 * @return bool
	 */
	public static function is_amp_request() {
		$is_amp_request = ( function_exists( 'is_amp_endpoint' ) && is_amp_endpoint() );

		/**
		 * Returns true if the current request should return valid AMP content.
		 *
		 * @since 1.0.0
		 * @since-jetpack 8.8.0
		 *
		 * @param boolean $is_amp_request Is this request supposed to return valid AMP content?
		 */
		return apply_filters( 'jetpack_lazy_images_is_amp_request', $is_amp_request );
	}

	/**
	 * Registers actions.
	 *
	 * @since 1.0.0
	 * @since-jetpack 8.8.0
	 *
	 * @return void
	 */
	private function __construct() {
		if ( is_admin() ) {
			return;
		}

		/**
		 * Whether the lazy-images module should load.
		 *
		 * This filter is not prefixed with jetpack_ to provide a smoother migration
		 * process from the WordPress Lazy Load plugin.
		 *
		 * @package automattic/jetpack-lazy-images
		 *
		 * @since 1.0.0
		 * @since-jetpack 5.6.0
		 *
		 * @param bool true Whether lazy image loading should occur.
		 */
		if ( ! apply_filters( 'lazyload_is_enabled', true ) ) {
			return;
		}

		if ( self::is_amp_request() ) {
			return;
		}

		add_action( 'the_post', array( $this, 'setup_filters' ), 9999 );
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_assets' ) );

		// Do not lazy load avatar in admin bar.
		add_action( 'admin_bar_menu', array( $this, 'remove_filters' ), 0 );

		add_filter( 'wp_kses_allowed_html', array( $this, 'allow_lazy_attributes' ) );
		add_action( 'wp_head', array( $this, 'add_nojs_fallback' ) );

		add_filter( 'wp_img_tag_add_loading_attr', array( $this, 'maybe_skip_core_loading_attribute' ), 10, 2 );
	}

	/**
	 * Setup filters.
	 *
	 * @since 1.0.0
	 * @since-jetpack 5.6.0
	 *
	 * @return void
	 */
	public function setup_filters() {
		// Do not lazy-load images in RSS feeds or embeds.
		if (
			is_feed()
			|| is_embed()
		) {
			return;
		}

		add_filter( 'the_content', array( $this, 'add_image_placeholders' ), PHP_INT_MAX ); // Run this later, so other content filters have run, including image_add_wh on WP.com.
		add_filter( 'post_thumbnail_html', array( $this, 'add_image_placeholders' ), PHP_INT_MAX );
		add_filter( 'get_avatar', array( $this, 'add_image_placeholders' ), PHP_INT_MAX );
		add_filter( 'widget_text', array( $this, 'add_image_placeholders' ), PHP_INT_MAX );
		add_filter( 'get_image_tag', array( $this, 'add_image_placeholders' ), PHP_INT_MAX );
		add_filter( 'wp_get_attachment_image_attributes', array( __CLASS__, 'process_image_attributes' ), PHP_INT_MAX );
	}

	/**
	 * Remove filters.
	 *
	 * @since 1.0.0
	 * @since-jetpack 5.6.0
	 *
	 * @return void
	 */
	public function remove_filters() {
		remove_filter( 'the_content', array( $this, 'add_image_placeholders' ), PHP_INT_MAX );
		remove_filter( 'post_thumbnail_html', array( $this, 'add_image_placeholders' ), PHP_INT_MAX );
		remove_filter( 'get_avatar', array( $this, 'add_image_placeholders' ), PHP_INT_MAX );
		remove_filter( 'widget_text', array( $this, 'add_image_placeholders' ), PHP_INT_MAX );
		remove_filter( 'get_image_tag', array( $this, 'add_image_placeholders' ), PHP_INT_MAX );
		remove_filter( 'wp_get_attachment_image_attributes', array( __CLASS__, 'process_image_attributes' ), PHP_INT_MAX );
	}

	/**
	 * Ensure that our lazy image attributes are not filtered out of image tags.
	 *
	 * @since 1.0.0
	 * @since-jetpack 5.6.0
	 *
	 * @param array $allowed_tags The allowed tags and their attributes.
	 * @return array
	 */
	public function allow_lazy_attributes( $allowed_tags ) {
		if ( ! isset( $allowed_tags['img'] ) ) {
			return $allowed_tags;
		}

		// But, if images are allowed, ensure that our attributes are allowed!
		$img_attributes = array_merge(
			$allowed_tags['img'],
			array(
				'data-lazy-src'    => 1,
				'data-lazy-srcset' => 1,
				'data-lazy-sizes'  => 1,
			)
		);

		$allowed_tags['img'] = $img_attributes;

		return $allowed_tags;
	}

	/**
	 * Add image placeholders.
	 *
	 * @since 1.0.0
	 * @since-jetpack 5.6.0
	 *
	 * @param string $content Content.
	 * @return string
	 */
	public function add_image_placeholders( $content ) {
		// Don't lazy load for feeds, previews.
		if ( is_feed() || is_preview() ) {
			return $content;
		}

		// This is a pretty simple regex, but it works.
		$content = preg_replace_callback( '#<(img)([^>]+?)(>(.*?)</\\1>|[\/]?>)#si', array( __CLASS__, 'process_image' ), $content );

		return $content;
	}

	/**
	 * Returns true when a given string of classes contains a class signifying lazy images.
	 * should not process the image.
	 *
	 * @since 1.0.0
	 * @since-jetpack 5.9.0
	 *
	 * @param string $classes A string of space-separated classes.
	 * @return bool
	 */
	public static function should_skip_image_with_blocked_class( $classes ) {
		$blocked_classes = array(
			'skip-lazy',
			'gazette-featured-content-thumbnail',
		);

		/**
		 * Allow plugins and themes to tell lazy images to skip an image with a given class.
		 *
		 * @package automattic/jetpack-lazy-images
		 *
		 * @since 1.0.0
		 * @since-jetpack 8.7.0
		 *
		 * @param array An array of strings where each string is a class.
		 */
		$blocked_classes = apply_filters( 'jetpack_lazy_images_blocked_classes', $blocked_classes );

		if ( ! is_array( $blocked_classes ) || empty( $blocked_classes ) ) {
			return false;
		}

		foreach ( $blocked_classes as $class ) {
			if ( false !== strpos( $classes, $class ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Processes images in content by acting as the preg_replace_callback.
	 *
	 * @since 1.0.0
	 * @since-jetpack 5.6.0
	 *
	 * @param array $matches Matches.
	 *
	 * @return string The image with updated lazy attributes.
	 */
	public static function process_image( $matches ) {
		$old_attributes_str       = $matches[2];
		$old_attributes_kses_hair = wp_kses_hair( $old_attributes_str, wp_allowed_protocols() );

		if ( empty( $old_attributes_kses_hair['src'] ) ) {
			return $matches[0];
		}

		$old_attributes = self::flatten_kses_hair_data( $old_attributes_kses_hair );

		// If we're processing again and this image is the fallback, just return it.
		if ( isset( $old_attributes['data-lazy-fallback'] ) ) {
			return $matches[0];
		}

		// If the loading attribute is already set. Let's remove it.
		unset( $old_attributes['loading'] );

		// If we've already processed the image don't process it again.
		if ( self::has_image_been_processed( $old_attributes ) ) {
			return sprintf( '<img %1$s>', self::build_attributes_string( $old_attributes ) );
		}

		$new_attributes     = self::process_image_attributes( $old_attributes );
		$new_attributes_str = self::build_attributes_string( $new_attributes );

		return sprintf( '<img %1$s><noscript><img data-lazy-fallback="1"%2$s /></noscript>', $new_attributes_str, $old_attributes_str );
	}

	/**
	 * Given an array of image attributes, updates the `src`, `srcset`, and `sizes` attributes so
	 * that they load lazily.
	 *
	 * @since 1.0.0
	 * @since-jetpack 5.7.0
	 *
	 * @param array $attributes Attributes.
	 *
	 * @return array The updated image attributes array with lazy load attributes.
	 */
	public static function process_image_attributes( $attributes ) {
		if ( self::has_image_been_processed( $attributes ) ) {
			return $attributes;
		}

		if ( empty( $attributes['src'] ) ) {
			return $attributes;
		}

		if ( ! empty( $attributes['class'] ) && self::should_skip_image_with_blocked_class( $attributes['class'] ) ) {
			return $attributes;
		}

		if ( isset( $attributes['data-skip-lazy'] ) ) {
			return $attributes;
		}

		/**
		 * Allow plugins and themes to conditionally skip processing an image via its attributes.
		 *
		 * @package automattic/jetpack-lazy-images
		 *
		 * @since 1.0.0
		 * @since-jetpack 5.9.0
		 * @deprecated-jetpack 6.5.0 Use jetpack_lazy_images_skip_image_with_attributes instead.
		 *
		 * @param bool  Default to not skip processing the current image.
		 * @param array An array of attributes via wp_kses_hair() for the current image.
		 */
		if ( apply_filters( 'jetpack_lazy_images_skip_image_with_atttributes', false, $attributes ) ) {
			return $attributes;
		}

		/**
		 * Allow plugins and themes to conditionally skip processing an image via its attributes.
		 *
		 * @package automattic/jetpack-lazy-images
		 *
		 * @since 1.0.0
		 * @since-jetpack 5.9.0
		 * @since-jetpack 6.5.0 Filter name was updated from jetpack_lazy_images_skip_image_with_atttributes to correct typo.
		 *
		 * @param bool  Default to not skip processing the current image.
		 * @param array An array of attributes via wp_kses_hair() for the current image.
		 */
		if ( apply_filters( 'jetpack_lazy_images_skip_image_with_attributes', false, $attributes ) ) {
			return $attributes;
		}

		$old_attributes = $attributes;

		// Stash srcset and sizes in data attributes.
		foreach ( array( 'srcset', 'sizes' ) as $attribute ) {
			if ( isset( $old_attributes[ $attribute ] ) ) {
				$attributes[ "data-lazy-$attribute" ] = $old_attributes[ $attribute ];
				unset( $attributes[ $attribute ] );
			}
		}

		// We set this, adding the query arg so that it doesn't exactly equal the src attribute, so that photon JavaScript
		// will hold off on processing this image.
		$attributes['data-lazy-src'] = esc_url_raw( add_query_arg( 'is-pending-load', true, $attributes['src'] ) );

		$attributes['srcset'] = self::get_placeholder_image();
		$attributes['class']  = sprintf(
			'%s jetpack-lazy-image',
			empty( $old_attributes['class'] )
				? ''
				: $old_attributes['class']
		);

		/**
		 * Allow plugins and themes to override the attributes on the image before the content is updated.
		 *
		 * One potential use of this filter is for themes that set `height:auto` on the `img` tag.
		 * With this filter, the theme could get the width and height attributes from the
		 * $attributes array and then add a style tag that sets those values as well, which could
		 * minimize reflow as images load.
		 *
		 * @package automattic/jetpack-lazy-images
		 *
		 * @since 1.0.0
		 * @since-jetpack 5.6.0
		 *
		 * @param array An array containing the attributes for the image, where the key is the attribute name
		 *              and the value is the attribute value.
		 */
		return apply_filters( 'jetpack_lazy_images_new_attributes', $attributes );
	}

	/**
	 * Adds JavaScript to check if the current browser supports JavaScript as well as some styles to hide lazy
	 * images when the browser does not support JavaScript.
	 *
	 * @since 1.0.0
	 * @since-jetpack 5.6.0
	 *
	 * @return void
	 */
	public function add_nojs_fallback() {
		?>
			<style type="text/css">
				/* If html does not have either class, do not show lazy loaded images. */
				html:not( .jetpack-lazy-images-js-enabled ):not( .js ) .jetpack-lazy-image {
					display: none;
				}
			</style>
			<script>
				document.documentElement.classList.add(
					'jetpack-lazy-images-js-enabled'
				);
			</script>
		<?php
	}

	/**
	 * Retrieves the placeholder image after running it through the lazyload_images_placeholder_image filter.
	 *
	 * @since 1.0.0
	 * @since-jetpack 5.6.0
	 *
	 * @return string The placeholder image source.
	 */
	private static function get_placeholder_image() {
		/**
		 * Allows plugins and themes to modify the placeholder image.
		 *
		 * This filter is not prefixed with jetpack_ to provide a smoother migration
		 * process from the WordPress Lazy Load plugin.
		 *
		 * @module lazy-images
		 *
		 * @since 1.0.0
		 * @since-jetpack 5.6.0
		 * @since-jetpack 6.5.0 Default image is now a base64 encoded transparent gif.
		 *
		 * @param string The URL to the placeholder image.
		 */
		return apply_filters(
			'lazyload_images_placeholder_image',
			'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7'
		);
	}

	/**
	 * Flatter KSES hair data.
	 *
	 * @since 1.0.0
	 * @since-jetpack 5.6.0
	 *
	 * @param array $attributes Attributes.
	 *
	 * @return array
	 */
	private static function flatten_kses_hair_data( $attributes ) {
		$flattened_attributes = array();
		foreach ( $attributes as $name => $attribute ) {
			$flattened_attributes[ $name ] = $attribute['value'];
		}
		return $flattened_attributes;
	}

	/**
	 * Build attributes string.
	 *
	 * @since 1.0.0
	 * @since-jetpack 5.6.0
	 *
	 * @param array $attributes Attributes.
	 *
	 * @return string
	 */
	private static function build_attributes_string( $attributes ) {
		$string = array();
		foreach ( $attributes as $name => $value ) {
			if ( '' === $value ) {
				$string[] = sprintf( '%s', $name );
			} else {
				$string[] = sprintf( '%s="%s"', $name, esc_attr( $value ) );
			}
		}
		return implode( ' ', $string );
	}

	/**
	 * Enqueue assets.
	 *
	 * @since 1.0.0
	 * @since-jetpack 5.6.0
	 *
	 * @return void
	 */
	public function enqueue_assets() {
		Assets::register_script(
			'jetpack-lazy-images-polyfill-intersectionobserver',
			'../dist/intersection-observer.js',
			__FILE__,
			array(
				'nonmin_path' => '../dist/intersection-observer.src.js',
				'in_footer'   => true,
			)
		);
		Assets::register_script(
			'jetpack-lazy-images',
			'../dist/lazy-images.js',
			__FILE__,
			array(
				'nonmin_path'  => 'js/lazy-images.js',
				'dependencies' => array( 'jetpack-lazy-images-polyfill-intersectionobserver' ),
				'in_footer'    => true,
			)
		);
		Assets::enqueue_script( 'jetpack-lazy-images' );
		wp_localize_script(
			'jetpack-lazy-images',
			'jetpackLazyImagesL10n',
			array(
				'loading_warning' => __( 'Images are still loading. Please cancel your print and try again.', 'jetpack-lazy-images' ),
			)
		);
	}

	/**
	 * If we have already initialized an image to be lazy loaded by Jetpack, then bypass core's lazy loading to minimize conflicts.
	 *
	 * See: https://github.com/Automattic/jetpack/issues/23553
	 *
	 * @since 2.1.18
	 *
	 * @param string|bool $value  The value to use for the loading attribute.
	 * @param string      $image  The markup for the image.
	 *
	 * @return bool If core's lazy loading should be bypassed, `false`. Otherwise, the original `$value`.
	 */
	public function maybe_skip_core_loading_attribute( $value, $image ) {
		if ( false !== strpos( $image, 'jetpack-lazy-image' ) ) {
			return false;
		}

		return $value;
	}

	/**
	 * Helper method for determining if image has been processed before or not.
	 *
	 * @since 2.1.19
	 *
	 * @param array $attributes The image attributes.
	 *
	 * @return boolean True if image has been processed before, false otherwise.
	 */
	public static function has_image_been_processed( $attributes ) {
		$non_empty_attributes = array(
			'data-lazy-src',
			'data-lazy-srcset',
			'data-lazy-sizes',
		);

		foreach ( $non_empty_attributes as $attribute ) {
			if ( ! empty( $attributes[ $attribute ] ) ) {
				return true;
			}
		}

		if ( isset( $attributes['class'] ) && false !== strpos( $attributes['class'], 'jetpack-lazy-image' ) ) {
			return true;
		}

		// If placeholder image is set, then we've already processed the image.
		if ( isset( $attributes['srcset'] ) && self::get_placeholder_image() === $attributes['srcset'] ) {
			return true;
		}

		return false;
	}
}
