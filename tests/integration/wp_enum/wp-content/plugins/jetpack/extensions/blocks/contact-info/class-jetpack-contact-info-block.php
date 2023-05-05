<?php
/**
 * Class Jetpack_Contact_Info_Block
 *
 * @package automattic/jetpack
 */

/**
 * Helper class that lets us add schema attributes dynamically because they are not something that is store with the content.
 * Due to the limitations of wp_kses.
 *
 * @since 7.1.0
 */
class Jetpack_Contact_Info_Block {

	/**
	 * Adds contact info schema attributes.
	 *
	 * @param array  $attr    Array containing the contact info block attributes.
	 * @param string $content String containing the contact info block content.
	 *
	 * @return string
	 */
	public static function render( $attr, $content ) {
		Jetpack_Gutenberg::load_styles_as_required( 'contact-info' );
		return str_replace(
			'class="wp-block-jetpack-contact-info', // Closing " intentionally ommited to that the user can also add the className as expected.
			'itemprop="location" itemscope itemtype="http://schema.org/Organization" class="wp-block-jetpack-contact-info',
			$content
		);
	}

	/**
	 * Adds address schema attributes.
	 *
	 * @param array  $attr    Array containing the address block attributes.
	 * @param string $content String containing the address block content.
	 *
	 * @return string
	 */
	public static function render_address( $attr, $content ) {
		// Returns empty content if the only attribute set is linkToGoogleMaps.
		if ( ! self::has_attributes( $attr, array( 'linkToGoogleMaps', 'className' ) ) ) {
			return '';
		}
		$find    = array(
			'class="wp-block-jetpack-address"',
			'class="jetpack-address__address',
			// Closing " left out on purpose - there are multiple address fields and they all need to be updated with the same itemprop.
			'class="jetpack-address__region"',
			'class="jetpack-address__city"',
			'class="jetpack-address__postal"',
			'class="jetpack-address__country"',
		);
		$replace = array(
			'itemprop="address" itemscope itemtype="http://schema.org/PostalAddress" class="wp-block-jetpack-address" ',
			'itemprop="streetAddress" class="jetpack-address__address', // Closing " left out on purpose.
			'itemprop="addressRegion" class="jetpack-address__region"',
			'itemprop="addressLocality" class="jetpack-address__city"',
			'itemprop="postalCode" class="jetpack-address__postal"',
			'itemprop="addressCountry" class="jetpack-address__country"',
		);

		return str_replace( $find, $replace, $content );
	}

	/**
	 * Helper function that lets us determine if a block has any valid attributes.
	 *
	 * @param array $attr Array containing the block attributes.
	 * @param array $omit Array containing the block attributes that we ignore.
	 *
	 * @return string
	 */
	public static function has_attributes( $attr, $omit = array() ) {
		foreach ( $attr as $attribute => $value ) {
			if ( ! in_array( $attribute, $omit, true ) && ! empty( $value ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Adds email schema attributes.
	 *
	 * @param array  $attr    Array containing the email block attributes.
	 * @param string $content String containing the email block content.
	 *
	 * @return string
	 */
	public static function render_email( $attr, $content ) {
		$content = self::has_attributes( $attr, array( 'className' ) ) ?
			str_replace( 'href="mailto:', 'itemprop="email" href="mailto:', $content ) :
			'';
		return $content;
	}

	/**
	 * Adds phone schema attributes. Also wraps the tel link in a span so that
	 * it's recognized as a telephone number in Google's Structured Data.
	 *
	 * @param array  $attr    Array containing the phone block attributes.
	 * @param string $content String containing the phone block content.
	 *
	 * @return string
	 */
	public static function render_phone( $attr, $content ) {
		if ( self::has_attributes( $attr, array( 'className' ) ) ) {
			return str_replace(
				array( '<a href="tel:', '</a>' ),
				array( '<span itemprop="telephone"><a href="tel:', '</a></span>' ),
				$content
			);
		}

		return '';
	}
}
