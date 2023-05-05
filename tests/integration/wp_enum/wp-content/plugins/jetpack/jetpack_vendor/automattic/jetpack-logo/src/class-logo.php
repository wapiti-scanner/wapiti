<?php
/**
 * A logo for Jetpack.
 *
 * @package automattic/jetpack-logo
 */

namespace Automattic\Jetpack\Assets;

/**
 * Jetpack logo as SVG shapes.
 *
 * Initializes the logo property with a string describing the Jetpack logo.
 * The Jetpack logo SVG string includes CSS classes to stylize it:
 * - jetpack-logo: the wrapper <svg> tag.
 * - jetpack-logo__icon-circle: the circle of the Jetpack mark.
 * - jetpack-logo__icon-triangle: two shapes that correspond to each triangle in the Jetpack mark.
 * - jetpack-logo__icon-text: the Jetpack lettering.
 *
 * @var string
 */
const JETPACK_LOGO_SVG = <<<'EOSVG'
<svg xmlns="http://www.w3.org/2000/svg" height="32" class="jetpack-logo" viewBox="0 0 118 32">
	<path class="jetpack-logo__icon-circle" d="M16,0C7.2,0,0,7.2,0,16s7.2,16,16,16s16-7.2,16-16S24.8,0,16,0z" fill="#069e08" />
	<polygon class="jetpack-logo__icon-triangle" points="15,19 7,19 15,3" fill="#fff" />
	<polygon class="jetpack-logo__icon-triangle" points="17,29 17,13 25,13" fill="#fff" />
	<path class="jetpack-logo__text" d="M41.3 26.6c-.5-.7-.9-1.4-1.3-2.1 2.3-1.4 3-2.5 3-4.6V8h-3V6h6v13.4C46 22.8 45 24.8 41.3 26.6zM58.5 21.3c-1.5.5-2.7.6-4.2.6-3.6 0-5.8-1.8-5.8-6 0-3.1 1.9-5.9 5.5-5.9s4.9 2.5 4.9 4.9c0 .8 0 1.5-.1 2h-7.3c.1 2.5 1.5 2.8 3.6 2.8 1.1 0 2.2-.3 3.4-.7C58.5 19 58.5 21.3 58.5 21.3zM56 15c0-1.4-.5-2.9-2-2.9-1.4 0-2.3 1.3-2.4 2.9C51.6 15 56 15 56 15zM65 18.4c0 1.1.8 1.3 1.4 1.3.5 0 2-.2 2.6-.4v2.1c-.9.3-2.5.5-3.7.5-1.5 0-3.2-.5-3.2-3.1V12H60v-2h2.1V7.1H65V10h4v2h-4V18.4zM71 10h3v1.3c1.1-.8 1.9-1.3 3.3-1.3 2.5 0 4.5 1.8 4.5 5.6s-2.2 6.3-5.8 6.3c-.9 0-1.3-.1-2-.3V28h-3V10zM76.5 12.3c-.8 0-1.6.4-2.5 1.2v5.9c.6.1.9.2 1.8.2 2 0 3.2-1.3 3.2-3.9C79 13.4 78.1 12.3 76.5 12.3zM93 22h-3v-1.5c-.9.7-1.9 1.5-3.5 1.5-1.5 0-3.1-1.1-3.1-3.2 0-2.9 2.5-3.4 4.2-3.7l2.4-.3v-.3c0-1.5-.5-2.3-2-2.3-.7 0-2.3.5-3.7 1.1L84 11c1.2-.4 3-1 4.4-1 2.7 0 4.6 1.4 4.6 4.7L93 22zM90 16.4l-2.2.4c-.7.1-1.4.5-1.4 1.6 0 .9.5 1.4 1.3 1.4s1.5-.5 2.3-1V16.4zM104.5 21.3c-1.1.4-2.2.6-3.5.6-4.2 0-5.9-2.4-5.9-5.9 0-3.7 2.3-6 6.1-6 1.4 0 2.3.2 3.2.5V13c-.8-.3-2-.6-3.2-.6-1.7 0-3.2.9-3.2 3.6 0 2.9 1.5 3.8 3.3 3.8.9 0 1.9-.2 3.2-.7V21.3zM110 15.2c.2-.3.2-.8 3.8-5.2h3.7l-4.6 5.7 5 6.3h-3.7l-4.2-5.8V22h-3V6h3V15.2z" />
</svg>
EOSVG;

/**
 * Create and render a Jetpack logo.
 */
class Logo {

	/**
	 * Return the Jetpack logo.
	 *
	 * @return string The Jetpack logo.
	 */
	public function render() {
		return JETPACK_LOGO_SVG;
	}

	/**
	 * Return string containing the Jetpack logo.
	 *
	 * @since 1.1.4
	 * @since-jetpack 7.5.0
	 *
	 * @param bool $logotype Should we use the full logotype (logo + text). Default to false.
	 *
	 * @return string
	 */
	public function get_jp_emblem( $logotype = false ) {
		$logo_text = $this->get_jp_logo_parts();
		return sprintf(
			'<svg id="jetpack-logo__icon" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" viewBox="0 0 %1$s 32">%2$s</svg>',
			( true === $logotype ? '118' : '32' ),
			( true === $logotype ? $logo_text['logo'] . $logo_text['text'] : $logo_text['logo'] )
		);
	}

	/**
	 * Return string containing the Jetpack logo in a slightly larger format than get_jp_emblem().
	 *
	 * @since 1.1.4
	 * @param bool $logotype Should we use the full logotype (logo + text). Default to false.
	 * @return string
	 */
	public function get_jp_emblem_larger( $logotype = false ) {
		$logo_text = $this->get_jp_logo_parts();
		return sprintf(
			'<svg class="jitm-jp-logo" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" height="32" viewBox="0 0 %1$s 32">%2$s</svg>',
			( true === $logotype ? '118' : '32' ),
			( true === $logotype ? $logo_text['logo'] . $logo_text['text'] : $logo_text['logo'] )
		);
	}

	/**
	 * Return array containing the Jetpack logo and text
	 *
	 * @since 1.6.0 - Added $color parameter.
	 *
	 * @param string $color The color of the logo.
	 *
	 * @return array
	 */
	private function get_jp_logo_parts( $color = '#069e08' ) {
		return array(
			'logo' => '<path fill="' . $color . '" d="M16,0C7.2,0,0,7.2,0,16s7.2,16,16,16c8.8,0,16-7.2,16-16S24.8,0,16,0z M15.2,18.7h-8l8-15.5V18.7z M16.8,28.8 V13.3h8L16.8,28.8z"/>',
			'text' => '<path d="M41.3,26.6c-0.5-0.7-0.9-1.4-1.3-2.1c2.3-1.4,3-2.5,3-4.6V8h-3V6h6v13.4C46,22.8,45,24.8,41.3,26.6z" />
			<path d="M65,18.4c0,1.1,0.8,1.3,1.4,1.3c0.5,0,2-0.2,2.6-0.4v2.1c-0.9,0.3-2.5,0.5-3.7,0.5c-1.5,0-3.2-0.5-3.2-3.1V12H60v-2h2.1V7.1 H65V10h4v2h-4V18.4z" />
			<path d="M71,10h3v1.3c1.1-0.8,1.9-1.3,3.3-1.3c2.5,0,4.5,1.8,4.5,5.6s-2.2,6.3-5.8,6.3c-0.9,0-1.3-0.1-2-0.3V28h-3V10z M76.5,12.3 c-0.8,0-1.6,0.4-2.5,1.2v5.9c0.6,0.1,0.9,0.2,1.8,0.2c2,0,3.2-1.3,3.2-3.9C79,13.4,78.1,12.3,76.5,12.3z" />
			<path d="M93,22h-3v-1.5c-0.9,0.7-1.9,1.5-3.5,1.5c-1.5,0-3.1-1.1-3.1-3.2c0-2.9,2.5-3.4,4.2-3.7l2.4-0.3v-0.3c0-1.5-0.5-2.3-2-2.3 c-0.7,0-2.3,0.5-3.7,1.1L84,11c1.2-0.4,3-1,4.4-1c2.7,0,4.6,1.4,4.6,4.7L93,22z M90,16.4l-2.2,0.4c-0.7,0.1-1.4,0.5-1.4,1.6 c0,0.9,0.5,1.4,1.3,1.4s1.5-0.5,2.3-1V16.4z" />
			<path d="M104.5,21.3c-1.1,0.4-2.2,0.6-3.5,0.6c-4.2,0-5.9-2.4-5.9-5.9c0-3.7,2.3-6,6.1-6c1.4,0,2.3,0.2,3.2,0.5V13 c-0.8-0.3-2-0.6-3.2-0.6c-1.7,0-3.2,0.9-3.2,3.6c0,2.9,1.5,3.8,3.3,3.8c0.9,0,1.9-0.2,3.2-0.7V21.3z" />
			<path d="M110,15.2c0.2-0.3,0.2-0.8,3.8-5.2h3.7l-4.6,5.7l5,6.3h-3.7l-4.2-5.8V22h-3V6h3V15.2z" />
			<path d="M58.5,21.3c-1.5,0.5-2.7,0.6-4.2,0.6c-3.6,0-5.8-1.8-5.8-6c0-3.1,1.9-5.9,5.5-5.9s4.9,2.5,4.9,4.9c0,0.8,0,1.5-0.1,2h-7.3 c0.1,2.5,1.5,2.8,3.6,2.8c1.1,0,2.2-0.3,3.4-0.7C58.5,19,58.5,21.3,58.5,21.3z M56,15c0-1.4-0.5-2.9-2-2.9c-1.4,0-2.3,1.3-2.4,2.9 C51.6,15,56,15,56,15z" />',
		);
	}

	/**
	 * Return a base64 encoded SVG of the Jetpack logo.
	 * Can be used as a data URI to use the logo inline in CSS.
	 *
	 * @since 1.6.0
	 *
	 * @param string $color The color of the logo.
	 *
	 * @return string
	 */
	public function get_base64_logo( $color = '#ffffff' ) {
		$logo_text    = $this->get_jp_logo_parts( $color );
		$base_logo    = sprintf(
			'<svg xmlns="http://www.w3.org/2000/svg" x="20px" y="20px" viewBox="-4 -5 41 41">%1$s</svg>',
			$logo_text['logo']
		);
		$encoded_logo = base64_encode( $base_logo ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- The encoded version is used as data URI to use the logo in CSS.

		return 'data:image/svg+xml;base64,' . $encoded_logo;
	}
}
