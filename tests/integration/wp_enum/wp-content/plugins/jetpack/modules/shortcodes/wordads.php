<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Wordads shortcode.
 *
 * Examples:
 * [wordads]
 *
 * @package automattic/jetpack
 */

/**
 * Embed WordAds 'ad' in post
 */
class Jetpack_WordAds_Shortcode {

	/**
	 * Used to determine whether scripts and styles have been enqueued already.
	 *
	 * @var bool false Should we enqueue scripts and styles.
	 */
	private $scripts_and_style_included = false;

	/**
	 * Initialize.
	 */
	public function __construct() {
		add_action( 'init', array( $this, 'action_init' ) );
	}

	/**
	 * Register our shortcode and enqueue necessary files.
	 */
	public function action_init() {
		global $wordads;

		if ( empty( $wordads ) ) {
			return null;
		}

		add_shortcode( 'wordads', array( $this, 'wordads_shortcode' ) );
	}

	/**
	 * Our [wordads] shortcode.
	 * Prints a WordAds Ad.
	 *
	 * @param array  $atts    Array of shortcode attributes.
	 * @param string $content Post content.
	 *
	 * @return string HTML for WordAds shortcode.
	 */
	public static function wordads_shortcode( $atts, $content = '' ) {
		$atts = shortcode_atts( array(), $atts, 'wordads' );

		return self::wordads_shortcode_html( $atts, $content );
	}

	/**
	 * The shortcode output
	 *
	 * @param array  $atts    Array of shortcode attributes.
	 * @param string $content Post content.
	 *
	 * @return string HTML output
	 */
	private static function wordads_shortcode_html( $atts, $content = '' ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		global $wordads;

		if ( empty( $wordads ) ) {
			return '<div>' . __( 'The WordAds module is not active', 'jetpack' ) . '</div>';
		}

		$html = '<div class="jetpack-wordad" itemscope itemtype="https://schema.org/WPAdBlock"></div>';
		$html = $wordads->insert_inline_ad( $html );

		return $html;
	}
}

new Jetpack_WordAds_Shortcode();
