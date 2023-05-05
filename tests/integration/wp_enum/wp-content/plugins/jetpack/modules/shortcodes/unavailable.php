<?php //phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Display a message on the frontend when we retire a shortcode,
 * explaining why the shortcode is not available anymore.
 *
 * @package automattic/jetpack
 */

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

/**
 * Class Jetpack_Shortcode_Unavailable
 */
class Jetpack_Shortcode_Unavailable {
	/**
	 * Shortcodes that are unavailable.
	 *
	 * Key is the shortcode, value is string explaining why.
	 *
	 * @var array
	 */
	public $shortcodes;

	/**
	 * Set up the actions and filters for the class to listen to.
	 *
	 * @param array $shortcodes An associative array of keys being the shortcodes that are unavailable, and a string explaining why.
	 */
	public function __construct( $shortcodes ) {
		$this->shortcodes = $shortcodes;

		add_action( 'template_redirect', array( $this, 'add_shortcodes' ) );
	}

	/**
	 * For all of our defined unavailable shortcodes, if something else hasn't
	 * already claimed them, add a handler to nullify their output.
	 */
	public function add_shortcodes() {
		foreach ( array_keys( $this->shortcodes ) as $shortcode ) {
			if ( ! shortcode_exists( $shortcode ) ) {
				add_shortcode( $shortcode, array( $this, 'stub_shortcode' ) );
			}
		}
	}

	/**
	 * Nullify the output of unavailable shortcodes.  Includes a filter to make
	 * it easier to notify admins that a shortcode that they used is unavailable.
	 *
	 * @param array  $atts      Shortcode attributes.
	 * @param string $content   Post content.
	 * @param string $shortcode Shortcode name.
	 *
	 * @return mixed|void
	 */
	public function stub_shortcode( $atts, $content = '', $shortcode = '' ) {
		$str = '';
		if ( current_user_can( 'edit_posts' ) && ! empty( $this->shortcodes[ $shortcode ] ) ) {
			$str = sprintf( '<div><strong>%s</strong></div>', $this->shortcodes[ $shortcode ] );
		}
		/**
		 * Filter the front-end output of unavailable shortcodes.
		 *
		 * @module shortcodes
		 *
		 * @since 4.5.0
		 *
		 * @param string $str The html displayed in lieu of the shortcode.
		 * @param array $atts The attributes (numeric or named) passed to the shortcode.
		 * @param string $content The content (if any) between the opening and closing tags.
		 * @param string $shortcode The shortcode tag used to invoke this.
		 */
		return apply_filters( 'jetpack_stub_shortcode', $str, $atts, $content, $shortcode );
	}
}

/**
 * Init class.
 */
function jetpack_init_shortcode_unavailable() {
	new Jetpack_Shortcode_Unavailable(
		array(
			'digg'                    => __( 'The Digg API was shut down in 2014.', 'jetpack' ),
			'hulu'                    => __( 'Hulu no longer allows embedding content.', 'jetpack' ),
			'blip.tv'                 => __( 'The Blip.tv service has been shut down since August 20th, 2015.', 'jetpack' ),
			'googlevideo'             => __( 'The Google Video embed service is not available anymore, it has been replaced by YouTube.', 'jetpack' ),
			'jetpack-email-subscribe' => __( 'The Email Subscribe shortcode is now available as a block in the Block editor.', 'jetpack' ),
			'lytro'                   => __( 'Lytro has been shut down since March 2019.', 'jetpack' ),
		)
	);
}
add_action( 'init', 'jetpack_init_shortcode_unavailable' );
