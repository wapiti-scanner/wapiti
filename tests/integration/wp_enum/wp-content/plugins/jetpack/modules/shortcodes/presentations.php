<?php //phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

use Automattic\Jetpack\Assets;

/**
 * Presentations
 * Presentations plugin based on the work done by <a href="http://darylkoop.com/">Daryl Koopersmith</a>. Powered by jmpress.js
 *
 * HOW TO: How the plugin settings are organized and which features are supported.
 *
 * The entire presentation should be wrapped with a [presentation] shortcode, and every
 * individual slide should be wrapped with a [slide] shortcode. Any settings supported
 * by [slide] can be set into [presentation], which will apply that setting for the entire
 * presentation unless overridden by individual slides.
 *
 * - [presentation] only settings:
 *     - duration: transition durations, default is one second.
 *     - height:   content height, default is 400px
 *     - width:    content width, default is 550px
 *     - autoplay: delay between transitions in seconds, default 3s
 *                 when set the presentation will automatically transition between slides
 *                 as long as the presentation remains in focus
 *
 * - [slide] settings:
 *     - transition: specifies where the next slide will be placed relative
 *                   to the last one before it. Supported values are "up", "down"
 *                   "left", "right", or "none". Default value is "down".
 *
 *     - scale:      scales the content relative to other slides, default value is one
 *
 *     - rotate:     rotates the content by the specified degrees, default is zero
 *
 *     - fade:       slides will fade in and out during transition. Values of "on" or
 *                   "true" will enable fading, while values of "no" or "false" will
 *                   disable it. Default value is "on"
 *
 *     - bgcolor:    specifies a background color for the slides. Any CSS valid value
 *                   is permitted. Default color is transparent.
 *
 *     - bgimg:      specifies an image url which will fill the background. Image is
 *                   set to fill the background 100% width and height
 *
 *     - fadebullets: any html <li> tags will start out with an opacity of 0 and any
 *                    subsequent slide transitions will show the bullets one by one
 *
 * Known issues:
 *
 * - IE 7/8 are not supported by jmpress and presentations will not work
 * - IE 9 will not animate transitions at all, though it's possible to at least
 *   switch between slides.
 * - Infinite Scroll themes will not load presentations properly unless the post
 *   happens to be on the first loaded page. The permalink page will function
 *   properly, however.
 * - Exiting fullscreen mode will not properly reset the scroll locations in Safari
 *
 * @package automattic/jetpack
 */

if ( ! class_exists( 'Presentations' ) ) :
	/**
	 * Create a shortcode to display Presentations and slides.
	 */
	class Presentations {

		/**
		 * Presentation settings.
		 *
		 * @var array
		 */
		private $presentation_settings;
		/**
		 * Do we have a Presentation shortcode to be displayed.
		 *
		 * @var bool
		 */
		private $presentation_initialized;
		/**
		 * Were scripts and styles enqueued already.
		 *
		 * @var bool
		 */
		private $scripts_and_style_included;

		/**
		 * Constructor
		 */
		public function __construct() {
			$this->presentation_initialized   = false;
			$this->scripts_and_style_included = false;

			// Registers shortcodes.
			add_action( 'wp_head', array( $this, 'add_scripts' ), 1 );

			add_shortcode( 'presentation', array( $this, 'presentation_shortcode' ) );
			add_shortcode( 'slide', array( $this, 'slide_shortcode' ) );
		}

		/**
		 * Enqueue all scripts and styles.
		 */
		public function add_scripts() {
			$this->scripts_and_style_included = false;

			if ( empty( $GLOBALS['posts'] ) || ! is_array( $GLOBALS['posts'] ) ) {
				return;
			}

			foreach ( $GLOBALS['posts'] as $p ) {
				if ( isset( $p->post_content ) && has_shortcode( $p->post_content, 'presentation' ) ) {
					$this->scripts_and_style_included = true;
					break;
				}
			}

			if ( ! $this->scripts_and_style_included ) {
				return;
			}

			$plugin = plugin_dir_url( __FILE__ );
			// Add CSS.
			wp_enqueue_style( 'presentations', $plugin . 'css/style.css', array(), JETPACK__VERSION );
			// Add JavaScript.
			wp_enqueue_script( 'jquery' );
			wp_enqueue_script(
				'jmpress',
				Assets::get_file_url_for_environment( '_inc/build/shortcodes/js/jmpress.min.js', 'modules/shortcodes/js/jmpress.js' ),
				array( 'jquery' ),
				JETPACK__VERSION,
				true
			);
			wp_enqueue_script(
				'presentations',
				Assets::get_file_url_for_environment( '_inc/build/shortcodes/js/main.min.js', 'modules/shortcodes/js/main.js' ),
				array( 'jquery', 'jmpress' ),
				JETPACK__VERSION,
				true
			);
		}

		/**
		 * Main Presentation shortcode.
		 *
		 * @param array  $atts    Shortcode attributes.
		 * @param string $content Post content.
		 */
		public function presentation_shortcode( $atts, $content = '' ) {
			// Mark that we've found a valid [presentation] shortcode.
			$this->presentation_initialized = true;

			$atts = shortcode_atts(
				array(
					'duration'    => '',
					'height'      => '',
					'width'       => '',
					'bgcolor'     => '',
					'bgimg'       => '',
					'autoplay'    => '',

					// Settings.
					'transition'  => '',
					'scale'       => '',
					'rotate'      => '',
					'fade'        => '',
					'fadebullets' => '',
				),
				$atts,
				'presentation'
			);

			$this->presentation_settings = array(
				'transition'  => 'down',
				'scale'       => 1,
				'rotate'      => 0,
				'fade'        => 'on',
				'fadebullets' => 0,
				'last'        => array(
					'x'      => 0,
					'y'      => 0,
					'scale'  => 1,
					'rotate' => 0,
				),
			);

			// Set the presentation-wide settings.
			if ( '' !== trim( $atts['transition'] ) ) {
				$this->presentation_settings['transition'] = $atts['transition'];
			}

			if ( '' !== trim( $atts['scale'] ) ) {
				$this->presentation_settings['scale'] = (float) $atts['scale'];
			}

			if ( '' !== trim( $atts['rotate'] ) ) {
				$this->presentation_settings['rotate'] = (float) $atts['rotate'];
			}

			if ( '' !== trim( $atts['fade'] ) ) {
				$this->presentation_settings['fade'] = $atts['fade'];
			}

			if ( '' !== trim( $atts['fadebullets'] ) ) {
				$this->presentation_settings['fadebullets'] = $atts['fadebullets'];
			}

			// Set any settings the slides don't care about.
			if ( '' !== trim( $atts['duration'] ) ) {
				$duration = (float) $atts['duration'] . 's';
			} else {
				$duration = '1s';
			}

			// Autoplay durations are set in milliseconds.
			if ( '' !== trim( $atts['autoplay'] ) ) {
				$autoplay = (float) $atts['autoplay'] * 1000;
			} else {
				$autoplay = 0;
			} // No autoplay

			// Set the presentation size as specified or with some nicely sized dimensions.
			if ( '' !== trim( $atts['width'] ) ) {
				$this->presentation_settings['width'] = (int) $atts['width'];
			} else {
				$this->presentation_settings['width'] = 480;
			}

			if ( '' !== trim( $atts['height'] ) ) {
				$this->presentation_settings['height'] = (int) $atts['height'];
			} else {
				$this->presentation_settings['height'] = 370;
			}

			// Hide the content by default in case the scripts fail.
			$style = 'display: none; width: ' . $this->presentation_settings['width'] . 'px; height: ' . $this->presentation_settings['height'] . 'px;';

			/*
			 * Check for background color XOR background image
			 * Use a white background if nothing specified
			 */
			if ( preg_match( '/https?\:\/\/[^\'"\s]*/', $atts['bgimg'], $matches ) ) {
				$style .= ' background-image: url("' . esc_url( $matches[0] ) . '");';
			} elseif ( '' !== trim( $atts['bgcolor'] ) ) {
				$style .= ' background-color: ' . esc_attr( $atts['bgcolor'] ) . ';';
			} else {
				$style .= ' background-color: #fff;';
			}

			// Not supported message style is inlined incase the style sheet doesn't get included.
			$out  = "<section class='presentation-wrapper'>";
			$out .= "<p class='not-supported-msg' style='display: inherit; padding: 25%; text-align: center;'>";
			$out .= __( 'This slideshow could not be started. Try refreshing the page or viewing it in another browser.', 'jetpack' ) . '</p>';

			$out .= sprintf(
				'<div class="presentation" duration="%s" data-autoplay="%s" style="%s">',
				esc_attr( $duration ),
				esc_attr( $autoplay ),
				esc_attr( $style )
			);
			$out .= "<div class='nav-arrow-left'></div>";
			$out .= "<div class='nav-arrow-right'></div>";
			$out .= "<div class='nav-fullscreen-button'></div>";

			if ( $autoplay ) {
				$out .= '<div class="autoplay-overlay" style="display: none;"><p class="overlay-msg">';
				$out .= __( 'Click to autoplay the presentation!', 'jetpack' );
				$out .= '</p></div>';
			}

			$out .= do_shortcode( $content );

			$out .= '</section>';

			$this->presentation_initialized = false;

			return $out;
		}

		/**
		 * Slide shortcode.
		 *
		 * @param array  $atts    Shortcode attributes.
		 * @param string $content Post content.
		 */
		public function slide_shortcode( $atts, $content = '' ) {
			// Bail out unless wrapped by a [presentation] shortcode.
			if ( ! $this->presentation_initialized ) {
				return $content;
			}

			$atts = shortcode_atts(
				array(
					'transition'  => '',
					'scale'       => '',
					'rotate'      => '',
					'fade'        => '',
					'fadebullets' => '',
					'bgcolor'     => '',
					'bgimg'       => '',
				),
				$atts,
				'slide'
			);

			// Determine positioning based on transition.
			if ( '' === trim( $atts['transition'] ) ) {
				$atts['transition'] = $this->presentation_settings['transition'];
			}

			// Setting the content scale.
			if ( '' === trim( $atts['scale'] ) ) {
				$atts['scale'] = $this->presentation_settings['scale'];
			}

			if ( '' === trim( $atts['scale'] ) ) {
				$scale = 1;
			} else {
				$scale = (float) $atts['scale'];
			}

			if ( $scale < 0 ) {
				$scale *= -1;
			}

			// Setting the content rotation.
			if ( '' === trim( $atts['rotate'] ) ) {
				$atts['rotate'] = $this->presentation_settings['rotate'];
			}

			if ( '' === trim( $atts['rotate'] ) ) {
				$rotate = 0;
			} else {
				$rotate = (float) $atts['rotate'];
			}

			// Setting if the content should fade.
			if ( '' === trim( $atts['fade'] ) ) {
				$atts['fade'] = $this->presentation_settings['fade'];
			}

			if ( 'on' === $atts['fade'] || 'true' === $atts['fade'] ) {
				$fade = 'fade';
			} else {
				$fade = '';
			}

			// Setting if bullets should fade on step changes.
			if ( '' === trim( $atts['fadebullets'] ) ) {
				$atts['fadebullets'] = $this->presentation_settings['fadebullets'];
			}

			if ( 'on' === $atts['fadebullets'] || 'true' === $atts['fadebullets'] ) {
				$fadebullets = 'fadebullets';
			} else {
				$fadebullets = '';
			}

			$coords = $this->get_coords(
				array(
					'transition' => $atts['transition'],
					'scale'      => $scale,
					'rotate'     => $rotate,
				)
			);

			$x = $coords['x'];
			$y = $coords['y'];

			/*
			 * Check for background color XOR background image
			 * Use a white background if nothing specified
			 */
			if ( preg_match( '/https?\:\/\/[^\'"\s]*/', $atts['bgimg'], $matches ) ) {
				$style = 'background-image: url("' . esc_url( $matches[0] ) . '");';
			} elseif ( '' !== trim( $atts['bgcolor'] ) ) {
				$style = 'background-color: ' . esc_attr( $atts['bgcolor'] ) . ';';
			} else {
				$style = '';
			}

			// Put everything together and let jmpress do the magic!
			$out = sprintf(
				'<div class="step %s %s" data-x="%s" data-y="%s" data-scale="%s" data-rotate="%s" style="%s">',
				esc_attr( $fade ),
				esc_attr( $fadebullets ),
				esc_attr( $x ),
				esc_attr( $y ),
				esc_attr( $scale ),
				esc_attr( $rotate ),
				esc_attr( $style )
			);

			$out .= '<div class="slide-content">';
			$out .= do_shortcode( $content );
			$out .= '</div></div>';

			return $out;
		}

		/**
		 * Determines the position of the next slide based on the position and scaling of the previous slide.
		 *
		 * @param array $args {
		 * Array of key-value pairs.
		 *
		 *  @type string $transition: the transition name, "up", "down", "left", or "right".
		 *  @type float $scale: the scale of the next slide (used to determine the position of the slide after that).
		 * }
		 *
		 * @return array with the 'x' and 'y' coordinates of the slide.
		 */
		private function get_coords( $args ) {
			if ( 0 === $args['scale'] ) {
				$args['scale'] = 1;
			}

			$width  = $this->presentation_settings['width'];
			$height = $this->presentation_settings['height'];
			$last   = $this->presentation_settings['last'];
			$scale  = $last['scale'];

			$next = array(
				'x'      => $last['x'],
				'y'      => $last['y'],
				'scale'  => $args['scale'],
				'rotate' => $args['rotate'],
			);

			// All angles are measured from the vertical axis, so everything is backwards!
			$diag_angle = atan2( $width, $height );
			$diagonal   = sqrt( pow( $width, 2 ) + pow( $height, 2 ) );

			/*
			 * We offset the angles by the angle formed by the diagonal so that
			 * we can multiply the sines directly against the diagonal length
			 */
			$theta = deg2rad( $last['rotate'] ) - $diag_angle;
			$phi   = deg2rad( $next['rotate'] ) - $diag_angle;

			// We start by displacing by the slide dimensions.
			$total_horiz_disp = $width * $scale;
			$total_vert_disp  = $height * $scale;

			/*
			 * If the previous slide was rotated, we add the incremental offset from the rotation
			 * Namely the difference between the regular dimension (no rotation) and the component
			 * of the diagonal for that angle
			 */
			$total_horiz_disp += ( ( ( abs( sin( $theta ) ) * $diagonal ) - $width ) / 2 ) * $scale;
			$total_vert_disp  += ( ( ( abs( cos( $theta ) ) * $diagonal ) - $height ) / 2 ) * $scale;

			/*
			 * Similarly, we check if the current slide has been rotated and add whatever additional
			 * offset has been added. This is so that two rotated corners don't clash with each other.
			 * Note: we are checking the raw angle relative to the vertical axis, NOT the diagonal angle.
			 */
			if ( 0 !== $next['rotate'] % 180 ) {
				$total_horiz_disp += ( abs( ( sin( $phi ) * $diagonal ) - $width ) / 2 ) * $next['scale'];
				$total_vert_disp  += ( abs( ( cos( $phi ) * $diagonal ) - $height ) / 2 ) * $next['scale'];
			}

			switch ( trim( $args['transition'] ) ) {
				case 'none':
					break;

				case 'left':
					$next['x'] -= $total_horiz_disp;
					break;

				case 'right':
					$next['x'] += $total_horiz_disp;
					break;

				case 'up':
					$next['y'] -= $total_vert_disp;
					break;

				case 'down':
				default:
					$next['y'] += $total_vert_disp;
					break;
			}

			$this->presentation_settings['last'] = $next;

			return $next;
		}
	}

	$GLOBALS['presentations'] = new Presentations();
endif;
