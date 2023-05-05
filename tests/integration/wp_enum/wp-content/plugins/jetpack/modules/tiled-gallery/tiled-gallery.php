<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Status;

// Include the class file containing methods for rounding constrained array elements.
// Here the constrained array element is the dimension of a row, group or an image in the tiled gallery.
require_once __DIR__ . '/math/class-constrained-array-rounding.php';

// Layouts
require_once __DIR__ . '/tiled-gallery/tiled-gallery-rectangular.php';
require_once __DIR__ . '/tiled-gallery/tiled-gallery-square.php';
require_once __DIR__ . '/tiled-gallery/tiled-gallery-circle.php';

/**
 * Jetpack tiled gallery class.
 */
class Jetpack_Tiled_Gallery {
	/**
	 * Supported gallery design types.
	 *
	 * @var array
	 */
	private static $talaveras = array( 'rectangular', 'square', 'circle', 'rectangle', 'columns' );

	/**
	 * Class constructor.
	 */
	public function __construct() {
		add_action( 'admin_init', array( $this, 'settings_api_init' ) );
		add_filter( 'jetpack_gallery_types', array( $this, 'jetpack_gallery_types' ), 9 );
		add_filter( 'jetpack_default_gallery_type', array( $this, 'jetpack_default_gallery_type' ) );
	}

	/**
	 * Check whether tiling is enabled.
	 *
	 * @return bool
	 */
	public function tiles_enabled() {
		return '' !== Jetpack_Options::get_option_and_ensure_autoload( 'tiled_galleries', '' );
	}

	/**
	 * Set attributes.
	 *
	 * @param array $atts - the attributes.
	 */
	public function set_atts( $atts ) {
		global $post;

		$this->atts = shortcode_atts(
			array(
				'order'     => 'ASC',
				'orderby'   => 'menu_order ID',
				'id'        => isset( $post->ID ) ? $post->ID : 0,
				'include'   => '',
				'exclude'   => '',
				'type'      => '',
				'grayscale' => false,
				'link'      => '',
				'columns'   => 3,
			),
			$atts,
			'gallery'
		);

		$this->atts['id'] = (int) $this->atts['id'];
		$this->float      = is_rtl() ? 'right' : 'left';

		// Default to rectangular is tiled galleries are checked
		if ( $this->tiles_enabled() && ( ! $this->atts['type'] || 'default' === $this->atts['type'] ) ) {
			/** This filter is already documented in class-jetpack-gallery-settings.php */
			$this->atts['type'] = apply_filters( 'jetpack_default_gallery_type', 'rectangular' );
		}

		if ( ! $this->atts['orderby'] ) {
			$this->atts['orderby'] = sanitize_sql_orderby( $this->atts['orderby'] );
			if ( ! $this->atts['orderby'] ) {
				$this->atts['orderby'] = 'menu_order ID';
			}
		}

		if ( 'rand' === strtolower( $this->atts['order'] ) ) {
			$this->atts['orderby'] = 'rand';
		}

		// We shouldn't have more than 20 columns.
		if ( ! is_numeric( $this->atts['columns'] ) || 20 < $this->atts['columns'] ) {
			$this->atts['columns'] = 3;
		}
	}

	/**
	 * Get the media attachments.
	 *
	 * @return WP_Post[]
	 */
	public function get_attachments() {
		$atts = $this->atts;

		if ( ! empty( $atts['include'] ) ) {
			$include      = preg_replace( '/[^0-9,]+/', '', $atts['include'] );
			$_attachments = get_posts(
				array(
					'include'          => $include,
					'post_status'      => 'inherit',
					'post_type'        => 'attachment',
					'post_mime_type'   => 'image',
					'order'            => $atts['order'],
					'orderby'          => $atts['orderby'],
					'suppress_filters' => false,
				)
			);

			$attachments = array();
			foreach ( $_attachments as $key => $val ) {
				$attachments[ $val->ID ] = $_attachments[ $key ];
			}
		} elseif ( 0 === $atts['id'] ) {
			/*
			 * Should NEVER Happen but infinite_scroll_load_other_plugins_scripts means it does
			 * Querying with post_parent == 0 can generate stupidly memcache sets
			 * on sites with 10000's of unattached attachments as get_children puts every post in the cache.
			 * TODO Fix this properly.
			 */
			$attachments = array();
		} elseif ( ! empty( $atts['exclude'] ) ) {
			$exclude     = preg_replace( '/[^0-9,]+/', '', $atts['exclude'] );
			$attachments = get_children(
				array(
					'post_parent'      => $atts['id'],
					'exclude'          => $exclude,
					'post_status'      => 'inherit',
					'post_type'        => 'attachment',
					'post_mime_type'   => 'image',
					'order'            => $atts['order'],
					'orderby'          => $atts['orderby'],
					'suppress_filters' => false,
				)
			);
		} else {
			$attachments = get_children(
				array(
					'post_parent'      => $atts['id'],
					'post_status'      => 'inherit',
					'post_type'        => 'attachment',
					'post_mime_type'   => 'image',
					'order'            => $atts['order'],
					'orderby'          => $atts['orderby'],
					'suppress_filters' => false,
				)
			);
		}
		return $attachments;
	}

	/**
	 * Enqueue the default scripts and styles.
	 */
	public static function default_scripts_and_styles() {
		wp_enqueue_script(
			'tiled-gallery',
			Assets::get_file_url_for_environment(
				'_inc/build/tiled-gallery/tiled-gallery/tiled-gallery.min.js',
				'modules/tiled-gallery/tiled-gallery/tiled-gallery.js'
			),
			array(),
			JETPACK__VERSION,
			false
		);
		wp_enqueue_style( 'tiled-gallery', plugins_url( 'tiled-gallery/tiled-gallery.css', __FILE__ ), array(), '2012-09-21' );
		wp_style_add_data( 'tiled-gallery', 'rtl', 'replace' );
	}

	/**
	 * The gallery shortcode.
	 *
	 * @param mixed $val - the value.
	 * @param array $atts - the attributes.
	 *
	 * @return string
	 */
	public function gallery_shortcode( $val, $atts ) {
		if ( ! empty( $val ) ) { // something else is overriding post_gallery, like a custom VIP shortcode
			return $val;
		}

		$this->set_atts( $atts );

		$attachments = $this->get_attachments();
		if ( empty( $attachments ) ) {
			return '';
		}

		if ( is_feed() || defined( 'IS_HTML_EMAIL' ) ) {
			return '';
		}

		/**
		 * Filters the permissible Tiled Gallery types.
		 *
		 * @module tiled-gallery
		 *
		 * @since 3.7.0
		 *
		 * @param array Array of allowed types. Default: 'rectangular', 'square', 'circle', 'rectangle', 'columns'.
		 */
		$talaveras = apply_filters( 'jetpack_tiled_gallery_types', self::$talaveras );

		if ( in_array( $this->atts['type'], $talaveras, true ) ) {
			// Enqueue styles and scripts
			self::default_scripts_and_styles();

			// Generate gallery HTML
			$gallery_class = 'Jetpack_Tiled_Gallery_Layout_' . ucfirst( $this->atts['type'] );
			$gallery       = new $gallery_class( $attachments, $this->atts['link'], $this->atts['grayscale'], (int) $this->atts['columns'] );
			$gallery_html  = $gallery->HTML();

			if ( $gallery_html && class_exists( 'Jetpack' ) && class_exists( 'Jetpack_Photon' ) ) {
				// Tiled Galleries in Jetpack require that Photon be active.
				// If it's not active, run it just on the gallery output.
				if ( ! in_array( 'photon', Jetpack::get_active_modules(), true ) && ! ( new Status() )->is_offline_mode() ) {
					$gallery_html = Jetpack_Photon::filter_the_content( $gallery_html );
				}
			}

			return trim( preg_replace( '/\s+/', ' ', $gallery_html ) ); // remove any new lines from the output so that the reader parses it better
		}

		return '';
	}

	/**
	 * See if gallery is already defined.
	 *
	 * @return bool
	 */
	public static function gallery_already_redefined() {
		global $shortcode_tags;
		$redefined = false;
		if ( ! isset( $shortcode_tags['gallery'] ) || $shortcode_tags['gallery'] !== 'gallery_shortcode' ) {
			$redefined = true;
		}
		/**
		 * Filter the output of the check for another plugin or theme affecting WordPress galleries.
		 *
		 * This will let folks that replace core’s shortcode confirm feature parity with it, so Jetpack's Tiled Galleries can still work.
		 *
		 * @module tiled-gallery
		 *
		 * @since 3.1.0
		 *
		 * @param bool $redefined Does another plugin or theme already redefines the default WordPress gallery?
		 */
		return apply_filters( 'jetpack_tiled_gallery_shortcode_redefined', $redefined );
	}

	/**
	 * Initialize the tiled gallery.
	 */
	public static function init() {
		if ( self::gallery_already_redefined() ) {
			return;
		}

		$gallery = new Jetpack_Tiled_Gallery();
		add_filter( 'post_gallery', array( $gallery, 'gallery_shortcode' ), 1001, 2 );
	}

	/**
	 * Get the width of the gallery.
	 *
	 * @return int
	 */
	public static function get_content_width() {
		$tiled_gallery_content_width = Jetpack::get_content_width();

		if ( ! $tiled_gallery_content_width ) {
			$tiled_gallery_content_width = 500;
		}

		/**
		 * Filter overwriting the default content width.
		 *
		 * @module tiled-gallery
		 *
		 * @since 2.1.0
		 *
		 * @param string $tiled_gallery_content_width Default Tiled Gallery content width.
		 */
		return apply_filters( 'tiled_gallery_content_width', $tiled_gallery_content_width );
	}

	/**
	 * Media UI integration
	 *
	 * @param array $types - the type of gallery.
	 *
	 * @return array
	 */
	public function jetpack_gallery_types( $types ) {
		if ( get_option( 'tiled_galleries' ) && isset( $types['default'] ) ) {
			// Tiled is set as the default, meaning that type='default'
			// will still display the mosaic.
			$types['thumbnails'] = $types['default'];
			unset( $types['default'] );
		}

		$types['rectangular'] = __( 'Tiled Mosaic', 'jetpack' );
		$types['square']      = __( 'Square Tiles', 'jetpack' );
		$types['circle']      = __( 'Circles', 'jetpack' );
		$types['columns']     = __( 'Tiled Columns', 'jetpack' );

		return $types;
	}

	/**
	 * Get the default gallery type.
	 *
	 * @return string
	 */
	public function jetpack_default_gallery_type() {
		return ( get_option( 'tiled_galleries' ) ? 'rectangular' : 'default' );
	}

	/**
	 * Get the talaveras.
	 *
	 * @return array
	 */
	public static function get_talaveras() {
		return self::$talaveras;
	}

	/**
	 * Add a checkbox field to the Carousel section in Settings > Media
	 * for setting tiled galleries as the default.
	 */
	public function settings_api_init() {
		global $wp_settings_sections;

		// Add the setting field [tiled_galleries] and place it in Settings > Media
		if ( isset( $wp_settings_sections['media']['carousel_section'] ) ) {
			$section = 'carousel_section';
		} else {
			$section = 'default';
		}

		add_settings_field( 'tiled_galleries', __( 'Tiled Galleries', 'jetpack' ), array( $this, 'setting_html' ), 'media', $section );
		register_setting( 'media', 'tiled_galleries', 'esc_attr' );
	}

	/**
	 * Render the settings HTML.
	 */
	public function setting_html() {
		echo '<label><input name="tiled_galleries" type="checkbox" value="1" ' .
			checked( 1, '' !== get_option( 'tiled_galleries' ), false ) . ' /> ' .
			esc_html__( 'Display all your gallery pictures in a cool mosaic.', 'jetpack' ) . '</br></label>';
	}
}

add_action( 'init', array( 'Jetpack_Tiled_Gallery', 'init' ) );
