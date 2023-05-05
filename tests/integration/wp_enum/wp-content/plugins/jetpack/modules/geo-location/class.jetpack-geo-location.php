<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Adds support for geo-location features.
 *
 * All Jetpack sites can support geo-location features.  Users can tag posts with geo-location data
 * using the UI provided by Calypso.  That information will be included in RSS feeds, meta tags during
 * wp_head, and in the Geo microformat following post content.
 *
 * If your theme declares support for "geo-location", you'll also get a small icon and location label
 * visible to users at the bottom of single posts and pages.
 *
 * To declare support in your theme, call `add_theme_support( 'jetpack-geo-location' )`.
 *
 * Once you've added theme support, you can rely on the standard HTML output generated in the
 * the_content_location_display() method of this class.  Or, you can use the "geo_location_display"
 * filter to generate custom HTML for your particular theme.  Your filter function will receive an
 * the default HTML as its first argument and an array containing the geo-location information as
 * its second argument in the following format:
 *
 * array(
 *     'is_public'    => boolean,
 *     'latitude'     => float,
 *     'longitude'    => float,
 *     'label'        => string,
 *     'is_populated' => boolean
 * )
 *
 * Add your filter with:
 *
 * add_filter( 'jetpack_geo_location_display', 'your_filter_function_name', 10, 2);
 */
class Jetpack_Geo_Location {
	/**
	 * Jetpack_Geo_Location singleton instance.
	 *
	 * @var Jetpack_Geo_Location|null
	 */
	private static $instance;

	/**
	 * Whether dashicons are enqueued.
	 *
	 * @since 6.6.0
	 *
	 * @var bool
	 */
	private static $style_enqueued = false;

	/**
	 * Jetpack_Geo_Location instance init.
	 */
	public static function init() {
		if ( self::$instance === null ) {
			self::$instance = new Jetpack_Geo_Location();
		}

		return self::$instance;
	}

	/**
	 * This is mostly just used for testing purposes.
	 */
	public static function reset_instance() {
		self::$instance = null;
	}

	/**
	 * Jetpack_Geo_Location class constructor.
	 */
	public function __construct() {
		add_action( 'init', array( $this, 'wordpress_init' ) );
		add_action( 'wp_head', array( $this, 'wp_head' ) );
		add_filter( 'the_content', array( $this, 'the_content_microformat' ) );

		$this->register_rss_hooks();
	}

	/**
	 * Register support for the geo-location feature on pages and posts.  Register the meta
	 * fields managed by this plugin so that they are properly sanitized during save.
	 */
	public function wordpress_init() {
		// Only render location label after post content, if the theme claims to support "geo-location".
		if ( current_theme_supports( 'jetpack-geo-location' ) ) {
			add_filter( 'the_content', array( $this, 'the_content_location_display' ), 15, 1 );
		}

		add_post_type_support( 'post', 'geo-location' );
		add_post_type_support( 'page', 'geo-location' );

		register_meta(
			'post',
			'geo_public',
			array(
				'sanitize_callback' => array( $this, 'sanitize_public' ),
				'type'              => 'boolean',
				'single'            => true,
			)
		);

		register_meta(
			'post',
			'geo_latitude',
			array(
				'sanitize_callback' => array( $this, 'sanitize_coordinate' ),
				'type'              => 'float',
				'single'            => true,
			)
		);

		register_meta(
			'post',
			'geo_longitude',
			array(
				'sanitize_callback' => array( $this, 'sanitize_coordinate' ),
				'type'              => 'float',
				'single'            => true,
			)
		);

		register_meta(
			'post',
			'geo_address',
			array(
				'sanitize_callback' => 'sanitize_text_field',
				'type'              => 'string',
				'single'            => true,
			)
		);
	}

	/**
	 * Filter "public" input to always be either 1 or 0.
	 *
	 * @param mixed $public Value to normalize.
	 *
	 * @return int
	 */
	public function sanitize_public( $public ) {
		return absint( $public ) ? 1 : 0;
	}

	/**
	 * Filter geo coordinates and normalize them to floats with 7 digits of precision.
	 *
	 * @param mixed $coordinate Latitude or longitude coordinate.
	 *
	 * @return float|null
	 */
	public function sanitize_coordinate( $coordinate ) {
		if ( ! $coordinate ) {
			return null;
		}

		return round( (float) $coordinate, 7 );
	}

	/**
	 * Render geo.position and ICBM meta tags with public geo meta values when rendering
	 * a single post.
	 */
	public function wp_head() {
		if ( ! is_single() ) {
			return;
		}

		$meta_values = $this->get_meta_values( $this->get_post_id() );

		if ( ! $meta_values['is_public'] ) {
			return;
		}

		if ( ! self::$style_enqueued ) {
			// only enqueue scripts and styles when needed.
			self::enqueue_scripts();
			self::$style_enqueued = true;
		}

		echo "\n<!-- Jetpack Geo-location Tags -->\n";

		if ( $meta_values['label'] ) {
			printf(
				'<meta name="geo.placename" content="%s" />',
				esc_attr( $meta_values['label'] )
			);
		}

		printf(
			'<meta name="geo.position" content="%s;%s" />' . PHP_EOL,
			esc_attr( $meta_values['latitude'] ),
			esc_attr( $meta_values['longitude'] )
		);

		printf(
			'<meta name="ICBM" content="%s, %s" />' . PHP_EOL,
			esc_attr( $meta_values['latitude'] ),
			esc_attr( $meta_values['longitude'] )
		);

		echo "\n<!-- End Jetpack Geo-location Tags -->\n";
	}

	/**
	 * Append public meta values in the Geo microformat (https://en.wikipedia.org/wiki/Geo_(microformat)
	 * to the supplied content.
	 *
	 * Note that we cannot render the microformat in the context of an excerpt because tags are stripped
	 * in that context, making our microformat data visible.
	 *
	 * @param string $content Current post content.
	 *
	 * @return string
	 */
	public function the_content_microformat( $content ) {
		if ( is_feed() || $this->is_currently_excerpt_filter() ) {
			return $content;
		}

		$meta_values = $this->get_meta_values( $this->get_post_id() );

		if ( ! $meta_values['is_public'] ) {
			return $content;
		}

		$microformat = sprintf(
			'<div id="geo-post-%d" class="geo geo-post" style="display: none">',
			esc_attr( $this->get_post_id() )
		);

		$microformat .= sprintf(
			'<span class="latitude">%s</span>',
			esc_html( $meta_values['latitude'] )
		);

		$microformat .= sprintf(
			'<span class="longitude">%s</span>',
			esc_html( $meta_values['longitude'] )
		);

		$microformat .= '</div>';

		return $content . $microformat;
	}

	/**
	 * Register a range of hooks for integrating geo data with various feeds.
	 */
	public function register_rss_hooks() {
		add_action( 'rss2_ns', array( $this, 'rss_namespace' ) );
		add_action( 'atom_ns', array( $this, 'rss_namespace' ) );
		add_action( 'rdf_ns', array( $this, 'rss_namespace' ) );
		add_action( 'rss_item', array( $this, 'rss_item' ) );
		add_action( 'rss2_item', array( $this, 'rss_item' ) );
		add_action( 'atom_entry', array( $this, 'rss_item' ) );
		add_action( 'rdf_item', array( $this, 'rss_item' ) );
	}

	/**
	 * Add the georss namespace during RSS generation.
	 */
	public function rss_namespace() {
		echo PHP_EOL . "\t" . 'xmlns:georss="http://www.georss.org/georss"';
		echo PHP_EOL . "\t" . 'xmlns:geo="http://www.w3.org/2003/01/geo/wgs84_pos#"';
		echo PHP_EOL . "\t";
	}

	/**
	 * Output georss data for RSS items, assuming we have data for the currently rendered post and
	 * that data as marked as public.
	 */
	public function rss_item() {
		$meta_values = $this->get_meta_values( $this->get_post_id() );

		if ( ! $meta_values['is_public'] ) {
			return;
		}

		printf(
			"\t<georss:point>%s %s</georss:point>\n",
			ent2ncr( esc_html( $meta_values['latitude'] ) ),
			ent2ncr( esc_html( $meta_values['longitude'] ) )
		);

		printf( "\t\t<geo:lat>%s</geo:lat>\n", ent2ncr( esc_html( $meta_values['latitude'] ) ) );
		printf( "\t\t<geo:long>%s</geo:long>\n", ent2ncr( esc_html( $meta_values['longitude'] ) ) );
	}

	/**
	 * Enqueue CSS for rendering post flair with geo-location.
	 */
	private static function enqueue_scripts() {
		wp_enqueue_style( 'dashicons' );
	}

	/**
	 * If we're rendering a single post and public geo-location data is available for it,
	 * include the human-friendly location label in the output.
	 *
	 * @param string $content Current post content.
	 *
	 * @return string
	 */
	public function the_content_location_display( $content ) {
		if ( ! is_single() ) {
			return $content;
		}

		return $content . $this->get_location_label();
	}

	/**
	 * Get the HTML for displaying a label representing the location associated with the
	 * supplied post ID.  If no post ID is given, we'll use the global $post variable, if
	 * it is available.
	 *
	 * @param integer|null $post_id Post ID.
	 *
	 * @return string
	 */
	public function get_location_label( $post_id = null ) {
		$meta_values = $this->get_meta_values( $post_id ? $post_id : $this->get_post_id() );

		if ( ! $meta_values['is_public'] ) {
			return '';
		}

		// If the location has not been labeled, do not show the location.
		if ( ! $meta_values['label'] ) {
			return '';
		}

		$html  = '<div class="post-geo-location-label geo-chip">';
		$html .= '<span class="dashicons dashicons-location" style="vertical-align: text-top;"></span> ';
		$html .= esc_html( $meta_values['label'] );
		$html .= '</div>';

		/**
		 * Allow modification or replacement of the default geo-location display HTML.
		 *
		 * @module geo-location
		 *
		 * @param array $html The default HTML for displaying a geo-location label.
		 * @param array $geo_data An array containing "latitude", "longitude" and "label".
		 */
		$html = apply_filters( 'jetpack_geo_location_display', $html, $meta_values );

		return $html;
	}

	/**
	 * Get the ID of the current global post object, if available.  Otherwise, return null.
	 *
	 * This isolates the access of the global scope to this single method, making it easier to
	 * safeguard against unexpected missing $post objects in other hook functions.
	 *
	 * @return int|null
	 */
	public function get_post_id() {
		global $post;

		if ( ! isset( $post ) || ! $post || ! is_object( $post ) || ! isset( $post->ID ) ) {
			return null;
		}

		return $post->ID;
	}

	/**
	 * Retrieve geo-location post_meta data for the specified post ID.
	 *
	 * This method always returns an array with the following structure:
	 *
	 * array(is_public => bool, latitude => float, longitude => float, label => string, is_populated => bool)
	 *
	 * So, regardless of whether your post actually has values in postmeta for the geo-location fields,
	 * you can be sure that you can reference those array keys in calling code without having to juggle
	 * isset(), array_key_exists(), etc.
	 *
	 * Mocking this method during testing can also be useful for testing output and logic in various
	 * hook functions.
	 *
	 * @param integer $post_id Post ID.
	 *
	 * @return array A predictably structured array representing the meta values for the supplied post ID.
	 */
	public function get_meta_values( $post_id ) {
		$meta_values = array(
			'is_public'    => (bool) $this->sanitize_public( $this->get_meta_value( $post_id, 'public' ) ),
			'latitude'     => $this->sanitize_coordinate( $this->get_meta_value( $post_id, 'latitude' ) ),
			'longitude'    => $this->sanitize_coordinate( $this->get_meta_value( $post_id, 'longitude' ) ),
			'label'        => trim( (string) $this->get_meta_value( $post_id, 'address' ) ),
			'is_populated' => false,
		);

		if ( $meta_values['latitude'] && $meta_values['longitude'] && $meta_values['label'] ) {
			$meta_values['is_populated'] = true;
		}

		return $meta_values;
	}

	/**
	 * This function wraps get_post_meta() to enable us to keep the "geo_" prefix isolated to a single
	 * location in the code and to assist in mocking during testing.
	 *
	 * @param integer $post_id Post ID.
	 * @param string  $meta_field_name The meta field to retrieve.
	 *
	 * @return mixed
	 */
	public function get_meta_value( $post_id, $meta_field_name ) {
		if ( ! $post_id ) {
			return null;
		}

		return get_post_meta( $post_id, 'geo_' . $meta_field_name, true );
	}

	/**
	 * Check to see if the current filter is the get_the_excerpt filter.
	 *
	 * Just checking current_filter() here is not adequate because current_filter() only looks
	 * at the last element in the $wp_current_filter array.  In the context of rendering an
	 * excerpt, however, both get_the_excerpt and the_content are present in that array.
	 *
	 * @return bool
	 */
	public function is_currently_excerpt_filter() {
		if ( ! isset( $GLOBALS['wp_current_filter'] ) ) {
			return false;
		}

		$current_filters = (array) $GLOBALS['wp_current_filter'];

		return in_array( 'get_the_excerpt', $current_filters, true );
	}
}

Jetpack_Geo_Location::init();
