<?php
/**
 * Adding extra functions for the gallery.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Assets;

/**
 * Renders extra controls in the Gallery Settings section of the new media UI.
 */
class Jetpack_Gallery_Settings {
	/**
	 * The constructor.
	 */
	public function __construct() {
		add_action( 'admin_init', array( $this, 'admin_init' ) );
	}

	/**
	 * Initialize the admin resources.
	 */
	public function admin_init() {
		/**
		 * Filter the available gallery types.
		 *
		 * @module shortcodes, tiled-gallery
		 *
		 * @since 2.5.1
		 *
		 * @param array $value Array of the default thumbnail grid gallery type. Default array contains one key, ‘default’.
		 */
		$this->gallery_types = apply_filters( 'jetpack_gallery_types', array( 'default' => __( 'Thumbnail Grid', 'jetpack' ) ) );

		// Enqueue the media UI only if needed.
		if ( count( $this->gallery_types ) > 1 ) {
			add_action( 'wp_enqueue_media', array( $this, 'wp_enqueue_media' ) );
			add_action( 'print_media_templates', array( $this, 'print_media_templates' ) );
		}
		// Add Slideshow and Galleries functionality to core's media gallery widget.
		add_filter( 'widget_media_gallery_instance_schema', array( $this, 'core_media_widget_compat' ) );
	}

	/**
	 * Updates the schema of the core gallery widget so we can save the
	 * fields that we add to Gallery Widgets, like `type` and `conditions`
	 *
	 * @param array $schema The current schema for the core gallery widget.
	 * @return array  the updated schema
	 */
	public function core_media_widget_compat( $schema ) {
		$schema['type'] = array(
			'type'        => 'string',
			'enum'        => array_keys( $this->gallery_types ),
			'description' => __( 'Type of gallery.', 'jetpack' ),
			'default'     => 'default',
		);
		return $schema;
	}

	/**
	 * Registers/enqueues the gallery settings admin js.
	 */
	public function wp_enqueue_media() {
		if ( ! wp_script_is( 'jetpack-gallery-settings', 'registered' ) ) {
			/**
			 * This only happens if we're not in Jetpack, but on WPCOM instead.
			 * This is the correct path for WPCOM.
			 */
			wp_register_script(
				'jetpack-gallery-settings',
				Assets::get_file_url_for_environment( '_inc/build/gallery-settings.min.js', '_inc/gallery-settings.js' ),
				array( 'jquery', 'media-views' ),
				'20121225',
				false
			);
		}

		wp_enqueue_script( 'jetpack-gallery-settings' );
	}

	/**
	 * Outputs a view template which can be used with wp.media.template
	 */
	public function print_media_templates() {
		/**
		 * Filter the default gallery type.
		 *
		 * @module tiled-gallery
		 *
		 * @since 2.5.1
		 *
		 * @param string $value A string of the gallery type. Default is ‘default’.
		 */
		$default_gallery_type = apply_filters( 'jetpack_default_gallery_type', 'default' );

		?>
		<script type="text/html" id="tmpl-jetpack-gallery-settings">
			<label class="setting">
				<span><?php esc_html_e( 'Type', 'jetpack' ); ?></span>
				<select class="type" name="type" data-setting="type">
					<?php foreach ( $this->gallery_types as $value => $caption ) : ?>
						<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $value, $default_gallery_type ); ?>><?php echo esc_html( $caption ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
		</script>
		<?php
	}
}
new Jetpack_Gallery_Settings();
