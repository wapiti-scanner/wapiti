<?php

namespace WPForms\Forms;

use WPForms\Helpers\PluginSilentUpgrader;
use WPForms_Builder;
use WPForms_Install_Skin;

/**
 * Icon Choices functionality.
 *
 * @since 1.7.9
 */
class IconChoices {

	/**
	 * Remote URL to download the icon library from.
	 *
	 * @since 1.7.9
	 *
	 * @var string
	 */
	const FONT_AWESOME_URL = 'https://wpforms.com/wp-content/icon-choices.zip';

	/**
	 * Font Awesome version.
	 *
	 * @since 1.7.9
	 *
	 * @var string
	 */
	const FONT_AWESOME_VERSION = '6.2.1';

	/**
	 * Default icon.
	 *
	 * @since 1.7.9
	 *
	 * @var string
	 */
	const DEFAULT_ICON = 'face-smile';

	/**
	 * Default icon style.
	 *
	 * @since 1.7.9
	 *
	 * @var string
	 */
	const DEFAULT_ICON_STYLE = 'regular';

	/**
	 * Default accent color.
	 *
	 * @since 1.7.9
	 *
	 * @var string
	 */
	const DEFAULT_COLOR = [
		'classic' => '#0399ed',
		'modern'  => '#066aab',
	];

	/**
	 * How many icons to display initially and paginate in the Icon Picker.
	 *
	 * @since 1.7.9
	 *
	 * @var int
	 */
	const DEFAULT_ICONS_PER_PAGE = 50;

	/**
	 * Absolute path to the cache directory.
	 *
	 * @since 1.7.9
	 *
	 * @var string
	 */
	private $cache_base_path;

	/**
	 * Cache directory URL.
	 *
	 * @since 1.7.9
	 *
	 * @var string
	 */
	private $cache_base_url;

	/**
	 * Absolute path to the icons data file.
	 *
	 * @since 1.7.9
	 *
	 * @var string
	 */
	private $icons_data_file;

	/**
	 * Whether icon library is already installed.
	 *
	 * @since 1.7.9
	 *
	 * @var bool
	 */
	private $is_installed;

	/**
	 * Default list of icon sizes.
	 *
	 * @since 1.7.9
	 *
	 * @var array
	 */
	private $default_icon_sizes;

	/**
	 * Initialize class.
	 *
	 * @since 1.7.9
	 */
	public function init() {

		$upload_dir = wpforms_upload_dir();

		$this->cache_base_url  = $upload_dir['url'] . '/icon-choices';
		$this->cache_base_path = $upload_dir['path'] . '/icon-choices';
		$this->icons_data_file = $this->cache_base_path . '/icons.json';

		$this->default_icon_sizes = [
			'large'  => [
				'label' => __( 'Large', 'wpforms-lite' ),
				'size'  => 64,
			],
			'medium' => [
				'label' => __( 'Medium', 'wpforms-lite' ),
				'size'  => 48,
			],
			'small'  => [
				'label' => __( 'Small', 'wpforms-lite' ),
				'size'  => 32,
			],
		];

		$this->hooks();
	}

	/**
	 * Hook into WordPress lifecycle.
	 *
	 * @since 1.7.9
	 */
	private function hooks() {

		// Add inline CSS with custom properties on the frontend.
		add_action( 'wpforms_frontend_css', [ $this, 'css_custom_properties' ] );

		// Add inline CSS with custom properties in the form builder.
		if ( wpforms_is_admin_page( 'builder' ) ) {
			add_action( 'admin_head', [ $this, 'css_custom_properties' ] );
		}

		// Load Font Awesome assets.
		add_action( 'wpforms_builder_enqueues', [ $this, 'enqueues' ] );

		// Send data to the frontend.
		add_filter( 'wpforms_builder_strings', [ $this, 'get_strings' ], 10, 2 );

		// Download and extract Font Awesome package.
		add_action( 'wp_ajax_wpforms_icon_choices_install', [ $this, 'install' ] );
	}

	/**
	 * Whether Font Awesome library is already installed or not.
	 *
	 * @since 1.7.9
	 *
	 * @return bool
	 */
	private function is_installed() {

		if ( $this->is_installed !== null ) {
			return $this->is_installed;
		}

		$this->is_installed = file_exists( $this->icons_data_file );

		return $this->is_installed;
	}

	/**
	 * Whether Icon Choices mode is active on any of the fields in current form.
	 *
	 * @since 1.7.9
	 *
	 * @return bool
	 */
	private function is_active() {

		$form_data = WPForms_Builder::instance()->form_data;

		return wpforms_has_field_setting( 'choices_icons', $form_data, false );
	}

	/**
	 * Install Font Awesome library from our server.
	 *
	 * @since 1.7.9
	 */
	public function install() { // phpcs:ignore WPForms.PHP.HooksMethod.InvalidPlaceForAddingHooks

		check_ajax_referer( 'wpforms-builder', 'nonce' );

		// WordPress assumes it's a plugin/theme and tries to get translations. We don't need that, and it breaks JS output.
		remove_action( 'upgrader_process_complete', [ 'Language_Pack_Upgrader', 'async_upgrade' ], 20 );

		require_once WPFORMS_PLUGIN_DIR . 'includes/admin/class-install-skin.php';

		// Create the Upgrader with our custom skin that reports errors as WP JSON.
		$installer = new PluginSilentUpgrader( new WPForms_Install_Skin() );

		// The installer skin reports any errors via wp_send_json_error() with generic error messages.
		$installer->init();
		$installer->run(
			[
				'package'     => self::FONT_AWESOME_URL,
				'destination' => $this->cache_base_path,
			]
		);

		$this->is_installed = true;

		wp_send_json_success();
	}

	/**
	 * Load all necessary Font Awesome assets.
	 *
	 * @since 1.7.9
	 *
	 * @param string $view Current Form Builder view (panel).
	 */
	public function enqueues( $view ) {

		if ( ! $this->is_installed() ) {
			return;
		}

		wp_enqueue_style(
			'wpforms-icon-choices-font-awesome',
			$this->cache_base_url . '/css/fontawesome.min.css',
			[],
			self::FONT_AWESOME_VERSION
		);

		wp_enqueue_style(
			'wpforms-icon-choices-font-awesome-brands',
			$this->cache_base_url . '/css/brands.min.css',
			[],
			self::FONT_AWESOME_VERSION
		);

		wp_enqueue_style(
			'wpforms-icon-choices-font-awesome-regular',
			$this->cache_base_url . '/css/regular.min.css',
			[],
			self::FONT_AWESOME_VERSION
		);

		wp_enqueue_style(
			'wpforms-icon-choices-font-awesome-solid',
			$this->cache_base_url . '/css/solid.min.css',
			[],
			self::FONT_AWESOME_VERSION
		);
	}

	/**
	 * Define additional field properties specific to Icon Choices feature.
	 *
	 * @since 1.7.9
	 *
	 * @see WPForms_Field_Checkbox::field_properties()
	 * @see WPForms_Field_Radio::field_properties()
	 * @see WPForms_Field_Payment_Checkbox::field_properties()
	 * @see WPForms_Field_Payment_Multiple::field_properties()
	 *
	 * @param array $properties Field properties.
	 * @param array $field      Field settings.
	 *
	 * @return array
	 */
	public function field_properties( $properties, $field ) {

		$properties['input_container']['class'][] = 'wpforms-icon-choices';
		$properties['input_container']['class'][] = sanitize_html_class( 'wpforms-icon-choices-' . $field['choices_icons_style'] );
		$properties['input_container']['class'][] = sanitize_html_class( 'wpforms-icon-choices-' . $field['choices_icons_size'] );

		$icon_color = isset( $field['choices_icons_color'] ) ? wpforms_sanitize_hex_color( $field['choices_icons_color'] ) : '';
		$icon_color = empty( $icon_color ) ? self::get_default_color() : $icon_color;

		$properties['input_container']['attr']['style'] = "--wpforms-icon-choices-color: {$icon_color};";

		foreach ( $properties['inputs'] as $key => $inputs ) {
			$properties['inputs'][ $key ]['container']['class'][] = 'wpforms-icon-choices-item';

			if ( in_array( $field['choices_icons_style'], [ 'default', 'modern', 'classic' ], true ) ) {
				$properties['inputs'][ $key ]['class'][] = 'wpforms-screen-reader-element';
			}
		}

		return $properties;
	}

	/**
	 * Display a single choice on the form front-end.
	 *
	 * @since 1.7.9
	 *
	 * @see WPForms_Field_Checkbox::field_display()
	 * @see WPForms_Field_Radio::field_display()
	 * @see WPForms_Field_Payment_Checkbox::field_display()
	 * @see WPForms_Field_Payment_Multiple::field_display()
	 *
	 * @param array       $field  Field settings.
	 * @param array       $choice Single choice item settings.
	 * @param string      $type   Field input type.
	 * @param string|null $label  Custom label, used by Payment fields.
	 */
	public function field_display( $field, $choice, $type, $label = null ) {

		// Only Payment fields supply a custom label.
		if ( ! $label ) {
			$label = $choice['label']['text'];
		}

		printf(
			'<label %1$s>
				<span class="wpforms-icon-choices-icon">
					%2$s
					<span class="wpforms-icon-choices-icon-bg"></span>
				</span>
				<input type="%3$s" %4$s %5$s %6$s>
				<span class="wpforms-icon-choices-label">%7$s</span>
			</label>',
			wpforms_html_attributes( $choice['label']['id'], $choice['label']['class'], $choice['label']['data'], $choice['label']['attr'] ),
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			$this->get_icon( $choice['icon'], $choice['icon_style'], $field['choices_icons_size'] ),
			esc_attr( $type ),
			wpforms_html_attributes( $choice['id'], $choice['class'], $choice['data'], $choice['attr'] ),
			esc_attr( $choice['required'] ),
			checked( '1', $choice['default'], false ),
			wp_kses_post( $label )
		);
	}

	/**
	 * Output inline CSS custom properties (vars).
	 *
	 * @since 1.7.9
	 *
	 * @param null|array $forms Frontend forms, if available.
	 *
	 * @return void
	 */
	public function css_custom_properties( $forms = null ) {

		$hook = current_action();

		// On the frontend, we need these properties only if Icon Choices is in use.
		if ( $hook === 'wpforms_frontend_css' && ! wpforms_has_field_setting( 'choices_icons', $forms, true ) ) {
			return;
		}

		$selectors = [
			'wpforms_frontend_css' => '.wpforms-container',
			'admin_head'           => '#wpforms-builder, .wpforms-icon-picker-container',
		];

		/**
		 * Add CSS custom properties.
		 *
		 * @since 1.7.9
		 *
		 * @param array $properties CSS custom properties using CSS syntax.
		 */
		$custom_properties = (array) apply_filters( 'wpforms_forms_icon_choices_css_custom_properties', [] );

		$icon_sizes = $this->get_icon_sizes();

		foreach ( $icon_sizes as $slug => $data ) {
			$custom_properties[ "wpforms-icon-choices-size-{$slug}" ] = $data['size'] . 'px';
		}

		$custom_properties_css = '';

		foreach ( $custom_properties as $property => $value ) {
			$custom_properties_css .= "--{$property}: {$value};";
		}

		printf(
			'<style id="wpforms-icon-choices-custom-properties">%s { %s }</style>',
			esc_attr( $selectors[ $hook ] ),
			esc_html( $custom_properties_css )
		);
	}

	/**
	 * Get available icon sizes.
	 *
	 * @since 1.7.9
	 *
	 * @return array A list of all icon sizes.
	 */
	public function get_icon_sizes() {

		/**
		 * Allow modifying the icon sizes.
		 *
		 * @since 1.7.9
		 *
		 * @param array $icon_sizes         {
 		 *     Default icon sizes.
		 *
		 *     @type string $key The icon slug.
		 *     @type array $value {
		 *         Individual icon size data.
		 *
 		 *         @type string $label Translatable label.
		 *         @type int    $size  The size value.
		 *     }
		 * }
		 * @param array $default_icon_sizes Default icon sizes for reference.
		 */
		$sizes = (array) apply_filters( 'wpforms_forms_icon_choices_get_icon_sizes', [], $this->default_icon_sizes );

		return array_merge( $this->default_icon_sizes, $sizes );
	}

	/**
	 * Read icons metadata from disk.
	 *
	 * @since 1.7.9
	 *
	 * @param array $strings Strings and values sent to the frontend.
	 * @param array $form    Current form.
	 *
	 * @return array
	 */
	public function get_strings( $strings, $form ) {

		$strings['continue'] = esc_html__( 'Continue', 'wpforms-lite' );
		$strings['done']     = esc_html__( 'Done!', 'wpforms-lite' );
		$strings['uh_oh']    = esc_html__( 'Uh oh!', 'wpforms-lite' );

		$strings['icon_choices'] = [
			'is_installed'       => false,
			'is_active'          => $this->is_active(),
			'default_icon'       => self::DEFAULT_ICON,
			'default_icon_style' => self::DEFAULT_ICON_STYLE,
			'default_color'      => self::get_default_color(),
			'icons'              => [],
			'icons_per_page'     => self::DEFAULT_ICONS_PER_PAGE,
			'strings'            => [
				'install_prompt_content'         => esc_html__( 'In order to use the Icon Choices feature, an icon library must be downloaded and installed. It\'s quick and easy, and you\'ll only have to do this once.', 'wpforms-lite' ),
				'install_title'                  => esc_html__( 'Installing Icon Library', 'wpforms-lite' ),
				'install_content'                => esc_html__( 'This should only take a minute. Please don’t close or reload your browser window.', 'wpforms-lite' ),
				'install_success_content'        => esc_html__( 'The icon library has been installed successfully. We will now save your form and reload the form builder.', 'wpforms-lite' ),
				'install_error_content'          => wp_kses(
					sprintf( /* translators: %s - WPForms Support URL.  */
						__( 'There was an error installing the icon library. Please try again later or <a href="%s" target="_blank" rel="noreferrer noopener">contact support</a> if the issue persists.', 'wpforms-lite' ),
						esc_url(
							wpforms_utm_link(
								'https://wpforms.com/account/support/',
								'builder-modal',
								'Icon Library Install Failure'
							)
						)
					),
					[
						'a' => [
							'href'   => true,
							'target' => true,
							'rel'    => true,
						],
					]
				),
				'reinstall_prompt_content'       => esc_html__( 'The icon library appears to be missing or damaged. It will now be reinstalled.', 'wpforms-lite' ),
				'icon_picker_title'              => esc_html__( 'Icon Picker', 'wpforms-lite' ),
				'icon_picker_description'        => esc_html__( 'Browse or search for the perfect icon.', 'wpforms-lite' ),
				'icon_picker_search_placeholder' => esc_html__( 'Search 2000+ icons...', 'wpforms-lite' ),
				'icon_picker_not_found'          => esc_html__( 'Sorry, we didn\'t find any matching icons.', 'wpforms-lite' ),
			],
		];

		if ( ! $this->is_installed() ) {
			return $strings;
		}

		$strings['icon_choices']['is_installed'] = true;
		$strings['icon_choices']['icons']        = $this->get_icons();

		return $strings;
	}

	/**
	 * Get an SVG icon code from a file for inline output in HTML.
	 *
	 * Note: the output does not need escaping.
	 *
	 * @since 1.7.9
	 *
	 * @param string $icon  Font Awesome icon name.
	 * @param string $style Font Awesome style (solid, brands).
	 * @param int    $size  Icon display size.
	 *
	 * @return string
	 */
	private function get_icon( $icon, $style, $size ) {

		$icon_sizes = $this->get_icon_sizes();
		$filename   = realpath( "{$this->cache_base_path}/svgs/{$style}/{$icon}.svg" );

		if ( ! $filename || ! is_file( $filename ) || ! is_readable( $filename ) ) {
			return '';
		}

		$svg = file_get_contents( $filename );

		if ( ! $svg ) {
			return '';
		}

		$height = ! empty( $icon_sizes[ $size ]['size'] ) ? $icon_sizes[ $size ]['size'] : $icon_sizes['large']['size'];
		$width  = $height * 1.25; // Icon width is equal or 25% larger/smaller than height. We force the largest value for all icons.

		return str_replace( 'viewBox=', 'width="' . $width . '" height="' . $height . 'px" viewBox=', $svg );
	}

	/**
	 * Get all available icons from the metadata file.
	 *
	 * @since 1.7.9
	 *
	 * @return array
	 */
	private function get_icons() {

		if ( ! is_file( $this->icons_data_file ) || ! is_readable( $this->icons_data_file ) ) {
			return [];
		}

		$icons = file_get_contents( $this->icons_data_file );

		if ( ! $icons ) {
			return [];
		}

		return (array) json_decode( $icons, false );
	}

	/**
	 * Get default accent color.
	 *
	 * @since 1.8.1
	 *
	 * @return string
	 */
	public static function get_default_color() {

		$render_engine = wpforms_get_render_engine();

		return array_key_exists( $render_engine, self::DEFAULT_COLOR ) ? self::DEFAULT_COLOR[ $render_engine ] : self::DEFAULT_COLOR['modern'];
	}
}
