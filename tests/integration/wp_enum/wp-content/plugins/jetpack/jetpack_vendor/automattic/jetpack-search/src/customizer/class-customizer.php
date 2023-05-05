<?php
/**
 * Jetpack Search Customizer Integration
 *
 * @package    @automattic/jetpack-search
 */

namespace Automattic\Jetpack\Search;

use Automattic\Jetpack\Assets;
use WP_Customize_Color_Control;

/**
 * Class to customize search on the site.
 */
class Customizer {

	/**
	 * Class initialization.
	 */
	public function __construct() {
		add_action( 'customize_register', array( $this, 'customize_register' ) );
		add_action( 'customize_controls_enqueue_scripts', array( $this, 'customize_controls_enqueue_scripts' ) );
		$this->plan = new Plan();
	}

	/**
	 * Initialize Customizer controls.
	 *
	 * @param WP_Customize_Manager $wp_customize Customizer instance.
	 */
	public function customize_register( $wp_customize ) {
		$section_id     = 'jetpack_search';
		$setting_prefix = Options::OPTION_PREFIX;

		$wp_customize->add_section(
			$section_id,
			array(
				'title'      => esc_html__( 'Jetpack Search', 'jetpack-search-pkg' ),
				'capability' => 'edit_theme_options',
				'priority'   => 200,
			)
		);

		$id = $setting_prefix . 'color_theme';
		$wp_customize->add_setting(
			$id,
			array(
				'default'   => 'light',
				'transport' => 'postMessage',
				'type'      => 'option',
			)
		);
		$wp_customize->add_control(
			$id,
			array(
				'label'       => __( 'Theme', 'jetpack-search-pkg' ),
				'description' => __( 'Select a theme for your search overlay.', 'jetpack-search-pkg' ),
				'section'     => $section_id,
				'type'        => 'radio',
				'choices'     => array(
					'light' => __( 'Light', 'jetpack-search-pkg' ),
					'dark'  => __( 'Dark', 'jetpack-search-pkg' ),
				),
			)
		);

		$id = $setting_prefix . 'result_format';
		$wp_customize->add_setting(
			$id,
			array(
				'default'   => 'minimal',
				'transport' => 'postMessage',
				'type'      => 'option',
			)
		);
		$wp_customize->add_control(
			$id,
			array(
				'label'       => __( 'Result Format', 'jetpack-search-pkg' ),
				'description' => __( 'Choose how the search results look.', 'jetpack-search-pkg' ),
				'section'     => $section_id,
				'type'        => 'select',
				'choices'     => array(
					'minimal'  => __( 'Minimal', 'jetpack-search-pkg' ),
					'expanded' => __( 'Expanded (shows images)', 'jetpack-search-pkg' ),
					'product'  => __( 'Product (for WooCommerce stores)', 'jetpack-search-pkg' ),
				),
			)
		);

		$id = $setting_prefix . 'default_sort';
		$wp_customize->add_setting(
			$id,
			array(
				'default' => 'relevance',
				'type'    => 'option',
			)
		);
		$wp_customize->add_control(
			$id,
			array(
				'choices'     => array(
					'relevance' => __( 'Relevance (recommended)', 'jetpack-search-pkg' ),
					'newest'    => __( 'Newest first', 'jetpack-search-pkg' ),
					'oldest'    => __( 'Oldest first', 'jetpack-search-pkg' ),
				),
				'description' => __( 'Pick the initial sort for your search results.', 'jetpack-search-pkg' ),
				'label'       => __( 'Default Sort', 'jetpack-search-pkg' ),
				'section'     => $section_id,
				'type'        => 'select',
			)
		);

		$id = $setting_prefix . 'overlay_trigger';
		$wp_customize->add_setting(
			$id,
			array(
				'default'   => Options::DEFAULT_OVERLAY_TRIGGER,
				'transport' => 'postMessage',
				'type'      => 'option',
			)
		);
		$wp_customize->add_control(
			$id,
			array(
				'label'       => __( 'Search Input Overlay Trigger', 'jetpack-search-pkg' ),
				'description' => __( 'Select when your overlay should appear.', 'jetpack-search-pkg' ),
				'section'     => $section_id,
				'type'        => 'select',
				'choices'     => array(
					Options::OVERLAY_TRIGGER_SUBMIT    => __( 'Open when user submits the form (recommended)', 'jetpack-search-pkg' ),
					Options::OVERLAY_TRIGGER_IMMEDIATE => __( 'Open when user starts typing', 'jetpack-search-pkg' ),
				),
			)
		);

		$id = $setting_prefix . 'excluded_post_types';
		$wp_customize->add_setting(
			$id,
			array(
				'default' => '',
				'type'    => 'option',
			)
		);
		$wp_customize->add_control(
			new Excluded_Post_Types_Control(
				$wp_customize,
				$id,
				array(
					'description' => __( 'Choose post types to exclude from search results. You must leave at least one post type unchecked.', 'jetpack-search-pkg' ),
					'label'       => __( 'Excluded Post Types', 'jetpack-search-pkg' ),
					'section'     => $section_id,
				)
			)
		);

		$id = $setting_prefix . 'highlight_color';
		$wp_customize->add_setting(
			$id,
			array(
				'default'   => '#FFC',
				'transport' => 'postMessage',
				'type'      => 'option',
			)
		);
		$wp_customize->add_control(
			new WP_Customize_Color_Control(
				$wp_customize,
				$id,
				array(
					'label'       => __( 'Highlight Search Terms', 'jetpack-search-pkg' ),
					'description' => __( 'Choose a color to highlight matching search terms.', 'jetpack-search-pkg' ),
					'section'     => $section_id,
				)
			)
		);

		$id = $setting_prefix . 'additional_settings_placeholder';
		$wp_customize->add_setting(
			$id,
			array( 'type' => 'option' )
		);
		$wp_customize->add_control(
			new Label_Control(
				$wp_customize,
				$id,
				array(
					'label'   => __( 'Additional Jetpack Search Settings', 'jetpack-search-pkg' ),
					'section' => $section_id,
				)
			)
		);

		$id = $setting_prefix . 'enable_sort';
		$wp_customize->add_setting(
			$id,
			array(
				'default'              => '1',
				'sanitize_callback'    => array( 'Automattic\Jetpack\Search\Helper', 'sanitize_checkbox_value' ),
				'sanitize_js_callback' => array( 'Automattic\Jetpack\Search\Helper', 'sanitize_checkbox_value_for_js' ),
				'transport'            => 'postMessage',
				'type'                 => 'option',
			)
		);
		$wp_customize->add_control(
			$id,
			array(
				'label'   => __( 'Show sort selector', 'jetpack-search-pkg' ),
				'section' => $section_id,
				'type'    => 'checkbox',
			)
		);

		$id = $setting_prefix . 'inf_scroll';
		$wp_customize->add_setting(
			$id,
			array(
				'default'              => '1',
				'sanitize_callback'    => array( 'Automattic\Jetpack\Search\Helper', 'sanitize_checkbox_value' ),
				'sanitize_js_callback' => array( 'Automattic\Jetpack\Search\Helper', 'sanitize_checkbox_value_for_js' ),
				'transport'            => 'postMessage',
				'type'                 => 'option',
			)
		);
		$wp_customize->add_control(
			$id,
			array(
				'type'    => 'checkbox',
				'section' => $section_id,
				'label'   => __( 'Enable infinite scrolling', 'jetpack-search-pkg' ),
			)
		);

		$id = $setting_prefix . 'show_post_date';
		$wp_customize->add_setting(
			$id,
			array(
				'default'              => '1',
				'sanitize_callback'    => array( 'Automattic\Jetpack\Search\Helper', 'sanitize_checkbox_value' ),
				'sanitize_js_callback' => array( 'Automattic\Jetpack\Search\Helper', 'sanitize_checkbox_value_for_js' ),
				'transport'            => 'postMessage',
				'type'                 => 'option',
			)
		);
		$wp_customize->add_control(
			$id,
			array(
				'type'    => 'checkbox',
				'section' => $section_id,
				'label'   => __( 'Show post date', 'jetpack-search-pkg' ),
			)
		);

		$id = $setting_prefix . 'show_powered_by';
		$wp_customize->add_setting(
			$id,
			array(
				'default'              => '1',
				'sanitize_callback'    => array( 'Automattic\Jetpack\Search\Helper', 'sanitize_checkbox_value' ),
				'sanitize_js_callback' => array( 'Automattic\Jetpack\Search\Helper', 'sanitize_checkbox_value_for_js' ),
				'transport'            => 'postMessage',
				'type'                 => 'option',
			)
		);

		if ( ! $this->plan->is_free_plan() ) {
			$wp_customize->add_control(
				$id,
				array(
					'type'    => 'checkbox',
					'section' => $section_id,
					'label'   => __( 'Display "Powered by Jetpack"', 'jetpack-search-pkg' ),
				)
			);
		}
	}

	/**
	 * Enqueue assets for Customizer controls.
	 */
	public function customize_controls_enqueue_scripts() {
		Assets::register_script(
			'jetpack-instant-search-customizer',
			'customize-controls/customize-controls.js',
			__FILE__,
			array(
				'css_path'     => 'customize-controls/customize-controls.css',
				'dependencies' => array( 'customize-controls' ),
				'in_footer'    => true,
				'textdomain'   => 'jetpack-search-pkg',
			)
		);
		Assets::enqueue_script( 'jetpack-instant-search-customizer' );
	}
}
