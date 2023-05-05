<?php
/**
 * CSS_Customizer_Nudge file.
 * CSS Nudge implementation for Atomic and WPCOM.
 *
 * @package Jetpack
 */

namespace Automattic\Jetpack\Dashboard_Customizations;

/**
 * Class WPCOM_CSS_Customizer
 *
 * @package Automattic\Jetpack\Dashboard_Customizations
 */
class CSS_Customizer_Nudge {
	/**
	 * Call to Action URL.
	 *
	 * @var string
	 */
	private $cta_url;

	/**
	 * The nudge message.
	 *
	 * @var string
	 */
	private $nudge_copy;

	/**
	 * The name of the control in Customizer.
	 *
	 * @var string
	 */
	private $control_name;

	/**
	 * CSS_Customizer_Nudge constructor.
	 *
	 * @param string $cta_url      The URL to the plans.
	 * @param string $nudge_copy   The nudge text.
	 * @param string $control_name The slug prefix of the nudge.
	 */
	public function __construct( $cta_url, $nudge_copy, $control_name = 'custom_css' ) {
		$this->cta_url      = $cta_url;
		$this->nudge_copy   = $nudge_copy;
		$this->control_name = $control_name;
	}

	/**
	 * Register the assets required for the CSS nudge page from the Customizer.
	 */
	public function customize_controls_enqueue_scripts_nudge() {
		\wp_enqueue_script(
			'additional-css-js',
			plugins_url( 'js/additional-css.js', __FILE__ ),
			array(),
			JETPACK__VERSION,
			true
		);
		\wp_enqueue_style(
			'additional-css',
			plugins_url( 'css/additional-css.css', __FILE__ ),
			array(),
			JETPACK__VERSION
		);
	}

	/**
	 * Register the CSS nudge in the Customizer.
	 *
	 * @param \WP_Customize_Manager $wp_customize The customize manager.
	 */
	public function customize_register_nudge( \WP_Customize_Manager $wp_customize ) {
		// Show a nudge in place of the normal CSS section.
		\add_action( 'customize_controls_enqueue_scripts', array( $this, 'customize_controls_enqueue_scripts_nudge' ) );

		$wp_customize->add_setting(
			$this->control_name . '[dummy_setting]',
			array(
				'type'      => $this->control_name . '_dummy_setting',
				'default'   => '',
				'transport' => 'refresh',
			)
		);

		$wp_customize->add_section( $this->create_css_nudge_section( $wp_customize ) );

		$wp_customize->add_control( $this->create_css_nudge_control( $wp_customize ) );
	}

	/**
	 * Create a nudge control object.
	 *
	 * @param \WP_Customize_Manager $wp_customize The Core Customize Manager.
	 *
	 * @return CSS_Nudge_Customize_Control
	 */
	public function create_css_nudge_control( \WP_Customize_Manager $wp_customize ) {
		return new CSS_Nudge_Customize_Control(
			$wp_customize,
			$this->control_name . '_control',
			array(
				'cta_url'    => $this->cta_url,
				'nudge_copy' => $this->nudge_copy,
				'label'      => __( 'Custom CSS', 'jetpack' ),
				'section'    => $this->control_name,
				'settings'   => $this->control_name . '[dummy_setting]',
			)
		);
	}

	/**
	 * Create the nudge section.
	 *
	 * @param \WP_Customize_Manager $wp_customize The core Customize Manager.
	 *
	 * @return \WP_Customize_Section
	 */
	public function create_css_nudge_section( \WP_Customize_Manager $wp_customize ) {
		return new \WP_Customize_Section(
			$wp_customize,
			$this->control_name,
			array(
				'title'    => __( 'Additional CSS', 'jetpack' ),
				'priority' => 200,
			)
		);
	}
}
