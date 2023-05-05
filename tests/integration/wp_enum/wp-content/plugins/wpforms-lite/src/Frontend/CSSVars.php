<?php

namespace WPForms\Frontend;

/**
 * CSS variables class.
 *
 * @since 1.8.1
 */
class CSSVars {

	/**
	 * Root vars and values.
	 *
	 * @since 1.8.1
	 *
	 * @var array
	 */
	const ROOT_VARS = [
		'field-border-radius'     => '3px',
		'field-background-color'  => '#ffffff',
		'field-border-color'      => 'rgba( 0, 0, 0, 0.25 )',
		'field-text-color'        => 'rgba( 0, 0, 0, 0.7 )',

		'label-color'             => 'rgba( 0, 0, 0, 0.85 )',
		'label-sublabel-color'    => 'rgba( 0, 0, 0, 0.55 )',
		'label-error-color'       => '#d63637',

		'button-border-radius'    => '3px',
		'button-background-color' => '#066aab',
		'button-text-color'       => '#ffffff',
	];

	/**
	 * Field Size vars and values.
	 *
	 * @since 1.8.1
	 *
	 * @var array
	 */
	const FIELD_SIZE = [
		'small'  => [
			'input-height'     => '31px',
			'input-spacing'    => '10px',
			'font-size'        => '14px',
			'line-height'      => '17px',
			'padding-h'        => '9px',
			'checkbox-size'    => '14px',
			'sublabel-spacing' => '5px',
			'icon-size'        => '0.75',
		],
		'medium' => [
			'input-height'     => '43px',
			'input-spacing'    => '15px',
			'font-size'        => '16px',
			'line-height'      => '19px',
			'padding-h'        => '14px',
			'checkbox-size'    => '16px',
			'sublabel-spacing' => '5px',
			'icon-size'        => '1',
		],
		'large'  => [
			'input-height'     => '50px',
			'input-spacing'    => '20px',
			'font-size'        => '18px',
			'line-height'      => '21px',
			'padding-h'        => '14px',
			'checkbox-size'    => '18px',
			'sublabel-spacing' => '10px',
			'icon-size'        => '1.25',
		],
	];

	/**
	 * Label Size vars and values.
	 *
	 * @since 1.8.1
	 *
	 * @var array
	 */
	const LABEL_SIZE = [
		'small'  => [
			'font-size'            => '14px',
			'line-height'          => '17px',
			'sublabel-font-size'   => '13px',
			'sublabel-line-height' => '16px',
		],
		'medium' => [
			'font-size'            => '16px',
			'line-height'          => '19px',
			'sublabel-font-size'   => '14px',
			'sublabel-line-height' => '17px',
		],
		'large'  => [
			'font-size'            => '18px',
			'line-height'          => '21px',
			'sublabel-font-size'   => '16px',
			'sublabel-line-height' => '19px',
		],
	];

	/**
	 * Button Size vars and values.
	 *
	 * @since 1.8.1
	 *
	 * @var array
	 */
	const BUTTON_SIZE = [
		'small'  => [
			'font-size'  => '14px',
			'height'     => '37px',
			'padding-h'  => '15px',
			'margin-top' => '5px',
		],
		'medium' => [
			'font-size'  => '17px',
			'height'     => '41px',
			'padding-h'  => '15px',
			'margin-top' => '10px',
		],
		'large'  => [
			'font-size'  => '20px',
			'height'     => '48px',
			'padding-h'  => '20px',
			'margin-top' => '15px',
		],
	];

	/**
	 * Render engine.
	 *
	 * @since 1.8.1
	 *
	 * @var string
	 */
	private $render_engine;

	/**
	 * CSS variables.
	 *
	 * @since 1.8.1
	 *
	 * @var array
	 */
	private $css_vars;

	/**
	 * Flag to check if root CSS vars were output.
	 *
	 * @since 1.8.1
	 *
	 * @var bool
	 */
	private $is_root_vars_displayed;

	/**
	 * Initialize class.
	 *
	 * @since 1.8.1
	 */
	public function init() {

		$this->init_vars();
		$this->hooks();
	}

	/**
	 * Register hooks.
	 *
	 * @since 1.8.1
	 */
	private function hooks() {

		add_action( 'wp_head', [ $this, 'output_root' ], PHP_INT_MAX );
	}

	/**
	 * CSS variables data.
	 *
	 * @since 1.8.1
	 */
	private function init_vars() {

		$vars = [];

		$vars[':root'] = array_merge(
			self::ROOT_VARS,
			$this->get_complex_vars( 'field-size', self::FIELD_SIZE['medium'] ),
			$this->get_complex_vars( 'label-size', self::LABEL_SIZE['medium'] ),
			$this->get_complex_vars( 'button-size', self::BUTTON_SIZE['medium'] )
		);

		/**
		 * Allows developers to modify default CSS variables which output on the frontend.
		 *
		 * @since 1.8.1
		 *
		 * @param array $vars CSS variables two-dimensional array.
		 *                    First level keys is the CSS selector.
		 *                    Second level keys is the variable name without the `--wpforms-` prefix.
		 */
		$this->css_vars = apply_filters( 'wpforms_frontend_css_vars_init_vars', $vars );
	}

	/**
	 * Get complex CSS variables data.
	 *
	 * @since 1.8.1
	 *
	 * @param string $prefix CSS variable prefix.
	 * @param array  $values Values.
	 */
	public function get_complex_vars( $prefix, $values ) {

		$vars = [];

		foreach ( $values as $key => $value ) {
			$vars[ "{$prefix}-{$key}" ] = $value;
		}

		return $vars;
	}

	/**
	 * Get CSS variables data by selector.
	 *
	 * @since 1.8.1
	 *
	 * @param string $selector Selector.
	 *
	 * @return array
	 */
	public function get_vars( $selector ) {

		if ( empty( $selector ) ) {
			$selector = ':root';
		}

		if ( empty( $this->css_vars[ $selector ] ) ) {
			return [];
		}

		return $this->css_vars[ $selector ];
	}

	/**
	 * Output root CSS variables.
	 *
	 * @since 1.8.1
	 * @since 1.8.1.2 Added $force argument.
	 *
	 * @param bool $force Force output root variables.
	 */
	public function output_root( $force = false ) {

		if ( ! empty( $this->is_root_vars_displayed ) && empty( $force ) ) {
			return;
		}

		$this->output_selector_vars( ':root', $this->css_vars[':root'] );

		$this->is_root_vars_displayed = true;
	}

	/**
	 * Output selector's CSS variables.
	 *
	 * @since 1.8.1
	 *
	 * @param string $selector Selector.
	 * @param array  $vars     Variables data.
	 * @param string $style_id Style tag Id attribute. Optional. Defaults to empty string.
	 */
	public function output_selector_vars( $selector, $vars, $style_id = '' ) {

		if ( empty( $this->render_engine ) ) {
			$this->render_engine = wpforms_get_render_engine();
		}

		if ( $this->render_engine === 'classic' ) {
			return;
		}

		$style_id = empty( $style_id ) ? 'wpforms-css-vars-' . $selector : $style_id;

		printf(
			'<style id="%1$s">
				%2$s {
					%3$s
				}
			</style>',
			sanitize_key( $style_id ),
			$selector, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
 			esc_html( $this->get_vars_css( $vars ) )
		);
	}

	/**
	 * Generate CSS code from given vars data.
	 *
	 * @since 1.8.1
	 *
	 * @param array $vars Variables data.
	 */
	private function get_vars_css( $vars ) {

		$result = '';

		foreach ( $vars as $name => $value ) {
			$result .= "--wpforms-{$name}: {$value};\n";
		}

		return $result;
	}
}
