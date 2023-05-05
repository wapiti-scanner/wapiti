<?php

namespace WPForms\Emails;

use TijsVerkoyen\CssToInlineStyles\CssToInlineStyles;
use WPForms\Helpers\Templates;

/**
 * Styler class inline style email templates.
 *
 * @since 1.5.4
 */
class Styler {

	/**
	 * Email message with no styles.
	 *
	 * @since 1.5.4
	 *
	 * @var string
	 */
	protected $email;

	/**
	 * Email style templates names.
	 *
	 * @since 1.5.4
	 *
	 * @var array
	 */
	protected $style_templates;

	/**
	 * Email style overrides.
	 *
	 * @since 1.5.4
	 *
	 * @var array
	 */
	protected $style_overrides;

	/**
	 * Email message with inline styles.
	 *
	 * @since 1.5.4
	 *
	 * @var string
	 */
	protected $styled_email;

	/**
	 * Constructor.
	 *
	 * @since 1.5.4
	 *
	 * @param string $email           Email with no styles.
	 * @param array  $style_templates Email style templates.
	 * @param array  $style_overrides Email style overrides.
	 */
	public function __construct( $email, $style_templates, $style_overrides ) {

		$this->email = $email;

		$this->style_templates = is_array( $style_templates ) ? $style_templates : [];
		$this->style_overrides = is_array( $style_overrides ) ? $style_overrides : [];
	}

	/**
	 * Template style overrides.
	 *
	 * @since 1.5.4
	 *
	 * @return array
	 */
	protected function get_style_overrides() {

		$defaults = [
			'email_background_color' => \wpforms_setting( 'email-background-color', '#e9eaec' ),
		];

		$overrides = \wp_parse_args( $this->style_overrides, $defaults );

		return \apply_filters( 'wpforms_emails_mailer_get_style_overrides', $overrides, $this );
	}

	/**
	 * Locate template name matching styles.
	 *
	 * @since 1.5.4
	 *
	 * @param string $name Template file name part.
	 *
	 * @return string
	 */
	protected function get_styles( $name = 'style' ) {

		if ( ! \array_key_exists( $name, $this->style_templates ) ) {
			return '';
		}

		return Templates::get_html(
			$this->style_templates[ $name ],
			$this->get_style_overrides(),
			true
		);
	}

	/**
	 * Final processing of the template markup.
	 *
	 * @since 1.5.4
	 */
	public function process_markup() {

		$this->styled_email = ( new CssToInlineStyles() )->convert( $this->email, $this->get_styles() );

		$queries = '<style type="text/css">' . $this->get_styles( 'queries' ) . "</style>\n</head>";

		// Inject media queries, CssToInlineStyles strips them.
		$this->styled_email = \str_replace( '</head>', $queries, $this->styled_email );
	}

	/**
	 * Get an email with inline styles.
	 *
	 * @since 1.5.4
	 *
	 * @return string
	 */
	public function get() {

		if ( empty( $this->styled_email ) ) {
			$this->process_markup();
		}

		return $this->styled_email;
	}
}
