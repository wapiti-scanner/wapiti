<?php

namespace WPForms\Emails\Templates;

use WPForms\Emails\Styler;
use WPForms\Helpers\Templates;

/**
 * Base email template class.
 *
 * @since 1.5.4
 */
class General {

	/**
	 * Template slug.
	 *
	 * @since 1.5.4
	 *
	 * @var string
	 */
	const TEMPLATE_SLUG = 'general';

	/**
	 * Email message.
	 *
	 * @since 1.5.4
	 *
	 * @var string
	 */
	protected $message;

	/**
	 * Content is plain text type.
	 *
	 * @since 1.5.4
	 *
	 * @var bool
	 */
	protected $plain_text;

	/**
	 * Dynamic {{tags}}.
	 *
	 * @since 1.5.4
	 *
	 * @var array
	 */
	protected $tags;

	/**
	 * Header/footer/body arguments.
	 *
	 * @since 1.5.4
	 *
	 * @var array
	 */
	protected $args;

	/**
	 * Final email content.
	 *
	 * @since 1.5.4
	 *
	 * @var string
	 */
	protected $content;

	/**
	 * Constructor.
	 *
	 * @since 1.5.4
	 *
	 * @param string $message Email message.
	 */
	public function __construct( $message = '' ) {

		$this->set_message( $message );

		$this->plain_text = 'default' !== \wpforms_setting( 'email-template', 'default' );

		$this->set_initial_args();
	}

	/**
	 * Set initial arguments to use in a template.
	 *
	 * @since 1.5.4
	 */
	public function set_initial_args() {

		$header_args = [
			'title' => \esc_html__( 'WPForms', 'wpforms-lite' ),
		];

		if ( ! $this->plain_text ) {
			$header_args['header_image'] = $this->get_header_image();
		}

		$args = [
			'header' => $header_args,
			'body'   => [ 'message' => $this->get_message() ],
			'footer' => [],
			'style'  => [],
		];

		$args = \apply_filters( 'wpforms_emails_templates_general_set_initial_args', $args, $this );

		$this->set_args( $args );
	}

	/**
	 * Get the template slug.
	 *
	 * @since 1.5.4
	 *
	 * @return string
	 */
	public function get_slug() {

		return static::TEMPLATE_SLUG;
	}

	/**
	 * Get the template parent slug.
	 *
	 * @since 1.5.4
	 *
	 * @return string
	 */
	public function get_parent_slug() {

		return self::TEMPLATE_SLUG;
	}

	/**
	 * Get the message.
	 *
	 * @since 1.5.4
	 *
	 * @return string
	 */
	public function get_message() {

		return \apply_filters( 'wpforms_emails_templates_general_get_message', $this->message, $this );
	}

	/**
	 * Get the dynamic tags.
	 *
	 * @since 1.5.4
	 *
	 * @return array
	 */
	public function get_tags() {

		return \apply_filters( 'wpforms_emails_templates_general_get_tags', $this->tags, $this );
	}

	/**
	 * Get header/footer/body arguments
	 *
	 * @since 1.5.4
	 *
	 * @param string $type Header/footer/body.
	 *
	 * @return array
	 */
	public function get_args( $type ) {

		if ( ! empty( $type ) ) {
			return isset( $this->args[ $type ] ) ? apply_filters( 'wpforms_emails_templates_general_get_args_' . $type, $this->args[ $type ], $this ) : [];
		}

		return apply_filters( 'wpforms_emails_templates_general_get_args', $this->args, $this );
	}

	/**
	 * Set email message.
	 *
	 * @since 1.5.4
	 *
	 * @param string $message Email message.
	 *
	 * @return General
	 */
	public function set_message( $message ) {

		$message = \apply_filters( 'wpforms_emails_templates_general_set_message', $message, $this );

		if ( ! \is_string( $message ) ) {
			return $this;
		}

		$this->message = $message;

		return $this;
	}

	/**
	 * Set the dynamic tags.
	 *
	 * @since 1.5.4
	 *
	 * @param array $tags Tags to set.
	 *
	 * @return General
	 */
	public function set_tags( $tags ) {

		$tags = \apply_filters( 'wpforms_emails_templates_general_set_tags', $tags, $this );

		if ( ! \is_array( $tags ) ) {
			return $this;
		}

		$this->tags = $tags;

		return $this;
	}

	/**
	 * Set header/footer/body/style arguments to use in a template.
	 *
	 * @since 1.5.4
	 *
	 * @param array $args  Arguments to set.
	 * @param bool  $merge Merge the arguments with existing once or replace.
	 *
	 * @return General
	 */
	public function set_args( $args, $merge = true ) {

		$args = \apply_filters( 'wpforms_emails_templates_general_set_args', $args, $this );

		if ( empty( $args ) || ! \is_array( $args ) ) {
			return $this;
		}

		foreach ( $args as $type => $value ) {

			if ( ! \is_array( $value ) ) {
				continue;
			}

			if ( ! isset( $this->args[ $type ] ) || ! \is_array( $this->args[ $type ] ) ) {
				$this->args[ $type ] = [];
			}

			$this->args[ $type ] = $merge ? \array_merge( $this->args[ $type ], $value ) : $value;
		}

		return $this;
	}

	/**
	 * Process and replace any dynamic tags.
	 *
	 * @since 1.5.4
	 *
	 * @param string $content Content to make replacements in.
	 *
	 * @return string
	 */
	public function process_tags( $content ) {

		$tags = $this->get_tags();

		if ( empty( $tags ) ) {
			return $content;
		}

		foreach ( $tags as $tag => $value ) {
			$content = \str_replace( $tag, $value, $content );
		}

		return $content;
	}

	/**
	 * Conditionally modify email template name.
	 *
	 * @since 1.5.4
	 *
	 * @param string $name Base template name.
	 *
	 * @return string
	 */
	protected function get_full_template_name( $name ) {

		$name = \sanitize_file_name( $name );

		if ( $this->plain_text ) {
			$name .= '-plain';
		}

		$template = 'emails/' . $this->get_slug() . '-' . $name;

		if ( ! Templates::locate( $template . '.php' ) ) {
			$template = 'emails/' . $this->get_parent_slug() . '-' . $name;
		}

		return \apply_filters( 'wpforms_emails_templates_general_get_full_template_name', $template, $this );
	}

	/**
	 * Get header image URL from settings.
	 *
	 * @since 1.5.4
	 *
	 * @return array
	 */
	protected function get_header_image() {

		/**
		 * Additional 'width' key with an integer value can be added to $img array to control image's width in pixels.
		 * This setting helps to scale an image in some versions of MS Outlook and old email clients.
		 * Percentage 'width' values have no effect in MS Outlook and will be sanitized as integer by an email template..
		 *
		 * Example:
		 *
		 * $img = [
		 *     'url'   => \wpforms_setting( 'email-header-image' ),
		 *     'width' => 150,
		 * ];
		 *
		 *
		 * To set percentage values for the modern email clients, use $this->set_args() method:
		 *
		 * $this->set_args(
		 *     [
		 *         'style' => [
		 *             'header_image_max_width' => '45%',
		 *         ],
		 *    ]
		 *);
		 *
		 * Both pixel and percentage approaches work well with 'wpforms_emails_templates_general_get_header_image' filter or this class extension.
		 */
		$img = [
			'url' => \wpforms_setting( 'email-header-image' ),
		];

		return \apply_filters( 'wpforms_emails_templates_general_get_header_image', $img, $this );
	}

	/**
	 * Get content part HTML.
	 *
	 * @since 1.5.4
	 *
	 * @param string $name Name of the content part.
	 *
	 * @return string
	 */
	protected function get_content_part( $name ) {

		if ( ! \is_string( $name ) ) {
			return '';
		}

		$html = Templates::get_html(
			$this->get_full_template_name( $name ),
			$this->get_args( $name ),
			true
		);

		return \apply_filters( 'wpforms_emails_templates_general_get_content_part', $html, $name, $this );
	}

	/**
	 * Assemble all content parts in an array.
	 *
	 * @since 1.5.4
	 *
	 * @return array
	 */
	protected function get_content_parts() {

		$parts = [
			'header' => $this->get_content_part( 'header' ),
			'body'   => $this->get_content_part( 'body' ),
			'footer' => $this->get_content_part( 'footer' ),
		];

		return \apply_filters( 'wpforms_emails_templates_general_get_content_parts', $parts, $this );
	}

	/**
	 * Apply inline styling and save email content.
	 *
	 * @since 1.5.4
	 *
	 * @param string $content Content with no styling applied.
	 */
	protected function save_styled( $content ) {

		if ( empty( $content ) ) {
			$this->content = '';
			return;
		}

		if ( $this->plain_text ) {
			$this->content = \wp_strip_all_tags( $content );
			return;
		}

		$style_templates = [
			'style'   => $this->get_full_template_name( 'style' ),
			'queries' => $this->get_full_template_name( 'queries' ),
		];

		$styler = new Styler( $content, $style_templates, $this->get_args( 'style' ) );

		$this->content = \apply_filters( 'wpforms_emails_templates_general_save_styled_content', $styler->get(), $this );
	}

	/**
	 * Build an email including styling.
	 *
	 * @since 1.5.4
	 *
	 * @param bool $force Rebuild the content if it was already built and saved.
	 */
	protected function build( $force = false ) {

		if ( $this->content && ! $force ) {
			return;
		}

		$content = \implode( $this->get_content_parts() );

		if ( empty( $content ) ) {
			return;
		}

		$content = $this->process_tags( $content );

		if ( ! $this->plain_text ) {
			$content = \make_clickable( $content );
		}

		$content = \apply_filters( 'wpforms_emails_templates_general_build_content', $content, $this );

		$this->save_styled( $content );
	}

	/**
	 * Return final email.
	 *
	 * @since 1.5.4
	 *
	 * @param bool $force Rebuild the content if it was already built and saved.
	 *
	 * @return string
	 */
	public function get( $force = false ) {

		$this->build( $force );

		return $this->content;
	}
}
