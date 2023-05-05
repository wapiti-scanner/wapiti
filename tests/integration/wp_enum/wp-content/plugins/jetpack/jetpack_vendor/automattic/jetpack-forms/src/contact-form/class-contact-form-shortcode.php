<?php
/**
 * Contact_Form_Shortcode class.
 *
 * @package automattic/jetpack-forms
 */

namespace Automattic\Jetpack\Forms\ContactForm;

/**
 * Generic shortcode class.
 * Does nothing other than store structured data and output the shortcode as a string
 *
 * Not very general - specific to Grunion.
 *
 * // phpcs:disable Generic.Files.OneObjectStructurePerFile.MultipleFound
 */
class Contact_Form_Shortcode {
	/**
	 * The name of the shortcode: [$shortcode_name /].
	 *
	 * @var string
	 */
	public $shortcode_name;

	/**
	 * Key => value pairs for the shortcode's attributes: [$shortcode_name key="value" ... /]
	 *
	 * @var array
	 */
	public $attributes;

	/**
	 * Key => value pair for attribute defaults.
	 *
	 * @var array
	 */
	public $defaults = array();

	/**
	 * The inner content of otherwise: [$shortcode_name]$content[/$shortcode_name]. Null for selfclosing shortcodes.
	 *
	 * @var null|string
	 */
	public $content;

	/**
	 * Associative array of inner "child" shortcodes equivalent to the $content: [$shortcode_name][child 1/][child 2/][/$shortcode_name]
	 *
	 * @var array
	 */
	public $fields;

	/**
	 * The HTML of the parsed inner "child" shortcodes".  Null for selfclosing shortcodes.
	 *
	 * @var null|string
	 */
	public $body;

	/**
	 * Constructor function.
	 *
	 * @param array       $attributes An associative array of shortcode attributes.  @see shortcode_atts().
	 * @param null|string $content Null for selfclosing shortcodes.  The inner content otherwise.
	 */
	public function __construct( $attributes, $content = null ) {
		$this->attributes = $this->unesc_attr( $attributes );
		if ( is_array( $content ) ) {
			$string_content = '';
			foreach ( $content as $field ) {
				$string_content .= (string) $field;
			}

			$this->content = $string_content;
		} else {
			$this->content = $content;
		}

		$this->parse_content( $this->content );
	}

	/**
	 * Processes the shortcode's inner content for "child" shortcodes.
	 *
	 * @param string $content The shortcode's inner content: [shortcode]$content[/shortcode].
	 */
	public function parse_content( $content ) {
		if ( $content === null ) {
			$this->body = null;
		} else {
			$this->body = do_shortcode( $content );
		}
	}

	/**
	 * Returns the value of the requested attribute.
	 *
	 * @param string $key The attribute to retrieve.
	 *
	 * @return mixed
	 */
	public function get_attribute( $key ) {
		return isset( $this->attributes[ $key ] ) ? $this->attributes[ $key ] : null;
	}

	/**
	 * Escape attributes.
	 *
	 * @param array $value - the value we're escaping.
	 *
	 * @return array
	 */
	public function esc_attr( $value ) {
		if ( is_array( $value ) ) {
			return array_map( array( $this, 'esc_attr' ), $value );
		}

		$value = Contact_Form_Plugin::strip_tags( $value );
		$value = _wp_specialchars( $value, ENT_QUOTES, false, true );

		// Shortcode attributes can't contain "]"
		$value = str_replace( ']', '', $value );
		$value = str_replace( ',', '&#x002c;', $value ); // store commas encoded
		$value = strtr(
			$value,
			array(
				'%' => '%25',
				'&' => '%26',
			)
		);

		// shortcode_parse_atts() does stripcslashes() so we have to do it here.
		$value = addslashes( $value );
		return $value;
	}

	/**
	 * Unescape attributes.
	 *
	 * @param array $value - the value we're escaping.
	 *
	 * @return array
	 */
	public function unesc_attr( $value ) {
		if ( is_array( $value ) ) {
			return array_map( array( $this, 'unesc_attr' ), $value );
		}

		// For back-compat with old Grunion encoding
		// Also, unencode commas
		$value = strtr(
			(string) $value,
			array(
				'%26' => '&',
				'%25' => '%',
			)
		);
		$value = preg_replace( array( '/&#x0*22;/i', '/&#x0*27;/i', '/&#x0*26;/i', '/&#x0*2c;/i' ), array( '"', "'", '&', ',' ), $value );
		$value = htmlspecialchars_decode( $value, ENT_QUOTES );
		$value = Contact_Form_Plugin::strip_tags( $value );

		return $value;
	}

	/**
	 * Generates the shortcode
	 */
	public function __toString() {
		$r = "[{$this->shortcode_name} ";

		foreach ( $this->attributes as $key => $value ) {
			if ( ! $value ) {
				continue;
			}

			if ( isset( $this->defaults[ $key ] ) && $this->defaults[ $key ] === $value ) {
				continue;
			}

			if ( 'id' === $key ) {
				continue;
			}

			$value = $this->esc_attr( $value );

			if ( is_array( $value ) ) {
				$value = join( ',', $value );
			}

			if ( false === strpos( $value, "'" ) ) {
				$value = "'$value'";
			} elseif ( false === strpos( $value, '"' ) ) {
				$value = '"' . $value . '"';
			} else {
				// Shortcodes can't contain both '"' and "'".  Strip one.
				$value = str_replace( "'", '', $value );
				$value = "'$value'";
			}

			$r .= "{$key}={$value} ";
		}

		$r = rtrim( $r );

		if ( $this->fields ) {
			$r .= ']';

			foreach ( $this->fields as $field ) {
				$r .= (string) $field;
			}

			$r .= "[/{$this->shortcode_name}]";
		} else {
			$r .= '/]';
		}

		return $r;
	}
}
