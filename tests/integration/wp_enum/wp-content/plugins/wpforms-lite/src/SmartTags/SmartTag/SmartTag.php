<?php

namespace WPForms\SmartTags\SmartTag;

/**
 * Class SmartTag.
 *
 * @since 1.6.7
 */
abstract class SmartTag {

	/**
	 * Full smart tag.
	 * For example: {smart_tag attr="1" attr2="true"}.
	 *
	 * @since 1.6.7
	 *
	 * @var string
	 */
	protected $smart_tag;

	/**
	 * List of attributes.
	 *
	 * @since 1.6.7
	 *
	 * @var array
	 */
	protected $attributes = [];

	/**
	 * SmartTag constructor.
	 *
	 * @since 1.6.7
	 *
	 * @param string $smart_tag Full smart tag.
	 */
	public function __construct( $smart_tag ) {

		$this->smart_tag = $smart_tag;
	}

	/**
	 * Get smart tag value.
	 *
	 * @since 1.6.7
	 *
	 * @param array  $form_data Form data.
	 * @param array  $fields    List of fields.
	 * @param string $entry_id  Entry ID.
	 *
	 * @return string
	 */
	abstract public function get_value( $form_data, $fields = [], $entry_id = '' );

	/**
	 * Get list of smart tag attributes.
	 *
	 * @since 1.6.7
	 *
	 * @return array
	 */
	public function get_attributes() {

		if ( ! empty( $this->attributes ) ) {
			return $this->attributes;
		}

		/**
		 * (\w+) an attribute name and also the first capturing group. Lowercase or uppercase letters, digits, underscore.
		 * = the equal sign.
		 * (["\']) single or double quote, the second capturing group.
		 * (.+?) an attribute value within the quotes, and also the third capturing group. Any number of any characters except new line. Lazy mode - match as few characters as possible to allow multiple attributes on one line.
		 * \2 - repeat the second capturing group.
		 */
		preg_match_all( '/(\w+)=(["\'])(.+?)\2/', $this->smart_tag, $attributes );
		$this->attributes = array_combine( $attributes[1], $attributes[3] );

		return $this->attributes;
	}
}
