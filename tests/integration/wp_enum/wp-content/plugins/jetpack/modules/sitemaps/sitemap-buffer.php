<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Sitemaps (per the protocol) are essentially lists of XML fragments;
 * lists which are subject to size constraints. The Jetpack_Sitemap_Buffer
 * class abstracts the details of constructing these lists while
 * maintaining the constraints.
 *
 * @since 4.8.0
 * @package automattic/jetpack
 */

/**
 * A buffer for constructing sitemap xml files.
 *
 * Models a list of strings such that
 *
 * 1. the list must have a bounded number of entries,
 * 2. the concatenation of the strings must have bounded
 *      length (including some header and footer strings), and
 * 3. each item has a timestamp, and we need to keep track
 *      of the most recent timestamp of the items in the list.
 *
 * @since 4.8.0
 */
abstract class Jetpack_Sitemap_Buffer {

	/**
	 * Largest number of items the buffer can hold.
	 *
	 * @access protected
	 * @since 4.8.0
	 * @var int $item_capacity The item capacity.
	 */
	protected $item_capacity;

	/**
	 * Largest number of bytes the buffer can hold.
	 *
	 * @access protected
	 * @since 4.8.0
	 * @var int $byte_capacity The byte capacity.
	 */
	protected $byte_capacity;

	/**
	 * Flag which detects when the buffer is full.
	 *
	 * @access protected
	 * @since 4.8.0
	 * @var bool $is_full_flag The flag value. This flag is set to false on construction and only flipped to true if we've tried to add something and failed.
	 */
	protected $is_full_flag;

	/**
	 * Flag which detects when the buffer is empty.
	 *
	 * @access protected
	 * @since 4.8.0
	 * @var bool $is_empty_flag The flag value. This flag is set to true on construction and only flipped to false if we've tried to add something and succeeded.
	 */
	protected $is_empty_flag;

	/**
	 * The most recent timestamp seen by the buffer.
	 *
	 * @access protected
	 * @since 4.8.0
	 * @var string $timestamp Must be in 'YYYY-MM-DD hh:mm:ss' format.
	 */
	protected $timestamp;

	/**
	 * The DOM document object that is currently being used to construct the XML doc.
	 *
	 * @access protected
	 * @since 5.3.0
	 * @var DOMDocument $doc
	 */
	protected $doc = null;

	/**
	 * The root DOM element object that holds everything inside. Do not use directly, call
	 * the get_root_element getter method instead.
	 *
	 * @access protected
	 * @since 5.3.0
	 * @var DOMElement $doc
	 */
	protected $root = null;

	/**
	 * Helper class to construct sitemap paths.
	 *
	 * @since 5.3.0
	 * @protected
	 * @var Jetpack_Sitemap_Finder
	 */
	protected $finder;

	/**
	 * Construct a new Jetpack_Sitemap_Buffer.
	 *
	 * @since 4.8.0
	 *
	 * @param int    $item_limit The maximum size of the buffer in items.
	 * @param int    $byte_limit The maximum size of the buffer in bytes.
	 * @param string $time The initial datetime of the buffer. Must be in 'YYYY-MM-DD hh:mm:ss' format.
	 */
	public function __construct( $item_limit, $byte_limit, $time ) {
		$this->is_full_flag = false;
		$this->timestamp    = $time;

		$this->finder = new Jetpack_Sitemap_Finder();
		$this->doc    = new DOMDocument( '1.0', 'UTF-8' );

		$this->item_capacity = max( 1, (int) $item_limit );
		$this->byte_capacity = max( 1, (int) $byte_limit ) - strlen( $this->doc->saveXML() );
	}

	/**
	 * Returns a DOM element that contains all sitemap elements.
	 *
	 * @access protected
	 * @since 5.3.0
	 * @return DOMElement $root
	 */
	abstract protected function get_root_element();

	/**
	 * Append an item to the buffer, if there is room for it,
	 * and set is_empty_flag to false. If there is no room,
	 * we set is_full_flag to true. If $item is null,
	 * don't do anything and report success.
	 *
	 * @since 5.3.0
	 *
	 * @param array $array The item to be added.
	 *
	 * @return bool True if the append succeeded, False if not.
	 */
	public function append( $array ) {
		if ( $array === null ) {
			return true;
		}

		if ( $this->is_full_flag ) {
			return false;
		}

		if ( 0 >= $this->item_capacity || 0 >= $this->byte_capacity ) {
			$this->is_full_flag = true;
			return false;
		} else {
			$this->item_capacity -= 1;
			$added_element        = $this->array_to_xml_string( $array, $this->get_root_element(), $this->doc );

			$this->byte_capacity -= strlen( $this->doc->saveXML( $added_element ) );

			return true;
		}
	}

	/**
	 * Retrieve the contents of the buffer.
	 *
	 * @since 4.8.0
	 *
	 * @return string The contents of the buffer (with the footer included).
	 */
	public function contents() {
		if ( $this->is_empty() ) {
			// The sitemap should have at least the root element added to the DOM.
			$this->get_root_element();
		}
		return $this->doc->saveXML();
	}

	/**
	 * Retrieve the document object.
	 *
	 * @since 5.3.0
	 * @return DOMDocument $doc
	 */
	public function get_document() {
		return $this->doc;
	}

	/**
	 * Detect whether the buffer is full.
	 *
	 * @since 4.8.0
	 *
	 * @return bool True if the buffer is full, false otherwise.
	 */
	public function is_full() {
		return $this->is_full_flag;
	}

	/**
	 * Detect whether the buffer is empty.
	 *
	 * @since 4.8.0
	 *
	 * @return bool True if the buffer is empty, false otherwise.
	 */
	public function is_empty() {
		return (
			! isset( $this->root )
			|| ! $this->root->hasChildNodes()
		);
	}

	/**
	 * Update the timestamp of the buffer.
	 *
	 * @since 4.8.0
	 *
	 * @param string $new_time A datetime string in 'YYYY-MM-DD hh:mm:ss' format.
	 */
	public function view_time( $new_time ) {
		$this->timestamp = max( $this->timestamp, $new_time );
	}

	/**
	 * Retrieve the timestamp of the buffer.
	 *
	 * @since 4.8.0
	 *
	 * @return string A datetime string in 'YYYY-MM-DD hh:mm:ss' format.
	 */
	public function last_modified() {
		return $this->timestamp;
	}

	/**
	 * Render an associative array as an XML string. This is needed because
	 * SimpleXMLElement only handles valid XML, but we sometimes want to
	 * pass around (possibly invalid) fragments. Note that 'null' values make
	 * a tag self-closing; this is only sometimes correct (depending on the
	 * version of HTML/XML); see the list of 'void tags'.
	 *
	 * Example:
	 *
	 * array(
	 *   'html' => array(                    |<html xmlns="foo">
	 *     'head' => array(                  |  <head>
	 *       'title' => 'Woo!',              |    <title>Woo!</title>
	 *     ),                                |  </head>
	 *     'body' => array(             ==>  |  <body>
	 *       'h2' => 'Some thing',           |    <h2>Some thing</h2>
	 *       'p'  => 'it's all up ons',      |    <p>it's all up ons</p>
	 *       'br' => null,                   |    <br />
	 *     ),                                |  </body>
	 *   ),                                  |</html>
	 * )
	 *
	 * @access protected
	 * @since 3.9.0
	 * @since 4.8.0 Rename, add $depth parameter, and change return type.
	 * @since 5.3.0 Refactor, remove $depth parameter, add $parent and $root, make access protected.
	 *
	 * @param array       $array A recursive associative array of tag/child relationships.
	 * @param DOMElement  $parent (optional) an element to which new children should be added.
	 * @param DOMDocument $root (optional) the parent document.
	 *
	 * @return string|DOMDocument The rendered XML string or an object if root element is specified.
	 */
	protected function array_to_xml_string( $array, $parent = null, $root = null ) {
		$return_string = false;

		if ( null === $parent ) {
			$return_string = true;
			$root          = new DOMDocument();
			$parent        = $root;
		}

		if ( is_array( $array ) ) {

			foreach ( $array as $key => $value ) {
				$element = $root->createElement( $key );
				$parent->appendChild( $element );

				if ( is_array( $value ) ) {
					foreach ( $value as $child_key => $child_value ) {
						$child = $root->createElement( $child_key );
						$element->appendChild( $child );
						$child->appendChild( self::array_to_xml_string( $child_value, $child, $root ) );
					}
				} else {
					$element->appendChild(
						$root->createTextNode( $value )
					);
				}
			}
		} else {
			$element = $root->createTextNode( $array );
			$parent->appendChild( $element );
		}

		if ( $return_string ) {
			return $root->saveHTML();
		} else {
			return $element;
		}
	}
}
