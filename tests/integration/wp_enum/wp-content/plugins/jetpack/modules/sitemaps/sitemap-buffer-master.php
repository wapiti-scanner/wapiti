<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
// phpcs:disable Generic.Classes.DuplicateClassName.Found -- sitemap-builder.php will require correct class file.
/**
 * Sitemaps (per the protocol) are essentially lists of XML fragments;
 * lists which are subject to size constraints. The Jetpack_Sitemap_Buffer_Master
 * extends the Jetpack_Sitemap_Buffer class to represent the master sitemap
 * buffer.
 *
 * @since 5.3.0
 * @package automattic/jetpack
 */

/**
 * A buffer for constructing master sitemap xml files.
 *
 * @since 5.3.0
 */
class Jetpack_Sitemap_Buffer_Master extends Jetpack_Sitemap_Buffer {
	/**
	 * Jetpack_Sitemap_Buffer_Master constructor.
	 *
	 * @param int    $item_limit The maximum size of the buffer in items.
	 * @param int    $byte_limit The maximum size of the buffer in bytes.
	 * @param string $time The initial datetime of the buffer. Must be in 'YYYY-MM-DD hh:mm:ss' format.
	 */
	public function __construct( $item_limit, $byte_limit, $time = '1970-01-01 00:00:00' ) {
		parent::__construct( $item_limit, $byte_limit, $time );

		$this->doc->appendChild(
			$this->doc->createComment( "generator='jetpack-" . JETPACK__VERSION . "'" )
		);

		$this->doc->appendChild(
			$this->doc->createComment( 'Jetpack_Sitemap_Buffer_Master' )
		);

		$this->doc->appendChild(
			$this->doc->createProcessingInstruction(
				'xml-stylesheet',
				'type="text/xsl" href="' . $this->finder->construct_sitemap_url( 'sitemap-index.xsl' ) . '"'
			)
		);
	}

	/**
	 * Returns a DOM element that contains all master sitemap elements.
	 */
	protected function get_root_element() {
		if ( ! isset( $this->root ) ) {
			$this->root = $this->doc->createElement( 'sitemapindex' );
			$this->root->setAttribute( 'xmlns', 'http://www.sitemaps.org/schemas/sitemap/0.9' );
			$this->doc->appendChild( $this->root );
			$this->byte_capacity -= strlen( $this->doc->saveXML( $this->root ) );
		}

		return $this->root;
	}
}
