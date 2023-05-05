<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
// phpcs:disable Generic.Classes.DuplicateClassName.Found -- sitemap-builder.php will require correct class file.
/**
 * Sitemaps (per the protocol) are essentially lists of XML fragments;
 * lists which are subject to size constraints. The Jetpack_Sitemap_Buffer_Page
 * extends the Jetpack_Sitemap_Buffer class to represent the single page sitemap
 * buffer.
 *
 * @since 5.3.0
 * @package automattic/jetpack
 */

/**
 * A buffer for constructing sitemap page xml files for users with no libxml support.
 *
 * @since 5.3.0
 */
class Jetpack_Sitemap_Buffer_Page extends Jetpack_Sitemap_Buffer_Fallback {
	/**
	 * Returns a DOM element that contains all single page sitemap elements.
	 */
	protected function get_root_element() {
		if ( ! isset( $this->root ) ) {

			/**
			 * Filter the attribute value pairs used for namespace and namespace URI mappings.
			 *
			 * @module sitemaps
			 *
			 * @since 3.9.0
			 *
			 * @param array $namespaces Associative array with namespaces and namespace URIs.
			 */
			$namespaces = apply_filters(
				'jetpack_sitemap_ns',
				array(
					'xmlns:xsi'          => 'http://www.w3.org/2001/XMLSchema-instance',
					'xsi:schemaLocation' => 'http://www.sitemaps.org/schemas/sitemap/0.9 http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd',
					'xmlns'              => 'http://www.sitemaps.org/schemas/sitemap/0.9',
				)
			);

			$jetpack_version = JETPACK__VERSION;
			$sitemap_xsl_url = $this->finder->construct_sitemap_url( 'sitemap.xsl' );

			$this->root = array(
				"<!-- generator='jetpack-{$jetpack_version}' -->" . PHP_EOL
				. "<?xml-stylesheet type='text/xsl' href='{$sitemap_xsl_url}'?>" . PHP_EOL
				. '<urlset ' . $this->array_to_xml_attr_string( $namespaces ) . '>',
				'</urlset>',
			);

			$this->byte_capacity -= strlen( join( '', $this->root ) );
		}

		return $this->root;
	}
}
