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
 * A buffer for constructing master sitemap xml files for users without libxml support.
 *
 * @since 5.3.0
 */
class Jetpack_Sitemap_Buffer_Master extends Jetpack_Sitemap_Buffer_Fallback {

	/**
	 * Returns a DOM element that contains all master sitemap elements.
	 */
	protected function get_root_element() {

		if ( ! isset( $this->root ) ) {

			$sitemap_index_xsl_url = $this->finder->construct_sitemap_url( 'sitemap-index.xsl' );
			$jetpack_version       = JETPACK__VERSION;

			$this->root = array(
				"<!-- generator='jetpack-{$jetpack_version}' -->" . PHP_EOL
				. "<?xml-stylesheet type='text/xsl' href='{$sitemap_index_xsl_url}'?>" . PHP_EOL
				. "<sitemapindex xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>" . PHP_EOL,
				'</sitemapindex>',
			);

			$this->byte_capacity -= strlen( join( '', $this->root ) );
		}

		return $this->root;
	}
}
