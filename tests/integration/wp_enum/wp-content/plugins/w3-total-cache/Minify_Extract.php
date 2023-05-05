<?php
namespace W3TC;

class Minify_Extract {
	/**
	 * Extracts JS files from content
	 * w3tc-url-escaping: When rendered, URLs need to be escaped via
	 * htmlspecialchars instead of esc_attr to not change the way it is encoded
	 * in source html. E.g. html contains a&amp;b Using esc_attr that will not
	 * double escape it as a result config value will be a&b.
	 *
	 * @param string  $content
	 * @return array
	 */
	static public function extract_js( $content ) {
		$matches = null;
		$files = array();

		$content = preg_replace( '~<!--.*?-->~s', '', $content );

		if ( preg_match_all( '~<script\s+[^<>]*src=["\']?([^"\']+)["\']?[^<>]*>\s*</script>~is',
				$content, $matches ) ) {
			$files = $matches[1];
		}

		$files = array_values( array_unique( $files ) );

		return $files;
	}

	/**
	 * Extract CSS files from content
	 *
	 * @param string  $content
	 * @return array
	 */
	static public function extract_css( $content ) {
		$content = preg_replace( '~<!--.*?-->~s', '', $content );

		$tags_files = array();

		$matches = null;
		if ( preg_match_all( '~<link\s+([^>]+)/?>(.*</link>)?~Uis', $content,
				$matches, PREG_SET_ORDER ) ) {
			foreach ( $matches as $match ) {
				$attrs = array();
				$attr_matches = null;
				if ( preg_match_all( '~(\w+)=["\']([^"\']*)["\']~', $match[1],
						$attr_matches, PREG_SET_ORDER ) ) {
					foreach ( $attr_matches as $attr_match ) {
						$attrs[$attr_match[1]] = trim( $attr_match[2] );
					}
				}

				if ( isset( $attrs['href'] ) && isset( $attrs['rel'] ) &&
					stristr( $attrs['rel'], 'stylesheet' ) !== false &&
					( !isset( $attrs['media'] ) || stristr( $attrs['media'], 'print' ) === false ) ) {
					$tags_files[] = array( $match[0], $attrs['href'] );
				}
			}

		}

		if ( preg_match_all( '~@import\s+(url\s*)?\(?["\']?\s*([^"\'\)\s]+)\s*["\']?\)?[^;]*;?~is',
				$content, $matches, PREG_SET_ORDER ) ) {
			foreach ( $matches as $match )
				$tags_files[] = array( $match[0], $match[2] );
		}

		return $tags_files;
	}
}
