<?php
namespace W3TC;

/**
 * Browsercache core
 */
class BrowserCache_Core {
	/**
	 * Returns replace extensions
	 *
	 * @return array
	 */
	public function get_replace_extensions( $config ) {
		$types = array();
		$extensions = array();

		if ( $config->get_boolean( 'browsercache.cssjs.replace' ) ) {
			$types = array_merge( $types, array_keys( $this->_get_cssjs_types() ) );
		}

		if ( $config->get_boolean( 'browsercache.html.replace' ) ) {
			$types = array_merge( $types, array_keys( $this->_get_html_types() ) );
		}

		if ( $config->get_boolean( 'browsercache.other.replace' ) ) {
			$types = array_merge( $types, array_keys( $this->_get_other_types() ) );
		}

		foreach ( $types as $type ) {
			$extensions = array_merge( $extensions, explode( '|', $type ) );
		}

		return $extensions;
	}



	/**
	 * Returns replace extensions
	 *
	 * @return array
	 */
	public function get_replace_querystring_extensions( $config ) {
		$extensions = array();

		if ( $config->get_boolean( 'browsercache.cssjs.replace' ) )
			$this->_fill_extensions( $extensions, $this->_get_cssjs_types(), 'replace' );
		if ( $config->get_boolean( 'browsercache.html.replace' ) )
			$this->_fill_extensions( $extensions, $this->_get_html_types(), 'replace' );
		if ( $config->get_boolean( 'browsercache.other.replace' ) )
			$this->_fill_extensions( $extensions, $this->_get_other_types(), 'replace' );

		if ( $config->get_boolean( 'browsercache.cssjs.querystring' ) )
			$this->_fill_extensions( $extensions, $this->_get_cssjs_types(), 'querystring' );
		if ( $config->get_boolean( 'browsercache.html.querystring' ) )
			$this->_fill_extensions( $extensions, $this->_get_html_types(), 'querystring' );
		if ( $config->get_boolean( 'browsercache.other.querystring' ) )
			$this->_fill_extensions( $extensions, $this->_get_other_types(), 'querystring' );

		return $extensions;
	}



	private function _fill_extensions( &$extensions, $types, $operation ) {
		foreach ( array_keys( $types ) as $type ) {
			$type_extensions = explode( '|', $type );
			foreach ( $type_extensions as $ext ) {
				if ( !isset( $extensions[$ext] ) )
					$extensions[$ext] = array();
				$extensions[$ext][$operation] = true;
			}
		}
	}

	/**
	 * Returns CSS/JS mime types
	 *
	 * @return array
	 */
	private function _get_cssjs_types() {
		$mime_types = include W3TC_INC_DIR . '/mime/cssjs.php';
		return $mime_types;
	}



	/**
	 * Returns HTML mime types
	 *
	 * @return array
	 */
	private function _get_html_types() {
		$mime_types = include W3TC_INC_DIR . '/mime/html.php';
		return $mime_types;
	}



	/**
	 * Returns other mime types
	 *
	 * @return array
	 */
	private function _get_other_types() {
		$mime_types = include W3TC_INC_DIR . '/mime/other.php';
		return $mime_types;
	}
}
