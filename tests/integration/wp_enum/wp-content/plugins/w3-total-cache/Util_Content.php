<?php
namespace W3TC;

class Util_Content {
	/**
	 * Check if content is HTML
	 *
	 * @param string  $content
	 * @return boolean
	 */
	static public function is_html( $content ) {
		$content = Util_Content::_is_html_prepare( $content );
		return stripos( $content, '<html' ) === 0 ||
			stripos( $content, '<!DOCTYPE' ) === 0;
	}

	/**
	 * Check if content is HTML or XML
	 *
	 * @param string  $content
	 * @return boolean
	 */
	static public function is_html_xml( $content ) {
		$content = Util_Content::_is_html_prepare( $content );
		return stripos( $content, '<?xml' ) === 0 ||
			stripos( $content, '<html' ) === 0 ||
			stripos( $content, '<!DOCTYPE' ) === 0;
	}

	static private function _is_html_prepare( $content ) {
		if ( strlen( $content ) > 1000 ) {
			$content = substr( $content, 0, 1000 );
		}

		if ( strstr( $content, '<!--' ) !== false ) {
			$content = preg_replace( '~<!--.*?-->~s', '', $content );
		}

		$content = ltrim( $content, "\x00\x09\x0A\x0D\x20\xBB\xBF\xEF" );
		return $content;
	}

	/**
	 * If content can handle HTML comments, can disable printout per request using filter 'w3tc_can_print_comment'
	 *
	 * @param unknown $buffer
	 * @return bool
	 */
	static public function can_print_comment( $buffer ) {
		if ( function_exists( 'apply_filters' ) )
			return apply_filters( 'w3tc_can_print_comment', Util_Content::is_html_xml( $buffer ) && !defined( 'DOING_AJAX' ) );
		return Util_Content::is_html_xml( $buffer ) && !defined( 'DOING_AJAX' );
	}

	/**
	 * Returns GMT date
	 *
	 * @param integer $time
	 * @return string
	 */
	static public function http_date( $time ) {
		return gmdate( 'D, d M Y H:i:s \G\M\T', $time );
	}

	/**
	 * Escapes HTML comment
	 *
	 * @param string  $comment
	 * @return mixed
	 */
	static public function escape_comment( $comment ) {
		while ( strstr( $comment, '--' ) !== false ) {
			$comment = str_replace( '--', '- -', $comment );
		}

		return $comment;
	}



	/**
	 * Deprecated. Added to prevent loading-order errors during upgrades
	 * from older w3tc plugin versions
	 **/
	static public function is_database_error() {
		return false;
	}



	/**
	 * Converts
	 * 127.0.0.1:1234 to ( '123.0.0.1', 1234 )
	 * tls://127.0.0.1:1234 to ( 'tls://123.0.0.1', 1234 )
	 * unix:/my/pipe to ( 'unix:/my/pipe', 0 )
	 *
	 * Doesnt fit to that class perfectly but selected due to common usage
	 * of loaded classes
	 */
	static public function endpoint_to_host_port( $server, $port_default = 0 ) {
		$p = strrpos( $server, ':' );
		if ( substr( $server, 0, 5 ) == 'unix:' || $p === false ) {
			return array( trim( $server ), $port_default );
		}

		return array(
			trim( substr( $server, 0, $p ) ),
			(int)substr( $server, $p + 1 ) );
	}
}
