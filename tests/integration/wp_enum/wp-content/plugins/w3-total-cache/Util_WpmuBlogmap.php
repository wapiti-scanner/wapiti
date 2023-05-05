<?php
namespace W3TC;

class Util_WpmuBlogmap {
	static $content_by_filename = array();
	/**
	 * Returns blogmap filename by home url
	 *
	 * @param string  $blog_home_url
	 * @return string
	 */
	static public function blogmap_filename_by_home_url( $blog_home_url ) {
		if ( !defined( 'W3TC_BLOG_LEVELS' ) )
			return W3TC_CACHE_BLOGMAP_FILENAME;
		else {
			$filename = dirname( W3TC_CACHE_BLOGMAP_FILENAME ) . '/' .
				basename( W3TC_CACHE_BLOGMAP_FILENAME, '.json' ) . '/';

			$s = md5( $blog_home_url );
			for ( $n = 0; $n < W3TC_BLOG_LEVELS; $n++ )
				$filename .= substr( $s, $n, 1 ) . '/';

			return $filename . basename( W3TC_CACHE_BLOGMAP_FILENAME );
		}
	}

	/**
	 * Returns blog_id by home url
	 * If database not initialized yet - returns 0
	 *
	 * @return integer
	 */
	static public function get_current_blog_data() {
		$host = Util_Environment::host();

		// subdomain
		if ( Util_Environment::is_wpmu_subdomain() ) {
			$blog_data = Util_WpmuBlogmap::try_get_current_blog_data( $host );
			if ( is_null( $blog_data ) )
				$GLOBALS['w3tc_blogmap_register_new_item'] = $host;

			return $blog_data;
		} else {
			// try subdir blog
			$url = $host . ( isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '' ); // phpcs:ignore
			$pos = strpos( $url, '?' );
			if ( $pos !== false )
				$url = substr( $url, 0, $pos );

			$url = rtrim( $url, '/' );
			$start_url = $url;

			for ( ;; ) {
				$blog_data = Util_WpmuBlogmap::try_get_current_blog_data( $url );
				if ( !is_null( $blog_data ) )
					return $blog_data;
				$pos = strrpos( $url, '/' );
				if ( $pos === false )
					break;

				$url = rtrim( substr( $url, 0, $pos ), '/' );
			}

			$GLOBALS['w3tc_blogmap_register_new_item'] = $start_url;
			return null;
		}
	}



	static public function try_get_current_blog_data( $url ) {
		$filename = Util_WpmuBlogmap::blogmap_filename_by_home_url( $url );

		if ( isset( self::$content_by_filename[$filename] ) ) {
			$blog_data = self::$content_by_filename[$filename];
		} else {
			$blog_data = null;

			if ( file_exists( $filename ) ) {
				$data = file_get_contents( $filename );
				$blog_data = @json_decode( $data, true );

				if ( is_array( $blog_data ) )
					self::$content_by_filename[$filename] = $blog_data;
			}
		}

		if ( isset( $blog_data[$url] ) )
			return $blog_data[$url];

		return null;
	}

	/**
	 * Registers new blog url in url=>blog mapfile
	 */
	static public function register_new_item( $config ) {
		if ( !isset( $GLOBALS['current_blog'] ) ) {
			return false;
		}


		// find blog_home_url
		if ( Util_Environment::is_wpmu_subdomain() ) {
			$blog_home_url = $GLOBALS['w3tc_blogmap_register_new_item'];
		} else {
			$home_url = rtrim( get_home_url(), '/' );
			if ( substr( $home_url, 0, 7 ) == 'http://' ) {
				$home_url = substr( $home_url, 7 );
			} else if ( substr( $home_url, 0, 8 ) == 'https://' ) {
				$home_url = substr( $home_url, 8 );
			}

			if ( substr( $GLOBALS['w3tc_blogmap_register_new_item'], 0,
					strlen( $home_url ) ) == $home_url ) {
				$blog_home_url = $home_url;
			} else {
				$blog_home_url = $GLOBALS['w3tc_blogmap_register_new_item'];
			}
		}


		// write contents
		$filename = Util_WpmuBlogmap::blogmap_filename_by_home_url( $blog_home_url );

		if ( !@file_exists( $filename ) ) {
			$blog_ids = array();
		} else {
			$data = @file_get_contents( $filename );
			$blog_ids = @json_decode( $data, true );
			if ( !is_array( $blog_ids ) ) {
				$blog_ids = array();
			}
		}

		if ( isset( $blog_ids[$blog_home_url] ) ) {
			return false;
		}

		$data = $config->get_boolean( 'common.force_master' ) ? 'm' : 'c';
		$blog_home_url = preg_replace( '/[^a-zA-Z0-9\+\.%~!:()\/\-\_]/', '', $blog_home_url );
		$blog_ids[$blog_home_url] = $data . $GLOBALS['current_blog']->blog_id;

		$data = json_encode( $blog_ids );

		try {
			Util_File::file_put_contents_atomic( $filename, $data );
		} catch ( \Exception $ex ) {
			return false;
		}

		unset( self::$content_by_filename[$filename] );
		unset( $GLOBALS['w3tc_blogmap_register_new_item'] );

		return true;
	}
}
