<?php
namespace W3TC;

class SystemOpCache_Core {
	public function is_enabled() {
		return Util_Installed::opcache() || Util_Installed::apc_opcache();
	}



	public function flush() {
		if ( Util_Installed::opcache() ) {
			return opcache_reset();
		} else if ( Util_Installed::apc_opcache() ) {
				$result = apc_clear_cache();   // that doesnt clear user cache
				$result |= apc_clear_cache( 'opcode' );   // extra
				return $result;
			}
		return false;
	}




	public function flush_file( $filename ) {
		if ( file_exists( $filename ) ) {
		} else if ( file_exists( ABSPATH . $filename ) )
				$filename = ABSPATH . DIRECTORY_SEPARATOR . $filename;
			elseif ( file_exists( WP_CONTENT_DIR . DIRECTORY_SEPARATOR . $filename ) )
				$filename = WP_CONTENT_DIR . DIRECTORY_SEPARATOR . $filename;
			elseif ( file_exists( WPINC . DIRECTORY_SEPARATOR . $filename ) )
				$filename = WPINC . DIRECTORY_SEPARATOR . $filename;
			elseif ( file_exists( WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $filename ) )
				$filename = WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $filename;
			else
				return false;

			if ( function_exists( 'opcache_invalidate' ) )
				return opcache_invalidate( $filename, true );
			else if ( function_exists( 'apc_compile_file' ) )
					return apc_compile_file( $filename );

				return false;
	}
}
