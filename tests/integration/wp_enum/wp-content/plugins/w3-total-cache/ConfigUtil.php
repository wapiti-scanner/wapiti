<?php
namespace W3TC;

class ConfigUtil {
	static public function is_item_exists( $blog_id, $preview ) {
		if ( defined( 'W3TC_CONFIG_DATABASE' ) && W3TC_CONFIG_DATABASE ) {
			return ConfigDbStorage::is_item_exists( $blog_id, $preview );
		}

		return file_exists( Config::util_config_filename( 0, false ) );
	}



	static public function remove_item( $blog_id, $preview ) {
		if ( defined( 'W3TC_CONFIG_DATABASE' ) && W3TC_CONFIG_DATABASE ) {
			ConfigDbStorage::remove_item( $blog_id, $preview );
		} else {
			$filename = Config::util_config_filename( $blog_id, $preview );
			@unlink( $filename );
		}

		if ( defined( 'W3TC_CONFIG_CACHE_ENGINE' ) ) {
			ConfigCache::remove_item( $blog_id, $preview );
		}
	}



	/**
	 * Deploys the config file from a preview config file
	 *
	 * @param integer $direction     +1: preview->production
	 *                           -1: production->preview
	 * @param boolean $remove_source remove source file
	 */
	static public function preview_production_copy( $blog_id, $direction ) {
		if ( defined( 'W3TC_CONFIG_DATABASE' ) && W3TC_CONFIG_DATABASE ) {
			ConfigDbStorage::preview_production_copy( $blog_id, $direction );
		} else {
			$preview_filename = Config::util_config_filename( $blog_id, true );
			$production_filename = Config::util_config_filename( $blog_id, false );

			if ( $direction > 0 ) {
				$src = $preview_filename;
				$dest = $production_filename;
			} else {
				$src = $production_filename;
				$dest = $preview_filename;
			}

			if ( !@copy( $src, $dest ) ) {
				Util_Activation::throw_on_write_error( $dest );
			}
		}

		if ( defined( 'W3TC_CONFIG_CACHE_ENGINE' ) ) {
			ConfigCache::remove_item( $blog_id, $preview );
		}
	}



	static public function save_item( $blog_id, $preview, $data ) {
		if ( defined( 'W3TC_CONFIG_DATABASE' ) && W3TC_CONFIG_DATABASE ) {
			ConfigDbStorage::save_item( $blog_id, $preview, $data );
		} else {
			$filename = Config::util_config_filename( $blog_id, $preview );
			if ( defined( 'JSON_PRETTY_PRINT' ) )
				$config = json_encode( $data, JSON_PRETTY_PRINT );
			else   // for older php versions
				$config = json_encode( $data );

			Util_File::file_put_contents_atomic( $filename, '<?php exit; ?>' . $config );
		}

		if ( defined( 'W3TC_CONFIG_CACHE_ENGINE' ) ) {
			ConfigCache::remove_item( $blog_id, $preview );
		}
	}
}
