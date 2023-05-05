<?php
/**
 * File: Cdn_Util.php
 *
 * @package W3TC
 */

namespace W3TC;

/**
 * Class: Cdn_Util
 */
class Cdn_Util {
	/**
	 * Check whether $engine is correct CDN engine
	 *
	 * @param string $engine CDN engine.
	 *
	 * @return bool
	 */
	public static function is_engine( $engine ) {
		return in_array(
			$engine,
			array(
				'akamai',
				'att',
				'azure',
				'cf',
				'cf2',
				'cotendo',
				'edgecast',
				'ftp',
				'google_drive',
				'highwinds',
				'limelight',
				'mirror',
				'rscf',
				'rackspace_cdn',
				's3',
				's3_compatible',
				'stackpath',
				'stackpath2',
			),
			true
		);
	}

	/**
	 * Returns true if CDN engine is mirror
	 *
	 * @param string $engine CDN engine.
	 *
	 * @return bool
	 */
	public static function is_engine_mirror( $engine ) {
		return in_array(
			$engine,
			array(
				'mirror',
				'cotendo',
				'cf2',
				'akamai',
				'edgecast',
				'att',
				'highwinds',
				'limelight',
				'rackspace_cdn',
				'stackpath',
				'stackpath2',
			),
			true
		);
	}

	/**
	 * Returns true if CDN engine is mirror.
	 *
	 * @param string $engine CDN engine.
	 *
	 * @return bool
	 */
	public static function is_engine_push( $engine ) {
		return ! self::is_engine_mirror( $engine );
	}

	/**
	 * Returns true if CDN has purge all support.
	 *
	 * @param unknown $engine CDN engine.
	 *
	 * @return bool
	 */
	public static function can_purge_all( $engine ) {
		return in_array(
			$engine,
			array(
				'att',
				'cf2',
				'cotendo',
				'edgecast',
				'highwinds',
				'limelight',
				'stackpath',
				'stackpath2',
			),
			true
		);
	}

	/**
	 * Returns true if CDN engine is supporting purge.
	 *
	 * @param string $engine CDN engine.
	 *
	 * @return bool
	 */
	public static function can_purge( $engine ) {
		return in_array(
			$engine,
			array(
				'akamai',
				'att',
				'azure',
				'cf',
				'cf2',
				'cotendo',
				'edgecast',
				'ftp',
				'highwinds',
				'limelight',
				'rscf',
				's3',
				's3_compatible',
				'stackpath',
				'stackpath2',
			),
			true
		);
	}

	/**
	 * Returns true if CDN supports realtime purge. That is purging on post changes, comments etc.
	 *
	 * @param unknown $engine CDN engine.
	 *
	 * @return bool
	 */
	public static function supports_realtime_purge( $engine ) {
		return ! in_array( $engine, array( 'cf2' ), true );
	}

	/**
	 * Search files.
	 *
	 * @param string  $search_dir Search path.
	 * @param string  $base_dir Base path.
	 * @param string  $mask Mask value.
	 * @param boolean $recursive Recursive flag.
	 *
	 * @return array
	 */
	public static function search_files( $search_dir, $base_dir, $mask = '*.*', $recursive = true ) {
		static $stack = array();

		$files  = array();
		$ignore = array(
			'.svn',
			'.git',
			'.DS_Store',
			'CVS',
			'Thumbs.db',
			'desktop.ini',
		);

		$dir = @opendir( $search_dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		if ( $dir ) {
			// phpcs:ignore WordPress.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition, WordPress.PHP.NoSilencedErrors.Discouraged
			while ( ( $entry = @readdir( $dir ) ) !== false ) {
				if ( '.' !== $entry && '..' !== $entry && ! in_array( $entry, $ignore, true ) ) {
					$path = $search_dir . '/' . $entry;

					if ( @is_dir( $path ) && $recursive ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
						array_push( $stack, $entry );
						$files = array_merge(
							$files,
							self::search_files(
								$path,
								$base_dir,
								$mask,
								$recursive
							)
						);
						array_pop( $stack );
					} else {
						$regexp = '~^(' . self::get_regexp_by_mask( $mask ) . ')$~i';

						if ( preg_match( $regexp, $entry ) ) {
							$tmp     = '' !== $base_dir ? $base_dir . '/' : '';
							$p       = implode( '/', $stack );
							$tmp    .= '' !== $p ? $p . '/' : '';
							$files[] = $tmp . $entry;
						}
					}
				}
			}

			@closedir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		}

		return $files;
	}

	/**
	 * Returns regexp by mask.
	 *
	 * @param string $mask Mask pattern.
	 *
	 * @return string
	 */
	public static function get_regexp_by_mask( $mask ) {
		$mask = trim( $mask );
		$mask = Util_Environment::preg_quote( $mask );

		$mask = str_replace(
			array(
				'\*',
				'\?',
				';',
			),
			array(
				'@ASTERISK@',
				'@QUESTION@',
				'|',
			),
			$mask
		);

		$regexp = str_replace(
			array(
				'@ASTERISK@',
				'@QUESTION@',
			),
			array(
				'[^\\?\\*:\\|\'"<>]*',
				'[^\\?\\*:\\|\'"<>]',
			),
			$mask
		);

		return $regexp;
	}

	/**
	 * Replaces folder placeholders.
	 *
	 * @param string $file Replacement value.
	 *
	 * @return string
	 */
	public static function replace_folder_placeholders( $file ) {
		static $content_dir, $plugin_dir, $upload_dir;
		if ( empty( $content_dir ) ) {
			$content_dir = str_replace( Util_Environment::document_root(), '', WP_CONTENT_DIR );
			$content_dir = substr( $content_dir, strlen( Util_Environment::site_url_uri() ) );
			$content_dir = trim( $content_dir, '/' );
			if ( defined( 'WP_PLUGIN_DIR' ) ) {
				$plugin_dir = str_replace( Util_Environment::document_root(), '', WP_PLUGIN_DIR );
				$plugin_dir = trim( $plugin_dir, '/' );
			} else {
				$plugin_dir = str_replace( Util_Environment::document_root(), '', WP_CONTENT_DIR . '/plugins' );
				$plugin_dir = trim( $plugin_dir, '/' );
			}
			$upload_dir = Util_Environment::wp_upload_dir();
			$upload_dir = str_replace( Util_Environment::document_root(), '', $upload_dir['basedir'] );
			$upload_dir = trim( $upload_dir, '/' );
		}
		$file = str_replace( '{wp_content_dir}', $content_dir, $file );
		$file = str_replace( '{plugins_dir}', $plugin_dir, $file );
		$file = str_replace( '{uploads_dir}', $upload_dir, $file );

		return $file;
	}

	/**
	 * Replaces folder placeholders URI.
	 *
	 * @param string $file Replacement value.
	 *
	 * @return string
	 */
	public static function replace_folder_placeholders_to_uri( $file ) {
		static $content_uri, $plugins_uri, $uploads_uri;
		if ( empty( $content_uri ) ) {
			$content_uri = Util_Environment::url_to_uri( content_url() );
			$plugins_uri = Util_Environment::url_to_uri( plugins_url() );

			$upload_dir = Util_Environment::wp_upload_dir();
			if ( isset( $upload_dir['baseurl'] ) ) {
				$uploads_uri = Util_Environment::url_to_uri( $upload_dir['baseurl'] );
			} else {
				$uploads_uri = '';
			}
		}
		$file = str_replace( '{wp_content_dir}', $content_uri, $file );
		$file = str_replace( '{plugins_dir}', $plugins_uri, $file );
		$file = str_replace( '{uploads_dir}', $uploads_uri, $file );

		return $file;
	}

	/**
	 * Get the override default value for cdn.flush_manually to prevent excessive invalidation charges for S3 CF and CF2.
	 *
	 * @since 2.2.6
	 *
	 * @param string $cdn_engine CDN engine value.
	 *
	 * @return boolean default value override;
	 */
	public static function get_flush_manually_default_override( $cdn_engine = null ) {
		$override_targets = array( 's3', 'cf', 'cf2' );
		return in_array( $cdn_engine, $override_targets, true );
	}
}
