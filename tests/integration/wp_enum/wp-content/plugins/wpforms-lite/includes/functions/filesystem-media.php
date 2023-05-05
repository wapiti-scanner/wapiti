<?php
/**
 * Helper functions to work with filesystem, uploads and media files.
 *
 * @since 1.8.0
 */

/**
 * Get WPForms upload root path (e.g. /wp-content/uploads/wpforms).
 *
 * As of 1.7.0, you can pass in your own value that matches the output of wp_upload_dir()
 * in order to use this function inside of a filter without infinite looping.
 *
 * @since 1.6.1
 *
 * @return array WPForms upload root path (no trailing slash).
 */
function wpforms_upload_dir() {

	$upload_dir = wp_upload_dir();

	if ( ! empty( $upload_dir['error'] ) ) {
		return [ 'error' => $upload_dir['error'] ];
	}

	$basedir             = wp_is_stream( $upload_dir['basedir'] ) ? $upload_dir['basedir'] : realpath( $upload_dir['basedir'] );
	$wpforms_upload_root = trailingslashit( $basedir ) . 'wpforms';

	/**
	 * Allow developers to change a directory where cache and uploaded files will be stored.
	 *
	 * @since 1.5.2
	 *
	 * @param string $wpforms_upload_root WPForms upload root directory.
	 */
	$custom_uploads_root = apply_filters( 'wpforms_upload_root', $wpforms_upload_root );

	if ( is_dir( $custom_uploads_root ) && wp_is_writable( $custom_uploads_root ) ) {
		$wpforms_upload_root = wp_is_stream( $custom_uploads_root )
			? $custom_uploads_root
			: realpath( $custom_uploads_root );
	}

	return [
		'path'  => $wpforms_upload_root,
		'url'   => trailingslashit( $upload_dir['baseurl'] ) . 'wpforms',
		'error' => false,
	];
}

/**
 * Create index.html file in the specified directory if it doesn't exist.
 *
 * @since 1.6.1
 *
 * @param string $path Path to the directory.
 *
 * @return int|false Number of bytes that were written to the file, or false on failure.
 */
function wpforms_create_index_html_file( $path ) {

	if ( ! is_dir( $path ) || is_link( $path ) ) {
		return false;
	}

	$index_file = wp_normalize_path( trailingslashit( $path ) . 'index.html' );

	// Do nothing if index.html exists in the directory.
	if ( file_exists( $index_file ) ) {
		return false;
	}

	// Create empty index.html.
	return file_put_contents( $index_file, '' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
}

/**
 * Create .htaccess file in the WPForms upload directory.
 *
 * @since 1.6.1
 *
 * @return bool True when the .htaccess file exists, false on failure.
 */
function wpforms_create_upload_dir_htaccess_file() {

	if ( ! apply_filters( 'wpforms_create_upload_dir_htaccess_file', true ) ) {
		return false;
	}

	$upload_dir = wpforms_upload_dir();

	if ( ! empty( $upload_dir['error'] ) ) {
		return false;
	}

	$htaccess_file = wp_normalize_path( trailingslashit( $upload_dir['path'] ) . '.htaccess' );
	$cache_key     = 'wpforms_htaccess_file';

	if ( is_file( $htaccess_file ) ) {
		$cached_stat = get_transient( $cache_key );
		$stat        = array_intersect_key(
			stat( $htaccess_file ),
			[
				'size'  => 0,
				'mtime' => 0,
				'ctime' => 0,
			]
		);

		if ( $cached_stat === $stat ) {
			return true;
		}

		@unlink( $htaccess_file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
	}

	if ( ! function_exists( 'insert_with_markers' ) ) {
		require_once ABSPATH . 'wp-admin/includes/misc.php';
	}

	$contents = apply_filters(
		'wpforms_create_upload_dir_htaccess_file_content',
		'# Disable PHP and Python scripts parsing.
<Files *>
  SetHandler none
  SetHandler default-handler
  RemoveHandler .cgi .php .php3 .php4 .php5 .phtml .pl .py .pyc .pyo
  RemoveType .cgi .php .php3 .php4 .php5 .phtml .pl .py .pyc .pyo
</Files>
<IfModule mod_php5.c>
  php_flag engine off
</IfModule>
<IfModule mod_php7.c>
  php_flag engine off
</IfModule>
<IfModule mod_php8.c>
  php_flag engine off
</IfModule>
<IfModule headers_module>
  Header set X-Robots-Tag "noindex"
</IfModule>'
	);

	$created = insert_with_markers( $htaccess_file, 'WPForms', $contents );

	if ( $created ) {
		clearstatcache( true, $htaccess_file );
		$stat = array_intersect_key(
			stat( $htaccess_file ),
			[
				'size'  => 0,
				'mtime' => 0,
				'ctime' => 0,
			]
		);

		set_transient( $cache_key, $stat );
	}

	return $created;
}

/**
 * Convert a file size provided, such as "2M", to bytes.
 *
 * @link http://stackoverflow.com/a/22500394
 *
 * @since 1.0.0
 *
 * @param string $size File size.
 *
 * @return int
 */
function wpforms_size_to_bytes( $size ) {

	if ( is_numeric( $size ) ) {
		return $size;
	}

	$suffix = substr( $size, - 1 );
	$value  = substr( $size, 0, - 1 );

	switch ( strtoupper( $suffix ) ) {
		case 'P':
			$value *= 1024;

		case 'T':
			$value *= 1024;

		case 'G':
			$value *= 1024;

		case 'M':
			$value *= 1024;

		case 'K':
			$value *= 1024;
			break;
	}

	return $value;
}

/**
 * Convert a file size provided, such as "2M", to bytes.
 *
 * @link http://stackoverflow.com/a/22500394
 *
 * @since 1.0.0
 *
 * @param bool $bytes Whether the value should be in bytes or formatted.
 *
 * @return false|string|int
 */
function wpforms_max_upload( $bytes = false ) {

	$max = wp_max_upload_size();

	if ( $bytes ) {
		return $max;
	}

	return size_format( $max );
}
