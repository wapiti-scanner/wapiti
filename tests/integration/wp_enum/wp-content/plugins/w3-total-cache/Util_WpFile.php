<?php
/**
 * File: Util_WpFile.php
 *
 * @package W3TC
 */

namespace W3TC;

/**
 * Class: Util_WpFile
 */
class Util_WpFile {
	/**
	 * Check WP_Filesystem credentials when running ajax.
	 *
	 * @since 2.2.1
	 *
	 * @param string $extra Extra markup for an error message.
	 */
	public static function ajax_check_credentials( $extra = null ) {
		$access_type = get_filesystem_method();
		ob_start();
		$credentials = request_filesystem_credentials(
			site_url() . '/wp-admin/',
			$access_type
		);
		ob_end_clean();

		if ( false === $credentials || ! WP_Filesystem( $credentials ) ) {
			global $wp_filesystem;

			$status['error'] = sprintf(
				// translators: 1: Filesystem access method: "direct", "ssh2", "ftpext" or "ftpsockets".
				__(
					'Unable to connect to the filesystem (using %1$s). Please confirm your credentials.  %2$s',
					'w3-total-cache'
				),
				$access_type,
				$extra
			);

			// Pass through the error from WP_Filesystem if one was raised.
			if ( $wp_filesystem instanceof WP_Filesystem_Base && is_wp_error( $wp_filesystem->errors ) &&
				$wp_filesystem->errors->has_errors() ) {
					$status['error'] = esc_html( $wp_filesystem->errors->get_error_message() );
			}

			wp_send_json_error( $status );
		}
	}

	/**
	 * Tries to write file content
	 *
	 * @param string  $filename path to file
	 * @param string  $content  data to write
	 * @param string  $method   Which method to use when creating
	 * @param string  $url      Where to redirect after creation
	 * @param bool|string $context  folder in which to write file
	 * @throws Util_WpFile_FilesystemWriteException
	 * @return void
	 */
	static public function write_to_file( $filename, $content ) {
		if ( @file_put_contents( $filename, $content ) )
			return;

		try {
			self::request_filesystem_credentials();
		} catch ( Util_WpFile_FilesystemOperationException $ex ) {
			throw new Util_WpFile_FilesystemWriteException( $ex->getMessage(),
				$ex->credentials_form(), $filename, $content );
		}

		global $wp_filesystem;
		if ( !$wp_filesystem->put_contents( $filename, $content ) ) {
			throw new Util_WpFile_FilesystemWriteException(
				'FTP credentials don\'t allow to write to file <strong>' .
				$filename . '</strong>', self::get_filesystem_credentials_form(),
				$filename, $content );
		}
	}

	/**
	 * Copy file using WordPress filesystem functions.
	 *
	 * @param unknown $source_filename
	 * @param unknown $destination_filename
	 * @param string  $method               Which method to use when creating
	 * @param string  $url                  Where to redirect after creation
	 * @param bool|string $context              folder to copy files too
	 * @throws Util_WpFile_FilesystemCopyException
	 */
	static public function copy_file( $source_filename, $destination_filename ) {
		$contents = @file_get_contents( $source_filename );
		if ( $contents ) {
			@file_put_contents( $destination_filename, $contents );
		}
		if ( @file_exists( $destination_filename ) ) {
			if ( @file_get_contents( $destination_filename ) == $contents )
				return;
		}

		try {
			self::request_filesystem_credentials();
		} catch ( Util_WpFile_FilesystemOperationException $ex ) {
			throw new Util_WpFile_FilesystemCopyException( $ex->getMessage(),
				$ex->credentials_form(),
				$source_filename, $destination_filename );
		}

		global $wp_filesystem;
		if ( !$wp_filesystem->put_contents( $destination_filename, $contents,
				FS_CHMOD_FILE ) ) {
			throw new Util_WpFile_FilesystemCopyException(
				'FTP credentials don\'t allow to copy to file <strong>' .
				$destination_filename . '</strong>',
				self::get_filesystem_credentials_form(),
				$source_filename, $destination_filename );
		}
	}

	/**
	 *
	 *
	 * @param unknown $folder
	 * @param string  $method  Which method to use when creating
	 * @param string  $url     Where to redirect after creation
	 * @param bool|string $context folder to create folder in
	 * @throws Util_WpFile_FilesystemMkdirException
	 */
	static private function create_folder( $folder, $from_folder ) {
		if ( @is_dir( $folder ) )
			return;

		if ( Util_File::mkdir_from_safe( $folder, $from_folder ) )
			return;

		try {
			self::request_filesystem_credentials();
		} catch ( Util_WpFile_FilesystemOperationException $ex ) {
			throw new Util_WpFile_FilesystemMkdirException( $ex->getMessage(),
				$ex->credentials_form(), $folder );
		}

		global $wp_filesystem;
		if ( !$wp_filesystem->mkdir( $folder, FS_CHMOD_DIR ) ) {
			throw new Util_WpFile_FilesystemMkdirException(
				'FTP credentials don\'t allow to create folder <strong>' .
				$folder . '</strong>',
				self::get_filesystem_credentials_form(),
				$folder );
		}
	}

	/**
	 *
	 *
	 * @param unknown $folder
	 * @param string  $method  Which method to use when creating
	 * @param string  $url     Where to redirect after creation
	 * @param bool|string $context folder to create folder in
	 * @throws Util_WpFile_FilesystemOperationException with S/FTP form if it can't get the required filesystem credentials
	 * @throws FileOperationException
	 */
	static public function create_writeable_folder( $folder, $from_folder ) {
		self::create_folder( $folder, $from_folder );

		$permissions = array( 0755, 0775, 0777 );

		for ( $set_index = 0; $set_index < count( $permissions ); $set_index++ ) {
			if ( is_writable( $folder ) )
				break;

			self::chmod( $folder, $permissions[$set_index] );
		}
	}

	/**
	 *
	 *
	 * @param unknown $folder
	 * @param string  $method  Which method to use when creating
	 * @param string  $url     Where to redirect after creation
	 * @param bool|string $context path folder where delete folders resides
	 * @throws Util_WpFile_FilesystemRmdirException
	 */
	static public function delete_folder( $folder ) {
		if ( !@is_dir( $folder ) )
			return;

		Util_File::rmdir( $folder );
		if ( !@is_dir( $folder ) )
			return;

		try {
			self::request_filesystem_credentials();
		} catch ( Util_WpFile_FilesystemOperationException $ex ) {
			throw new Util_WpFile_FilesystemRmdirException( $ex->getMessage(),
				$ex->credentials_form(), $folder );
		}

		global $wp_filesystem;
		if ( !$wp_filesystem->rmdir( $folder ) ) {
			throw new Util_WpFile_FilesystemRmdirException(
				__( 'FTP credentials don\'t allow to delete folder ', 'w3-total-cache' ) .
				'<strong>' . $folder . '</strong>',
				self::get_filesystem_credentials_form(),
				$folder );
		}
	}

	/**
	 *
	 *
	 * @param string  $filename
	 * @param int     $permission
	 * @return void
	 * @throws Util_WpFile_FilesystemChmodException
	 */
	static private function chmod( $filename, $permission ) {
		if ( @chmod( $filename, $permission ) )
			return;


		try {
			self::request_filesystem_credentials();
		} catch ( Util_WpFile_FilesystemOperationException $ex ) {
			throw new Util_WpFile_FilesystemChmodException( $ex->getMessage(),
				$ex->credentials_form(), $filename, $permission );
		}

		global $wp_filesystem;
		if ( !$wp_filesystem->chmod( $filename, $permission, true ) ) {
			throw new Util_WpFile_FilesystemChmodException(
				__( 'FTP credentials don\'t allow to chmod ', 'w3-total-cache' ) .
				'<strong>' . $filename . '</strong>',
				self::get_filesystem_credentials_form(),
				$filename, $permission );
		}

		return true;
	}

	/**
	 *
	 *
	 * @param unknown $file
	 * @param string  $method
	 * @param string  $url
	 * @param bool|string $context folder where file to be deleted resides
	 * @throws Util_WpFile_FilesystemOperationException with S/FTP form if it can't get the required filesystem credentials
	 */
	static public function delete_file( $filename ) {
		if ( !@file_exists( $filename ) )
			return;
		if ( @unlink( $filename ) )
			return;

		try {
			self::request_filesystem_credentials();
		} catch ( Util_WpFile_FilesystemOperationException $ex ) {
			throw new Util_WpFile_FilesystemRmException( $ex->getMessage(),
				$ex->credentials_form(), $filename );
		}

		global $wp_filesystem;
		if ( !$wp_filesystem->delete( $filename ) ) {
			throw new Util_WpFile_FilesystemRmException(
				__( 'FTP credentials don\'t allow to delete ', 'w3-total-cache' ) .
				'<strong>' . $filename . '</strong>',
				self::get_filesystem_credentials_form(),
				$filename );
		}
	}

	/**
	 * Get WordPress filesystems credentials. Required for WP filesystem usage.
	 *
	 * @param string  $method  Which method to use when creating
	 * @param string  $url     Where to redirect after creation
	 * @param bool|string $context path to folder that should be have filesystem credentials.
	 * If false WP_CONTENT_DIR is assumed
	 * @throws Util_WpFile_FilesystemOperationException with S/FTP form if it can't get the required filesystem credentials
	 */
	private static function request_filesystem_credentials( $method = '', $url = '', $context = false ) {
		if ( strlen( $url ) <= 0 ) {
			$url = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		}

		$url = preg_replace( '/&w3tc_note=([^&]+)/', '', $url );

		// Ensure request_filesystem_credentials() is available.
		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/template.php';

		$success = true;
		ob_start();
		if ( false === ( $creds = request_filesystem_credentials( $url, $method, false, $context, array() ) ) ) {
			$success =  false;
		}
		$form = ob_get_contents();
		ob_end_clean();

		ob_start();
		// If first check failed try again and show error message
		if ( !WP_Filesystem( $creds ) && $success ) {
			request_filesystem_credentials( $url, $method, true, false, array() );
			$success =  false;
			$form = ob_get_contents();
		}
		ob_end_clean();

		$error = '';
		if ( preg_match( "/<div([^c]+)class=\"error\">(.+)<\/div>/", $form, $matches ) ) {
			$error = $matches[2];
			$form = str_replace( $matches[0], '', $form );
		}

		if ( !$success ) {
			throw new Util_WpFile_FilesystemOperationException( $error, $form );
		}
	}

	/**
	 *
	 *
	 * @param string  $method
	 * @param string  $url
	 * @param bool|string $context
	 * @return Util_WpFile_FilesystemOperationException with S/FTP form
	 */
	static private function get_filesystem_credentials_form( $method = '', $url = '',
		$context = false ) {
		// Ensure request_filesystem_credentials() is available.
		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/template.php';

		ob_start();
		// If first check failed try again and show error message
		request_filesystem_credentials( $url, $method, true, false, array() );
		$success =  false;
		$form = ob_get_contents();

		ob_end_clean();

		$error = '';
		if ( preg_match( "/<div([^c]+)class=\"error\">(.+)<\/div>/", $form, $matches ) ) {
			$form = str_replace( $matches[0], '', $form );
		}

		$form = str_replace( '<input ', '<input class="w3tc-ignore-change" ', $form );

		return $form;
	}
}
