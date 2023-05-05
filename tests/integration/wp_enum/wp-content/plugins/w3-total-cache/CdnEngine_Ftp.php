<?php
namespace W3TC;

/**
 * W3 CDN FTP Class
 */

define( 'W3TC_CDN_FTP_CONNECT_TIMEOUT', 30 );

/**
 * class CdnEngine_Ftp
 */
class CdnEngine_Ftp extends CdnEngine_Base {
	/**
	 * FTP resource
	 *
	 * @var resource
	 */
	var $_ftp = null;

	/**
	 * PHP5 Constructor
	 *
	 * @param array   $config
	 */
	function __construct( $config = array() ) {
		$config = array_merge( array(
			'host' => '',
			'type' => '',
			'user' => '',
			'pass' => '',
			'default_keys' => false,
			'pubkey' => '',
			'privkey' => '',
			'path' => '',
			'pasv' => false,
			'domain' => array(),
			'docroot' => ''
		), $config );

		list( $ip, $port ) = Util_Content::endpoint_to_host_port( $config['host'], 21 );
		$config['host'] = $ip;
		$config['port'] = $port;

		if ( 'sftp' === $config['type'] && $config['default_keys'] ) {
			$home              = isset( $_SERVER['HOME'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HOME'] ) ) : '';
			$config['pubkey']  = $home . '/.ssh/id_rsa.pub';
			$config['privkey'] = $home . '/.ssh/id_rsa';
		}

		parent::__construct( $config );
	}

	/**
	 * Connects to FTP server
	 *
	 * @param string  $error
	 * @return boolean
	 */
	function _connect( &$error ) {
		if ( empty( $this->_config['host'] ) ) {
			$error = 'Empty host.';

			return false;
		}

		$this->_set_error_handler();

		if ( $this->_config['type'] == 'sftp' ) {
			if ( !function_exists( 'ssh2_connect' ) ) {
				$error = sprintf('Missing required php-ssh2 extension.');

				$this->_restore_error_handler();
				$this->_disconnect();

				return false;
			}

			$this->_ftp = @ssh2_connect( $this->_config['host'], (int) $this->_config['port'] );

			return $this->_connect_sftp( $error );
		}

		if ( $this->_config['type'] == 'ftps' )
			$this->_ftp = @ftp_ssl_connect( $this->_config['host'],
				(int) $this->_config['port'], W3TC_CDN_FTP_CONNECT_TIMEOUT );
		else
			$this->_ftp = @ftp_connect( $this->_config['host'],
				(int) $this->_config['port'], W3TC_CDN_FTP_CONNECT_TIMEOUT );

		if ( !$this->_ftp ) {
			$error = sprintf( 'Unable to connect to %s:%d (%s).',
				$this->_config['host'], $this->_config['port'],
				$this->_get_last_error() );

			$this->_restore_error_handler();

			return false;
		}

		if ( !@ftp_login( $this->_ftp, $this->_config['user'], $this->_config['pass'] ) ) {
			$error = sprintf( 'Incorrect login or password (%s).', $this->_get_last_error() );

			$this->_restore_error_handler();
			$this->_disconnect();

			return false;
		}

		if ( !@ftp_pasv( $this->_ftp, $this->_config['pasv'] ) ) {
			$error = sprintf( 'Unable to change mode to passive (%s).', $this->_get_last_error() );

			$this->_restore_error_handler();
			$this->_disconnect();

			return false;
		}

		if ( !empty( $this->_config['path'] ) && !@ftp_chdir( $this->_ftp, $this->_config['path'] ) ) {
			$error = sprintf( 'Unable to change directory to: %s (%s).', $this->_config['path'], $this->_get_last_error() );

			$this->_restore_error_handler();
			$this->_disconnect();

			return false;
		}

		$this->_restore_error_handler();

		return true;
	}

	/**
	 * Connects to SFTP server
	 *
	 * @param string  $error
	 * @return boolean
	 */
	function _connect_sftp( &$error ) {
		if ( is_file( $this->_config['pass'] ) ) {
			if ( !@ssh2_auth_pubkey_file( $this->_ftp, $this->_config['user'], $this->_config['pubkey'], $this->_config['privkey'], $this->_config['pass'] ) ) {
				$error = sprintf('Public key authentication failed (%s).', $this->_get_last_error());

				$this->_restore_error_handler();
				$this->_disconnect();

				return false;
			}
		} else {
			if ( !@ssh2_auth_password( $this->_ftp, $this->_config['user'], $this->_config['pass'] ) ) {
				$error = sprintf('Incorrect login or password (%s).', $this->_get_last_error());

				$this->_restore_error_handler();
				$this->_disconnect();

				return false;
			}
		}

		if ( !empty( $this->_config['path'] ) && !@ssh2_exec( $this->_ftp, 'cd ' . $this->_config['path'] ) ) {
			$error = sprintf( 'Unable to change directory to: %s (%s).', $this->_config['path'], $this->_get_last_error() );

			$this->_restore_error_handler();
			$this->_disconnect();

			return false;
		}

		$this->_restore_error_handler();

		return true;
	}

	/**
	 * Disconnects from FTP server
	 */
	function _disconnect() {
		if ( $this->_config['type'] == 'sftp' ) {
			if ( function_exists( 'ssh2_connect' ) ) {
				@ssh2_exec( $this->_ftp, 'echo "EXITING" && exit;' );
				$this->_ftp = null;
			}
		} else {
			@ftp_close( $this->_ftp );
		}
	}

	/**
	 * Sends MDTM command
	 *
	 * @param string  $remote_file
	 * @param integer $mtime
	 * @return boolean
	 */
	function _mdtm( $remote_file, $mtime ) {
		$command = sprintf( 'MDTM %s %s', date( 'YmdHis', $mtime ), $remote_file );

		return @ftp_raw( $this->_ftp, $command );
	}

	/**
	 * Uploads files to FTP
	 *
	 * @param array   $files
	 * @param array   $results
	 * @param boolean $force_rewrite
	 * @return boolean
	 */
	function upload( $files, &$results, $force_rewrite = false,
					 $timeout_time = NULL ) {
		$error = null;

		if ( !$this->_connect( $error ) ) {
			$results = $this->_get_results( $files, W3TC_CDN_RESULT_HALT, $error );

			return false;
		}

		$this->_set_error_handler();

		if ( $this->_config['type'] == 'sftp' ) {
			return $this->_upload_sftp( $files, $results, $force_rewrite, $timeout_time );
		}

		$home = @ftp_pwd( $this->_ftp );

		if ( $home === false ) {
			$results = $this->_get_results( $files, W3TC_CDN_RESULT_HALT, sprintf( 'Unable to get current directory (%s).', $this->_get_last_error() ) );

			$this->_restore_error_handler();
			$this->_disconnect();

			return false;
		}

		foreach ( $files as $file ) {
			$local_path = $file['local_path'];
			$remote_path = $file['remote_path'];

			// process at least one item before timeout so that progress goes on
			if ( !empty( $results ) ) {
				if ( !is_null( $timeout_time ) && time() > $timeout_time ) {
					return 'timeout';
				}
			}

			if ( !file_exists( $local_path ) ) {
				$results[] = $this->_get_result( $local_path, $remote_path,
					W3TC_CDN_RESULT_ERROR, 'Source file not found.', $file );

				continue;
			}

			@ftp_chdir( $this->_ftp, $home );

			$remote_dir = dirname( $remote_path );
			$remote_dirs = preg_split( '~\\/+~', $remote_dir );

			foreach ( $remote_dirs as $dir ) {
				if ( !@ftp_chdir( $this->_ftp, $dir ) ) {
					if ( !@ftp_mkdir( $this->_ftp, $dir ) ) {
						$results[] = $this->_get_result( $local_path,
							$remote_path, W3TC_CDN_RESULT_ERROR,
							sprintf( 'Unable to create directory (%s).',
								$this->_get_last_error() ),
							$file );

						continue 2;
					}

					if ( !@ftp_chdir( $this->_ftp, $dir ) ) {
						$results[] = $this->_get_result( $local_path,
							$remote_path, W3TC_CDN_RESULT_ERROR,
							sprintf( 'Unable to change directory (%s).',
								$this->_get_last_error() ),
							$file );

						continue 2;
					}
				}
			}

			// basename cannot be used, kills chinese chars and similar characters
			$remote_file = substr( $remote_path, strrpos( $remote_path, '/' )+1 );

			$mtime = @filemtime( $local_path );

			if ( !$force_rewrite ) {
				$size = @filesize( $local_path );
				$ftp_size = @ftp_size( $this->_ftp, $remote_file );
				$ftp_mtime = @ftp_mdtm( $this->_ftp, $remote_file );

				if ( $size === $ftp_size && $mtime === $ftp_mtime ) {
					$results[] = $this->_get_result( $local_path, $remote_path,
						W3TC_CDN_RESULT_OK, 'File up-to-date.', $file );

					continue;
				}
			}

			$result = @ftp_put( $this->_ftp, $remote_file, $local_path, FTP_BINARY );

			if ( $result ) {
				$this->_mdtm( $remote_file, $mtime );

				$results[] = $this->_get_result( $local_path, $remote_path,
					W3TC_CDN_RESULT_OK, 'OK', $file );
			} else {
				$results[] = $this->_get_result( $local_path, $remote_path,
					W3TC_CDN_RESULT_ERROR,
					sprintf( 'Unable to upload file (%s).',
						$this->_get_last_error() ),
					$file );
			}
		}

		$this->_restore_error_handler();
		$this->_disconnect();

		return !$this->_is_error( $results );
	}

	/**
	 * Uploads files to SFTP
	 *
	 * @param array   $files
	 * @param array   $results
	 * @param boolean $force_rewrite
	 * @return boolean
	 */
	function _upload_sftp( $files, $results, $force_rewrite, $timeout_time ) {
		$sftp = ssh2_sftp( $this->_ftp );

		foreach ( $files as $file ) {
			$local_path = $file['local_path'];
			$remote_path = $file['remote_path'];

			// process at least one item before timeout so that progress goes on
			if ( !empty( $results ) ) {
				if ( !is_null( $timeout_time ) && time() > $timeout_time ) {
					return 'timeout';
				}
			}

			if ( !file_exists( $local_path ) ) {
				$results[] = $this->_get_result( $local_path, $remote_path,
					W3TC_CDN_RESULT_ERROR, 'Source file not found.', $file );

				continue;
			}

			$remote_dir = dirname( $remote_path );

			if ( !@file_exists( 'ssh2.sftp://' . intval($sftp) . $remote_dir ) ) {
				if ( !@ssh2_sftp_mkdir( $sftp, $remote_dir, null, true ) ) {
					$results[] = $this->_get_result( $local_path,
						$remote_path, W3TC_CDN_RESULT_ERROR,
						sprintf( 'Unable to create directory (%s).',
							$this->_get_last_error() ),
						$file );

					continue;
				}
			}

			$mtime = @filemtime( $local_path );

			if ( !$force_rewrite ) {
				$size = @filesize( $local_path );
				$statinfo = @ssh2_sftp_stat( $sftp, $remote_path );

				if ( $size === $statinfo['size'] && $mtime === $statinfo['mtime'] ) {
					$results[] = $this->_get_result( $local_path, $remote_path,
						W3TC_CDN_RESULT_OK, 'File up-to-date.', $file );

					continue;
				}
			}

			$result = @ssh2_scp_send( $this->_ftp, $local_path, $remote_path );

			if ( $result ) {
				$results[] = $this->_get_result( $local_path, $remote_path,
					W3TC_CDN_RESULT_OK, 'OK', $file );
			} else {
				$results[] = $this->_get_result( $local_path, $remote_path,
					W3TC_CDN_RESULT_ERROR,
					sprintf( 'Unable to upload file (%s).',
						$this->_get_last_error() ),
					$file );
			}
		}

		$this->_restore_error_handler();
		$this->_disconnect();

		return !$this->_is_error( $results );
	}

	/**
	 * Deletes files from FTP
	 *
	 * @param array   $files
	 * @param array   $results
	 * @return boolean
	 */
	function delete( $files, &$results ) {
		$error = null;

		if ( !$this->_connect( $error ) ) {
			$results = $this->_get_results( $files, W3TC_CDN_RESULT_HALT, $error );

			return false;
		}

		$this->_set_error_handler();

		foreach ( $files as $file ) {
			$local_path = $file['local_path'];
			$remote_path = $file['remote_path'];

			if ( $this->_config['type'] == 'sftp' ) {
				$sftp = @ssh2_sftp( $this->_ftp );
				$result = @ssh2_sftp_unlink( $sftp, $remote_path );
			} else {
				$result = @ftp_delete( $this->_ftp, $remote_path );
			}

			if ( $result ) {
				$results[] = $this->_get_result( $local_path, $remote_path,
					W3TC_CDN_RESULT_OK, 'OK', $file );
			} else {
				$results[] = $this->_get_result( $local_path, $remote_path,
					W3TC_CDN_RESULT_ERROR,
					sprintf( 'Unable to delete file (%s).',
						$this->_get_last_error() ),
					$file );
			}

			while ( true ) {
				$remote_path = dirname( $remote_path );

				if ( $remote_path == '.' ) {
					break;
				}

				if ( $this->_config['type'] == 'sftp' && !@ssh2_sftp_rmdir( $sftp, $remote_path ) ) {
					break;
				} else if ( !@ftp_rmdir( $this->_ftp, $remote_path ) ) {
					break;
				}
			}
		}

		$this->_restore_error_handler();
		$this->_disconnect();

		return !$this->_is_error( $results );
	}

	/**
	 * Tests FTP server
	 *
	 * @param string  $error
	 * @return boolean
	 */
	function test( &$error ) {
		if ( !parent::test( $error ) ) {
			return false;
		}

		if ( $this->_config['type'] == 'sftp' ) {
			return $this->_test_sftp( $error );
		}

		$rand = md5( time() );
		$tmp_dir = 'test_dir_' . $rand;
		$tmp_file = 'test_file_' . $rand;
		$tmp_path = W3TC_CACHE_TMP_DIR . '/' . $tmp_file;

		if ( !@file_put_contents( $tmp_path, $rand ) ) {
			$error = sprintf( 'Unable to create file: %s.', $tmp_path );

			return false;
		}

		if ( !$this->_connect( $error ) ) {
			return false;
		}

		$this->_set_error_handler();

		if ( !@ftp_mkdir( $this->_ftp, $tmp_dir ) ) {
			$error = sprintf( 'Unable to make directory: %s (%s).', $tmp_dir, $this->_get_last_error() );

			@unlink( $tmp_path );

			$this->_restore_error_handler();
			$this->_disconnect();

			return false;
		}

		if ( file_exists( $this->_config['docroot'] . '/' . $tmp_dir ) ) {
			$error = sprintf( 'Test directory was made in your site root, not on separate FTP host or path. Change path or FTP information: %s.', $tmp_dir );

			@unlink( $tmp_path );
			@ftp_rmdir( $this->_ftp, $tmp_dir );

			$this->_restore_error_handler();
			$this->_disconnect();

			return false;
		}

		if ( !@ftp_chdir( $this->_ftp, $tmp_dir ) ) {
			$error = sprintf( 'Unable to change directory to: %s (%s).', $tmp_dir, $this->_get_last_error() );

			@unlink( $tmp_path );
			@ftp_rmdir( $this->_ftp, $tmp_dir );

			$this->_restore_error_handler();
			$this->_disconnect();

			return false;
		}

		if ( !@ftp_put( $this->_ftp, $tmp_file, $tmp_path, FTP_BINARY ) ) {
			$error = sprintf( 'Unable to upload file: %s (%s).', $tmp_path, $this->_get_last_error() );

			@unlink( $tmp_path );
			@ftp_cdup( $this->_ftp );
			@ftp_rmdir( $this->_ftp, $tmp_dir );

			$this->_restore_error_handler();
			$this->_disconnect();

			return false;
		}

		@unlink( $tmp_path );

		if ( !@ftp_delete( $this->_ftp, $tmp_file ) ) {
			$error = sprintf( 'Unable to delete file: %s (%s).', $tmp_path, $this->_get_last_error() );

			@ftp_cdup( $this->_ftp );
			@ftp_rmdir( $this->_ftp, $tmp_dir );

			$this->_restore_error_handler();
			$this->_disconnect();

			return false;
		}

		@ftp_cdup( $this->_ftp );

		if ( !@ftp_rmdir( $this->_ftp, $tmp_dir ) ) {
			$error = sprintf( 'Unable to remove directory: %s (%s).', $tmp_dir, $this->_get_last_error() );

			$this->_restore_error_handler();
			$this->_disconnect();

			return false;
		}

		$this->_restore_error_handler();
		$this->_disconnect();

		return true;
	}

	/**
	 * Tests FTP server
	 *
	 * @param string  $error
	 * @return boolean
	 */
	function _test_sftp( &$error ) {

		$rand = md5( time() );
		$tmp_dir = 'test_dir_' . $rand;
		$tmp_file = 'test_file_' . $rand;
		$local_path = W3TC_CACHE_TMP_DIR . '/' . $tmp_file;
		$remote_path = $tmp_dir . '/' . $tmp_file;

		if ( !@file_put_contents( $local_path, $rand ) ) {
			$error = sprintf( 'Unable to create file: %s.', $local_path );

			return false;
		}

		if ( !$this->_connect( $error ) ) {
			return false;
		}

		$sftp = @ssh2_sftp( $this->_ftp );

		$this->_set_error_handler();

		if ( !@ssh2_sftp_mkdir( $sftp, $tmp_dir ) ) {
			$error = sprintf( 'Unable to make directory: %s (%s).', $tmp_dir, $this->_get_last_error() );

			@unlink( $local_path );

			$this->_restore_error_handler();
			$this->_disconnect();

			return false;
		}

		if ( file_exists( $this->_config['docroot'] . '/' . $tmp_dir ) ) {
			$error = sprintf( 'Test directory was made in your site root, not on separate FTP host or path. Change path or FTP information: %s.', $tmp_dir );

			@unlink( $local_path );
			@ssh2_sftp_rmdir( $sftp, $tmp_dir );

			$this->_restore_error_handler();
			$this->_disconnect();

			return false;
		}

		if ( !@ssh2_scp_send( $this->_ftp, $local_path, $remote_path ) ) {
			$error = sprintf( 'Unable to upload file: %s (%s).', $local_path, $this->_get_last_error() );

			@unlink( $local_path );
			@ssh2_sftp_rmdir( $sftp, $tmp_dir );

			$this->_restore_error_handler();
			$this->_disconnect();

			return false;
		}

		@unlink( $local_path );

		if ( !@ssh2_sftp_unlink( $sftp, $remote_path ) ) {
			$error = sprintf( 'Unable to delete file: %s (%s).', $local_path, $this->_get_last_error() );

			@ssh2_sftp_rmdir( $sftp, $tmp_dir );

			$this->_restore_error_handler();
			$this->_disconnect();

			return false;
		}

		if ( !@ssh2_sftp_rmdir( $sftp, $tmp_dir ) ) {
			$error = sprintf( 'Unable to remove directory: %s (%s).', $tmp_dir, $this->_get_last_error() );

			$this->_restore_error_handler();
			$this->_disconnect();

			return false;
		}

		$this->_restore_error_handler();
		$this->_disconnect();

		return true;
	}

	/**
	 * Returns array of CDN domains
	 *
	 * @return array
	 */
	function get_domains() {
		if ( !empty( $this->_config['domain'] ) ) {
			return (array) $this->_config['domain'];
		}

		return array();
	}

	/**
	 * How and if headers should be set
	 *
	 * @return string W3TC_CDN_HEADER_NONE, W3TC_CDN_HEADER_UPLOADABLE, W3TC_CDN_HEADER_MIRRORING
	 */
	function headers_support() {
		return W3TC_CDN_HEADER_MIRRORING;
	}
}
