<?php
namespace W3TC;

/**
 * Google drive engine
 */
class CdnEngine_GoogleDrive extends CdnEngine_Base {
	private $_client_id;
	private $_refresh_token;
	private $_root_folder_id;
	private $_root_url;

	private $_service;
	private $_tablename_pathmap;



	/**
	 * PHP5 Constructor
	 *
	 * @param array   $config
	 */
	function __construct( $config = array() ) {
		parent::__construct( $config );

		$this->_client_id = $config['client_id'];
		$this->_refresh_token = $config['refresh_token'];
		$this->_root_folder_id = $config['root_folder_id'];
		$this->_root_url = rtrim( $config['root_url'], '/' ) . '/';
		$this->_new_access_token_callback = $config['new_access_token_callback'];

		global $wpdb;
		$this->_tablename_pathmap = $wpdb->base_prefix . W3TC_CDN_TABLE_PATHMAP;

		try {
		$this->_init_service( $config['access_token'] );
		} catch ( \Exception $e ) {
			$this->_service = null;
		}
	}



	private function _init_service( $access_token ) {
		if ( empty( $this->_client_id ) || empty( $access_token ) )
			throw new \Exception('service not configured');

		$client = new \W3TCG_Google_Client();
		$client->setClientId( $this->_client_id );
		$client->setAccessToken( $access_token );
		$this->_service = new \W3TCG_Google_Service_Drive( $client );
	}



	private function _refresh_token() {
		$result = wp_remote_post( W3TC_GOOGLE_DRIVE_AUTHORIZE_URL, array(
				'body' => array(
					'client_id' => $this->_client_id,
					'refresh_token' => $this->_refresh_token
				) ) );

		if ( is_wp_error( $result ) )
			throw new \Exception( $result );
		elseif ( $result['response']['code'] != '200' )
			throw new \Exception( $result['body'] );

		$access_token = $result['body'];
		call_user_func( $this->_new_access_token_callback, $access_token );
		$this->_init_service( $access_token );
	}



	/**
	 * Uploads files
	 *
	 * @param array   $files
	 * @param array   $results
	 * @param boolean $force_rewrite
	 * @return boolean
	 */
	function upload( $files, &$results, $force_rewrite = false, $timeout_time = NULL ) {
		if ( is_null( $this->_service ) )
			return false;

		$allow_refresh_token = true;
		$result = true;

		$files_chunks = array_chunk( $files , 20 );
		foreach ( $files_chunks as $files_chunk ) {
			$r = $this->_upload_chunk( $files_chunk, $results,
				$force_rewrite, $timeout_time, $allow_refresh_token );
			if ( $r == 'refresh_required' ) {
				$allow_refresh_token = false;
				$this->_refresh_token();

				$r = $this->_upload_chunk( $files_chunk, $results,
					$force_rewrite, $timeout_time, $allow_refresh_token );
			}
			if ( $r != 'success' )
				$result = false;
			if ( $r == 'timeout' ) {
				return 'timeout';
			}

		}

		return $result;
	}



	private function _properties_to_path( $file ) {
		$path_pieces = array();
		foreach ( $file->properties as $p ) {
			$k = ($p->key == 'path') ? 'path1' : $p->key;
			if ( !preg_match( '/^path[0-9]+$/', $k ) )
					continue;
			$path_pieces[$k] = $p->value;
		}
		if ( count( $path_pieces ) == 0 )
			return NULL;
		ksort($path_pieces);
		return join( $path_pieces );
	}



	private function _path_to_properties( $path ) {
		// from google drive api docs:
		// Maximum of 124 bytes size per property
		// (including both key and value) string in UTF-8 encoding.
		// Maximum of 30 private properties per file from any one application.
		$chunks = str_split( $path, 55 );
		$properties = array();
		$i = 1;

		foreach ( $chunks as $chunk ) {
			$p = new \W3TCG_Google_Service_Drive_Property();
			$p->key = 'path' . $i;
			$p->value = $chunk;
			$properties[] = $p;

			$i++;
		}

		return $properties;
	}



	private function _upload_chunk( $files, &$results, $force_rewrite,
		$timeout_time, $allow_refresh_token ) {
		list( $result, $listed_files ) = $this->list_files_chunk( $files,
			$allow_refresh_token, $timeout_time );
		if ( $result != 'success' )
			return $result;

		$files_by_path = array();

		foreach ( $listed_files as $existing_file ) {
			$path = $this->_properties_to_path( $existing_file );
			if ( $path ) {
				$files_by_path[$path] = $existing_file;
			}
		}

		// check update date and upload
		foreach ( $files as $file_descriptor ) {
			$remote_path = $file_descriptor['remote_path'];

			// process at least one item before timeout so that progress goes on
			if ( !empty( $results ) ) {
				if ( !is_null( $timeout_time ) && time() > $timeout_time )
					return 'timeout';
			}

			list( $parent_id, $title ) = $this->remote_path_to_title(
				$file_descriptor['remote_path'] );
			$properties = $this->_path_to_properties( $remote_path );
			if ( isset( $file_descriptor['content'] ) ) {
				// when content specified - just upload
				$content = $file_descriptor['content'];
			} else {
				$local_path = $file_descriptor['local_path'];
				if ( !file_exists( $local_path ) ) {
					$results[] = $this->_get_result( $local_path,
						$remote_path,
						W3TC_CDN_RESULT_ERROR, 'Source file not found.',
						$file_descriptor );
					continue;
				}

				$mtime = @filemtime( $local_path );

				$p = new \W3TCG_Google_Service_Drive_Property();
				$p->key = 'mtime';
				$p->value = $mtime;
				$properties[] = $p;

				if ( !$force_rewrite && isset( $files_by_path[$remote_path] ) ) {
					$existing_file = $files_by_path[$remote_path];
					$existing_size = $existing_file->fileSize;
					$existing_mtime = 0;
					if ( is_array( $existing_file->properties ) ) {
						foreach ( $existing_file->properties as $p ) {
							if ( $p->key == 'mtime' )
								$existing_mtime = $p->value;
						}
					}

					$size = @filesize( $local_path );
					if ( $mtime == $existing_mtime && $size == $existing_size ) {
						$results[] = $this->_get_result( $file_descriptor['local_path'],
							$remote_path, W3TC_CDN_RESULT_OK,
							'File up-to-date.', $file_descriptor );
						continue;
					}
				}

				$content = file_get_contents( $local_path );
			}

			$file = new \W3TCG_Google_Service_Drive_DriveFile();
			$file->setTitle( $title );
			$file->setProperties( $properties );

			$parent = new \W3TCG_Google_Service_Drive_ParentReference();
			$parent->setId( $parent_id );
			$file->setParents( array( $parent ) );

			try {
				try {
					// update file if there's one already or insert
					if ( isset( $files_by_path[$remote_path] ) ) {
						$existing_file = $files_by_path[$remote_path];

						$created_file = $this->_service->files->update(
							$existing_file->id, $file, array(
								'data' => $content,
								'uploadType' => 'media'
							) );
					} else {
						$created_file = $this->_service->files->insert( $file, array(
								'data' => $content,
								'uploadType' => 'media'
							) );

						$permission = new \W3TCG_Google_Service_Drive_Permission();
						$permission->setValue( '' );
						$permission->setType( 'anyone' );
						$permission->setRole( 'reader' );

						$this->_service->permissions->insert( $created_file->id,
							$permission );
					}
				} catch ( \W3TCG_Google_Auth_Exception $e ) {
					if ( $allow_refresh_token )
						return 'refresh_required';

					throw $e;
				}

				$results[] = $this->_get_result( $file_descriptor['local_path'],
					$remote_path, W3TC_CDN_RESULT_OK,
					'OK', $file_descriptor );
				$this->path_set_id( $remote_path, $created_file->id );
			} catch ( \W3TCG_Google_Service_Exception $e ) {
				$errors = $e->getErrors();
				$details = '';
				if ( count( $errors ) >= 1 ) {
					$details = json_encode($errors);
				}

				delete_transient( 'w3tc_cdn_google_drive_folder_ids' );

				$results[] = $this->_get_result( $file_descriptor['local_path'],
					$remote_path, W3TC_CDN_RESULT_ERROR,
					'Failed to upload file ' . $remote_path .
					' ' . $details, $file_descriptor );
				$result = 'with_errors';
				continue;
			} catch ( \Exception $e ) {
				delete_transient( 'w3tc_cdn_google_drive_folder_ids' );

				$results[] = $this->_get_result( $file_descriptor['local_path'],
					$remote_path, W3TC_CDN_RESULT_ERROR,
					'Failed to upload file ' . $remote_path,
					$file_descriptor );
				$result = 'with_errors';
				continue;
			}
		}

		return $result;
	}



	/**
	 * Deletes files
	 *
	 * @param array   $files
	 * @param array   $results
	 * @return boolean
	 */
	function delete( $files, &$results ) {
		$allow_refresh_token = true;
		$result = true;

		$files_chunks = array_chunk( $files , 20 );
		foreach ( $files_chunks as $files_chunk ) {
			$r = $this->_delete_chunk( $files_chunk, $results,
				$allow_refresh_token );
			if ( $r == 'refresh_required' ) {
				$allow_refresh_token = false;
				$this->_refresh_token();

				$r = $this->_delete_chunk( $files_chunk, $results,
					$allow_refresh_token );
			}
			if ( $r != 'success' )
				$result = false;
		}

		return $result;
	}



	private function _delete_chunk( $files, &$results, $allow_refresh_token ) {
		list( $result, $listed_files ) = $this->list_files_chunk( $files,
			$allow_refresh_token );
		if ( $result != 'success' )
			return $result;

		foreach ( $listed_files->items as $item ) {
			try {
				$this->_service->files->delete( $item->id );

				$results[] = $this->_get_result( $item->title,
					$item->title, W3TC_CDN_RESULT_OK,
					'OK' );
			} catch ( \Exception $e ) {
				$results[] = $this->_get_result( '',
					'', W3TC_CDN_RESULT_ERROR,
					'Failed to delete file ' . $item->title );
				$result = 'with_errors';
				continue;
			}

		}

		return $result;
	}




	private function list_files_chunk( $files, $allow_refresh_token,
		$timeout_time = NULL ) {
		$titles_filter = array();

		try {
			foreach ( $files as $file_descriptor ) {
				list( $parent_id, $title ) = $this->remote_path_to_title(
					$file_descriptor['remote_path'] );
				$titles_filter[] = '("' . $parent_id .
					'" in parents and title = "' . $title . '")';
				if ( !is_null( $timeout_time ) && time() > $timeout_time )
					return array( 'timeout', array() );
			}
		} catch ( \W3TCG_Google_Auth_Exception $e ) {
			if ( $allow_refresh_token )
				return array( 'refresh_required', array() );

			throw $e;
		} catch ( \Exception $e ) {
			return array( 'with_errors', array() );
		}


		// find files
		try {
			try {
				$listed_files = $this->_service->files->listFiles(
					array( 'q' => '(' . join( ' or ', $titles_filter ) . ') and trashed = false' )
				);
			} catch ( \W3TCG_Google_Auth_Exception $e ) {
				if ( $allow_refresh_token )
					return array( 'refresh_required', array() );

				throw $e;
			}
		} catch ( \Exception $e ) {
			return array( 'with_errors', array() );
		}

		return array( 'success', $listed_files );
	}



	private function remote_path_to_title( $remote_path ) {
		$title = substr( $remote_path, 1 );
		$pos = strrpos( $remote_path, '/' );
		if ( $pos === false ) {
			$path = '';
			$title = $remote_path;
		} else {
			$path = substr( $remote_path, 0, $pos );
			$title = substr( $remote_path, $pos + 1 );
		}

		$title = str_replace( '"', "'", $title );
		$parent_id = $this->path_to_parent_id( $this->_root_folder_id, $path );

		return array( $parent_id, $title );
	}



	private function path_to_parent_id( $root_id, $path ) {
		if ( empty( $path ) )
			return $root_id;

		$path = ltrim( $path, '/' );
		$pos = strpos( $path, '/' );
		if ( $pos === false ) {
			$top_folder = $path;
			$remaining_path = '';
		} else {
			$top_folder = substr( $path, 0, $pos );
			$remaining_path = substr( $path, $pos + 1 );
		}

		$new_root_id = $this->parent_id_resolve_step( $root_id, $top_folder );
		return $this->path_to_parent_id( $new_root_id, $remaining_path );
	}



	private function parent_id_resolve_step( $root_id, $folder ) {
		// decode top folder
		$ids_string = get_transient( 'w3tc_cdn_google_drive_folder_ids' );
		$ids = @unserialize( $ids_string );

		if ( isset( $ids[$root_id . '_' . $folder] ) )
			return $ids[$root_id . '_' . $folder];

		// find folder
		$items = $this->_service->files->listFiles( array(
				'q' => '"' . $root_id . '" in parents '.
				'and title = "' . $folder . '" ' .
				'and mimeType = "application/vnd.google-apps.folder" ' .
				'and trashed = false'
			) );

		if ( count( $items ) > 0 ) {
			$id = $items[0]->id;
		} else {
			// create folder
			$file = new \W3TCG_Google_Service_Drive_DriveFile( array(
					'title' => $folder,
					'mimeType' => 'application/vnd.google-apps.folder' ) );

			$parent = new \W3TCG_Google_Service_Drive_ParentReference();
			$parent->setId( $root_id );
			$file->setParents( array( $parent ) );

			$created_file = $this->_service->files->insert( $file );
			$id = $created_file->id;

			$permission = new \W3TCG_Google_Service_Drive_Permission();
			$permission->setValue( '' );
			$permission->setType( 'anyone' );
			$permission->setRole( 'reader' );

			$this->_service->permissions->insert( $id, $permission );
		}

		if ( !is_array( $ids ) )
			$ids = array();
		$ids[$root_id . '_' . $folder] = $id;
		set_transient( 'w3tc_cdn_google_drive_folder_ids', serialize( $ids ) );

		return $id;
	}



	/**
	 * Tests
	 *
	 * @param string  $error
	 * @return boolean
	 */
	function test( &$error ) {
		$test_content = '' . rand();

		$file = array(
			'local_path' => 'n/a',
			'remote_path' => '/folder/test.txt',
			'content' => $test_content
		);
		$results = array();

		if ( !$this->upload( array( $file ), $results ) ) {
			$error = sprintf( 'Unable to upload file %s', $file['remote_path'] );
			return false;
		}
		if ( !$this->delete( array( $file ), $results ) ) {
			$error = sprintf( 'Unable to delete file %s', $file['remote_path'] );
			return false;
		}

		return true;
	}



	/**
	 * Returns array of CDN domains
	 *
	 * @return array
	 */
	function get_domains() {
		return array();
	}



	/**
	 * How and if headers should be set
	 *
	 * @return string W3TC_CDN_HEADER_NONE, W3TC_CDN_HEADER_UPLOADABLE, W3TC_CDN_HEADER_MIRRORING
	 */
	function headers_support() {
		return W3TC_CDN_HEADER_NONE;
	}



	function purge_all( &$results ) {
		return false;
	}



	private function path_set_id( $path, $id ) {
		global $wpdb;
		$md5 = md5( $path );
		if ( !$id ) {
			$sql = "
				INSERT INTO $this->_tablename_pathmap (path, path_hash, remote_id)
				VALUES (%s, %s, NULL)
				ON DUPLICATE KEY UPDATE remote_id = NULL";
			$wpdb->query($wpdb->prepare($sql, $path, $md5));
		} else {
			$sql = "
				INSERT INTO $this->_tablename_pathmap (path, path_hash, remote_id)
				VALUES (%s, %s, %s)
				ON DUPLICATE KEY UPDATE remote_id = %s";
			$wpdb->query($wpdb->prepare(
				$sql, $path, $md5, $id, $id));
		}
	}



	private function path_get_id( $path, $allow_refresh_token = true ) {
		global $wpdb;
		$md5 = md5($path);
		$sql = "SELECT remote_id FROM $this->_tablename_pathmap WHERE path_hash = %s";
		$query = $wpdb->prepare( $sql, $md5 );
		$results = $wpdb->get_results( $query );
		if ( count( $results ) > 0 ) {
			return $results[0]->remote_id;
		}
		$props = $this->_path_to_properties( $path );
		$q = 'trashed = false';
		foreach ( $props as $prop ) {
				$key = $prop->key;
				$value = str_replace( "'", "\\'", $prop->value );
				$q .= " and properties has { key='$key' and " .
					  " value='$value' and visibility='PRIVATE' }";
		}

		try {
			$items = $this->_service->files->listFiles(
				array( 'q' => $q ) );
		} catch ( \W3TCG_Google_Auth_Exception $e ) {
			if ( $allow_refresh_token ) {
				$this->_refresh_token();
				return $this->path_get_id( $path, false );
			}

			throw $e;
		}

		$id = ( count( $items ) == 0 ) ? NULL : $items[0]->id;
		$this->path_set_id( $path, $id );

		return $id;
	}



	function format_url( $path, $allow_refresh_token = true ) {
		$id = $this->path_get_id( Util_Environment::remove_query( $path ) );
		if ( is_null( $id ) )
			return NULL;

		return 'https://drive.google.com/uc?id=' . $id;
	}
}
