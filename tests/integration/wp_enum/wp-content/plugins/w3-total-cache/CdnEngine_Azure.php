<?php
namespace W3TC;

/**
 * Windows Azure Storage CDN engine
 */
class CdnEngine_Azure extends CdnEngine_Base {
	/**
	 * Storage client object
	 *
	 * @var Microsoft_WindowsAzure_Storage_Blob
	 */
	var $_client = null;

	/**
	 * PHP5 Constructor
	 *
	 * @param array   $config
	 */
	function __construct( $config = array() ) {
		$config = array_merge( array(
				'user' => '',
				'key' => '',
				'container' => '',
				'cname' => array(),
			), $config );

		parent::__construct( $config );

		require_once W3TC_LIB_DIR . DIRECTORY_SEPARATOR . 'Azure' .
			DIRECTORY_SEPARATOR . 'loader.php';
	}

	/**
	 * Inits storage client object
	 *
	 * @param string  $error
	 * @return boolean
	 */
	function _init( &$error ) {
		if ( empty( $this->_config['user'] ) ) {
			$error = 'Empty account name.';
			return false;
		}

		if ( empty( $this->_config['key'] ) ) {
			$error = 'Empty account key.';

			return false;
		}

		if ( empty( $this->_config['container'] ) ) {
			$error = 'Empty container name.';

			return false;
		}

		try {
			$connectionString = 'DefaultEndpointsProtocol=https;AccountName=' .
			$this->_config['user'] .
			';AccountKey=' . $this->_config['key'];

			$this->_client = \MicrosoftAzure\Storage\Common\ServicesBuilder::getInstance()->createBlobService(
				$connectionString);
		} catch ( \Exception $ex ) {
			$error = $ex->getMessage();
			return false;
		}


		return true;
	}

	/**
	 * Uploads files to S3
	 *
	 * @param array   $files
	 * @param array   $results
	 * @param boolean $force_rewrite
	 * @return boolean
	 */
	function upload( $files, &$results, $force_rewrite = false,
		$timeout_time = NULL ) {
		$error = null;

		if ( !$this->_init( $error ) ) {
			$results = $this->_get_results( $files, W3TC_CDN_RESULT_HALT, $error );

			return false;
		}

		foreach ( $files as $file ) {
			$remote_path = $file['remote_path'];
			$local_path = $file['local_path'];

			// process at least one item before timeout so that progress goes on
			if ( !empty( $results ) ) {
				if ( !is_null( $timeout_time ) && time() > $timeout_time ) {
					return 'timeout';
				}
			}

			$results[] = $this->_upload( $file, $force_rewrite );
		}

		return !$this->_is_error( $results );
	}

	/**
	 * Uploads file
	 *
	 * @param string  $local_path
	 * @param string  $remote_path
	 * @param bool    $force_rewrite
	 * @return array
	 */
	function _upload( $file, $force_rewrite = false ) {
		$local_path = $file['local_path'];
		$remote_path = $file['remote_path'];

		if ( !file_exists( $local_path ) ) {
			return $this->_get_result( $local_path, $remote_path,
				W3TC_CDN_RESULT_ERROR, 'Source file not found.', $file );
		}

		$contents = @file_get_contents( $local_path );
		$md5 = md5( $contents );   // @md5_file( $local_path );
		$content_md5 = $this->_get_content_md5( $md5 );

		if ( !$force_rewrite ) {
			try {
				$propertiesResult = $this->_client->getBlobProperties( $this->_config['container'], $remote_path );
				$p = $propertiesResult->getProperties();

				$local_size = @filesize( $local_path );

				if ( $local_size == $p->getContentLength() && $content_md5 === $p->getContentMD5() ) {
					return $this->_get_result( $local_path, $remote_path,
						W3TC_CDN_RESULT_OK, 'File up-to-date.', $file );
				}
			} catch ( \Exception $exception ) {
			}
		}

		$headers = $this->get_headers_for_file( $file );

		try {
			// $headers
			$options = new \MicrosoftAzure\Storage\Blob\Models\CreateBlobOptions();
			$options->setBlobContentMD5( $content_md5 );
			if ( isset( $headers['Content-Type'] ) )
				$options->setBlobContentType( $headers['Content-Type'] );
			if ( isset( $headers['Cache-Control'] ) )
				$options->setBlobCacheControl( $headers['Cache-Control'] );

			$this->_client->createBlockBlob( $this->_config['container'],
				$remote_path, $contents, $options );
		} catch ( \Exception $exception ) {
			return $this->_get_result( $local_path, $remote_path,
				W3TC_CDN_RESULT_ERROR,
				sprintf( 'Unable to put blob (%s).', $exception->getMessage() ),
				$file );
		}

		return $this->_get_result( $local_path, $remote_path, W3TC_CDN_RESULT_OK,
			'OK', $file );
	}

	/**
	 * Deletes files from storage
	 *
	 * @param array   $files
	 * @param array   $results
	 * @return boolean
	 */
	function delete( $files, &$results ) {
		$error = null;

		if ( !$this->_init( $error ) ) {
			$results = $this->_get_results( $files, W3TC_CDN_RESULT_HALT, $error );

			return false;
		}

		foreach ( $files as $file ) {
			$local_path = $file['local_path'];
			$remote_path = $file['remote_path'];

			try {
				$r = $this->_client->deleteBlob( $this->_config['container'], $remote_path );
				$results[] = $this->_get_result( $local_path, $remote_path,
					W3TC_CDN_RESULT_OK, 'OK', $file );
			} catch ( \Exception $exception ) {
				$results[] = $this->_get_result( $local_path, $remote_path,
					W3TC_CDN_RESULT_ERROR,
					sprintf( 'Unable to delete blob (%s).', $exception->getMessage() ),
					$file );
			}
		}

		return !$this->_is_error( $results );
	}

	/**
	 * Tests S3
	 *
	 * @param string  $error
	 * @return boolean
	 */
	function test( &$error ) {
		if ( !parent::test( $error ) ) {
			return false;
		}

		$string = 'test_azure_' . md5( time() );

		if ( !$this->_init( $error ) ) {
			return false;
		}

		try {
			$containers = $this->_client->listContainers();
		} catch ( \Exception $exception ) {
			$error = sprintf( 'Unable to list containers (%s).', $exception->getMessage() );

			return false;
		}

		$container = null;

		foreach ( $containers->getContainers() as $_container ) {
			if ( $_container->getName() == $this->_config['container'] ) {
				$container = $_container;
				break;
			}
		}

		if ( !$container ) {
			$error = sprintf( 'Container doesn\'t exist: %s.', $this->_config['container'] );

			return false;
		}

		try {
			$this->_client->createBlockBlob( $this->_config['container'], $string, $string );
		} catch ( \Exception $exception ) {
			$error = sprintf( 'Unable to create blob (%s).', $exception->getMessage() );
			return false;
		}

		try {
			$propertiesResult = $this->_client->getBlobProperties( $this->_config['container'], $string );
			$p = $propertiesResult->getProperties();
			$size = $p->getContentLength();
			$md5 = $p->getContentMD5();
		} catch ( \Exception $exception ) {
			$error = sprintf( 'Unable to get blob properties (%s).', $exception->getMessage() );
			return false;
		}

		if ( $size != strlen( $string ) || $this->_get_content_md5( md5( $string ) ) != $md5 ) {
			try {
				$this->_client->deleteBlob( $this->_config['container'], $string );
			} catch ( \Exception $exception ) {
			}

			$error = 'Blob data properties are not equal.';
			return false;
		}

		try {
			$getBlob = $this->_client->getBlob( $this->_config['container'], $string );
			$dataStream = $getBlob->getContentStream();
			$data = stream_get_contents( $dataStream );
		} catch ( \Exception $exception ) {
			$error = sprintf( 'Unable to get blob data (%s).', $exception->getMessage() );
			return false;
		}


		if ( $data != $string ) {
			try {
				$this->_client->deleteBlob( $this->_config['container'], $string );
			} catch ( \Exception $exception ) {
			}

			$error = 'Blob datas are not equal.';
			return false;
		}

		try {
			$this->_client->deleteBlob( $this->_config['container'], $string );
		} catch ( \Exception $exception ) {
			$error = sprintf( 'Unable to delete blob (%s).', $exception->getMessage() );

			return false;
		}

		return true;
	}

	/**
	 * Returns CDN domain
	 *
	 * @return array
	 */
	function get_domains() {
		if ( !empty( $this->_config['cname'] ) ) {
			return (array) $this->_config['cname'];
		} elseif ( !empty( $this->_config['user'] ) ) {
			$domain = sprintf( '%s.blob.core.windows.net', $this->_config['user'] );

			return array(
				$domain
			);
		}

		return array();
	}

	/**
	 * Returns via string
	 *
	 * @return string
	 */
	function get_via() {
		return sprintf( 'Windows Azure Storage: %s', parent::get_via() );
	}

	/**
	 * Creates bucket
	 *
	 * @param string  $error
	 * @return boolean
	 */
	function create_container() {
		if ( !$this->_init( $error ) ) {
			throw new \Exception( $error );
		}

		try {
			$containers = $this->_client->listContainers();
		} catch ( \Exception $exception ) {
			$error = sprintf( 'Unable to list containers (%s).', $exception->getMessage() );
			throw new \Exception( $error );
		}

		if ( in_array( $this->_config['container'], (array) $containers ) ) {
			$error = sprintf( 'Container already exists: %s.', $this->_config['container'] );
			throw new \Exception( $error );
		}

		try {
			$createContainerOptions = new \MicrosoftAzure\Storage\Blob\Models\CreateContainerOptions();
			$createContainerOptions->setPublicAccess(
				\MicrosoftAzure\Storage\Blob\Models\PublicAccessType::CONTAINER_AND_BLOBS );

			$this->_client->createContainer( $this->_config['container'], $createContainerOptions );
		} catch ( \Exception $exception ) {
			$error = sprintf( 'Unable to create container: %s (%s)', $this->_config['container'], $exception->getMessage() );
			throw new \Exception( $error );
		}
	}

	/**
	 * Returns Content-MD5 header value
	 *
	 * @param string  $string
	 * @return string
	 */
	function _get_content_md5( $md5 ) {
		return base64_encode( pack( 'H*', $md5 ) );
	}

	/**
	 * Formats object URL
	 *
	 * @param string  $path
	 * @return string
	 */
	function _format_url( $path ) {
		$domain = $this->get_domain( $path );

		if ( $domain && !empty( $this->_config['container'] ) ) {
			$scheme = $this->_get_scheme();
			$url = sprintf( '%s://%s/%s/%s', $scheme, $domain, $this->_config['container'], $path );

			return $url;
		}

		return false;
	}

	/**
	 * How and if headers should be set
	 *
	 * @return string W3TC_CDN_HEADER_NONE, W3TC_CDN_HEADER_UPLOADABLE, W3TC_CDN_HEADER_MIRRORING
	 */
	function headers_support() {
		return W3TC_CDN_HEADER_UPLOADABLE;
	}

	function get_prepend_path( $path ) {
		$path = parent::get_prepend_path( $path );
		$path = $this->_config['container'] ? trim( $path, '/' ) . '/' . trim( $this->_config['container'], '/' ): $path;
		return $path;
	}
}
