<?php
/**
 * Tus_Client
 *
 * @package VideoPressUploader
 **/

// phpcs:disable Generic.Commenting.DocComment.MissingShort
// phpcs:disable Squiz.Commenting.VariableComment.Missing
// phpcs:disable Squiz.Commenting.FunctionComment.EmptyThrows
// phpcs:disable Generic.Commenting.DocComment.MissingShort
// phpcs:disable Squiz.Commenting.FunctionComment.MissingParamComment

namespace VideoPressUploader;

use InvalidArgumentException;
use WP_Error;
use WP_Http;

/**
 * Tus_Client
 */
class Tus_Client {

	/** @const string Tus protocol version. */
	const TUS_PROTOCOL_VERSION = '1.0.0';

	/** @const string Upload type partial. */
	const UPLOAD_TYPE_PARTIAL = 'partial';

	/** @const string Upload type final. */
	const UPLOAD_TYPE_FINAL = 'final';

	/** @const string Name separator for partial upload. */
	const PARTIAL_UPLOAD_NAME_SEPARATOR = '_';

	/** @const string Upload type normal. */
	const UPLOAD_TYPE_NORMAL = 'normal';

	/** @const string Header Content Type */
	const HEADER_CONTENT_TYPE = 'application/offset+octet-stream';

	/** @const string Base API Uri */
	const BASE_API_URL = 'https://public-api.wordpress.com/rest/v1.1/video-uploads/%d';

	/** @var Cacheable */
	protected $cache;

	/** @var string */
	protected $file_path;

	/** @var int */
	protected $file_size = 0;

	/** @var string */
	protected $file_name;

	/** @var string */
	protected $key;

	/** @var string */
	protected $url;

	/** @var string */
	protected $checksum;

	/** @var int */
	protected $partial_offset = -1;

	/** @var bool */
	protected $partial = false;

	/** @var string */
	protected $checksum_algorithm = 'sha256';

	/** @var array */
	protected $metadata = array();

	/** @var array */
	protected $headers = array();

	/**
	 * The details of the server response about the uploaded file
	 * VideoPress mod: Create new attribute
	 *
	 * @var array
	 */
	protected $uploaded_video_details = null;

	/**
	 * The API url composed by BASE_API_URL and the Blod ID.
	 *
	 * @var string
	 */
	protected $api_url = null;

	/**
	 * Tus_Client constructor.
	 *
	 * @param string $key The unique upload key identifier.
	 * @param string $upload_token The upload token retrieved from the server.
	 * @param int    $blog_id The current Jetpack Blog ID.
	 *
	 * @throws \ReflectionException
	 * @throws InvalidArgumentException
	 */
	public function __construct( $key, $upload_token, $blog_id ) {

		$this->key = $key;

		$this->headers = array(
			'Tus-Resumable'             => self::TUS_PROTOCOL_VERSION,
			'x-videopress-upload-token' => $upload_token,
		);

		$this->api_url = sprintf( self::BASE_API_URL, (int) $blog_id );

		$this->cache = new Transient_Store( $this->get_key() );
	}

	/**
	 * Get cache.
	 *
	 * @return Cacheable
	 */
	public function get_cache() {
		return $this->cache;
	}

	/**
	 * Gets one attribute from the cache, if it exists.
	 *
	 * @param string $attribute The attribute name.
	 * @return mixed The attribute value if found or null.
	 */
	public function get_cache_attribute( $attribute ) {
		$cache_values = $this->get_cache()->get( $this->get_key() );
		return ! empty( $cache_values[ $attribute ] ) ? $cache_values[ $attribute ] : null;
	}

	/**
	 * Sets the uploaded video details
	 *
	 * @param string $guid The guid of the created video.
	 * @param string $media_id The ID of the attachment created.
	 * @param string $upload_src The video URL.
	 * @return void
	 */
	protected function set_uploaded_video_details( $guid, $media_id, $upload_src ) {
		$this->uploaded_video_details = compact( 'guid', 'media_id', 'upload_src' );
	}

	/**
	 * Gets the details of the uploaded video
	 * VideoPress mod: Create new method
	 *
	 * @return array
	 */
	public function get_uploaded_video_details() {
		return $this->uploaded_video_details;
	}

	/**
	 * Set file properties.
	 *
	 * @param string      $file File path.
	 * @param string|null $name File name.
	 *
	 * @throws InvalidArgumentException
	 * @throws Tus_Exception
	 * @return Tus_Client
	 */
	public function file( $file, $name = null ) {
		if ( ! is_string( $file ) ) {
			throw new InvalidArgumentException( '$file needs to be a string' );
		}
		$this->file_path = $file;

		if ( ! file_exists( $file ) || ! is_readable( $file ) ) {
			throw new Tus_Exception( 'Cannot read file: ' . $file );
		}

		$this->file_name = ! empty( $name ) ? basename( $this->file_path ) : '';
		$this->file_size = filesize( $file );

		$this->add_metadata( 'filename', $this->file_name );

		return $this;
	}

	/**
	 * Get file path.
	 *
	 * @return string|null
	 */
	public function get_file_path() {
		return $this->file_path;
	}

	/**
	 * Set file name.
	 *
	 * @param string $name The file name.
	 *
	 * @throws InvalidArgumentException
	 * @return Tus_Client
	 */
	public function set_file_name( $name ) {
		if ( ! is_string( $name ) ) {
			throw new InvalidArgumentException( '$name needs to be a string' );
		}
		$this->add_metadata( 'filename', $this->file_name = $name );

		return $this;
	}

	/**
	 * Get file name.
	 *
	 * @return string|null
	 */
	public function get_file_name() {
		return $this->file_name;
	}

	/**
	 * Get file size.
	 *
	 * @return int
	 */
	public function get_file_size() {
		return $this->file_size;
	}

	/**
	 * Set checksum.
	 *
	 * @param string $checksum
	 *
	 * @throws InvalidArgumentException
	 * @return Tus_Client
	 */
	public function set_checksum( $checksum ) {
		if ( ! is_string( $checksum ) ) {
			throw new InvalidArgumentException( '$checksum needs to be a string' );
		}
		$this->checksum = $checksum;

		return $this;
	}

	/**
	 * Get checksum.
	 *
	 * @return string
	 */
	public function get_checksum() {
		if ( empty( $this->checksum ) ) {
			$this->set_checksum( hash_file( $this->get_checksum_algorithm(), $this->get_file_path() ) );
		}

		return $this->checksum;
	}

	/**
	 * Add metadata.
	 *
	 * @param string $key
	 * @param string $value
	 *
	 * @throws InvalidArgumentException
	 * @return Tus_Client
	 */
	public function add_metadata( $key, $value ) {
		if ( ! is_string( $key ) || ! is_string( $value ) ) {
			throw new InvalidArgumentException( '$key and $value need to be strings' );
		}
		$this->metadata[ $key ] = base64_encode( $value ); //phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode

		return $this;
	}

	/**
	 * Remove metadata.
	 *
	 * @param string $key
	 *
	 * @throws InvalidArgumentException
	 * @return Tus_Client
	 */
	public function remove_metadata( $key ) {
		if ( ! is_string( $key ) ) {
			throw new InvalidArgumentException( '$key needs to be a string' );
		}
		unset( $this->metadata[ $key ] );

		return $this;
	}

	/**
	 * Set metadata.
	 *
	 * @param array $items
	 *
	 * @return Tus_Client
	 */
	public function set_metadata( array $items ) {
		$items = array_map( 'base64_encode', $items );

		$this->metadata = $items;

		return $this;
	}

	/**
	 * Get metadata.
	 *
	 * @return array
	 */
	public function get_metadata() {
		return $this->metadata;
	}

	/**
	 * Get metadata for Upload-Metadata header.
	 *
	 * @return string
	 */
	protected function get_upload_metadata_header() {
		$metadata = array();

		foreach ( $this->get_metadata() as $key => $value ) {
			$metadata[] = "{$key} {$value}";
		}

		return implode( ',', $metadata );
	}

	/**
	 * Get key.
	 *
	 * @return string
	 */
	public function get_key() {
		return $this->key;
	}

	/**
	 * Get url.
	 *
	 * @throws File_Exception
	 * @return string|null
	 */
	public function get_url() {
		$this->url = $this->get_cache_attribute( 'location' );

		if ( ! $this->url ) {
			throw new File_Exception( 'File not found.' );
		}

		return $this->url;
	}

	/**
	 * Set checksum algorithm.
	 *
	 * @param string $algorithm
	 *
	 * @throws InvalidArgumentException
	 * @return Tus_Client
	 */
	public function set_checksum_algorithm( $algorithm ) {
		if ( ! is_string( $algorithm ) ) {
			throw new InvalidArgumentException( '$algorithm needs to be a string' );
		}
		$this->checksum_algorithm = $algorithm;

		return $this;
	}

	/**
	 * Get checksum algorithm.
	 *
	 * @return string
	 */
	public function get_checksum_algorithm() {
		return $this->checksum_algorithm;
	}

	/**
	 * Check if current upload is expired.
	 *
	 * @return bool
	 */
	public function is_expired() {
		$expires_at = $this->get_cache_attribute( 'expires_at' );

		return empty( $expires_at ) || time() > strtotime( $expires_at );
	}

	/**
	 * Check if this is a partial upload request.
	 *
	 * @return bool
	 */
	public function is_partial() {
		return $this->partial;
	}

	/**
	 * Get partial offset.
	 *
	 * @return int
	 */
	public function get_partial_offset() {
		return $this->partial_offset;
	}

	/**
	 * Set offset and force this to be a partial upload request.
	 *
	 * @param int $offset
	 *
	 * @throws InvalidArgumentException
	 * @return self
	 */
	public function seek( $offset ) {
		if ( ! is_int( $offset ) ) {
			throw new InvalidArgumentException( '$offset needs to be an integer' );
		}
		$this->partial_offset = $offset;

		$this->partial();

		return $this;
	}

	/**
	 * Upload file.
	 *
	 * @param int $bytes Bytes to upload.
	 *
	 * @throws Tus_Exception
	 * @throws InvalidArgumentException
	 *
	 * @return int
	 */
	public function upload( $bytes = -1 ) {
		if ( ! is_int( $bytes ) ) {
			throw new InvalidArgumentException( '$bytes needs to be an integer' );
		}
		$bytes          = $bytes < 0 ? $this->get_file_size() : $bytes;
		$partial_offset = $this->partial_offset < 0 ? 0 : $this->partial_offset;

		$offset = $this->get_offset();
		if ( is_wp_error( $offset ) ) {
			throw new Tus_Exception( "Couldn't connect to server." );
		}

		if ( false === $offset ) {
			$this->url = $this->create( $this->get_key() );
			$offset    = $partial_offset;
		}

		// Verify that upload is not yet expired.
		if ( $this->is_expired() ) {
			throw new Tus_Exception( 'Upload expired.' );
		}

		// Now, resume upload with PATCH request.
		return $this->send_patch_request( $bytes, $offset );
	}

	/**
	 * Create resource with POST request.
	 *
	 * @param string $key
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return string
	 */
	public function create( $key ) {
		if ( ! is_string( $key ) ) {
			throw new InvalidArgumentException( '$key needs to be a string' );
		}
		return $this->create_with_upload( $key, 0 )['location'];
	}

	/**
	 * Create resource with POST request and upload data using the creation-with-upload extension.
	 *
	 * @see https://tus.io/protocols/resumable-upload.html#creation-with-upload
	 *
	 * @param string $key
	 * @param int    $bytes -1 => all data; 0 => no data.
	 *
	 * @throws InvalidArgumentException
	 * @throws Tus_Exception
	 *
	 * @return array [
	 *   'location' => string,
	 *   'offset' => int
	 * ]
	 */
	public function create_with_upload( $key, $bytes = -1 ) {
		if ( ! is_string( $key ) ) {
			throw new InvalidArgumentException( '$key needs to be a string' );
		}
		$bytes = $bytes < 0 ? $this->file_size : $bytes;

		$headers = $this->headers + array(
			'Upload-Length'   => $this->file_size,
			'Upload-Key'      => $key,
			'Upload-Checksum' => $this->get_upload_checksum_header(),
			'Upload-Metadata' => $this->get_upload_metadata_header(),
		);

		$data = '';
		if ( $bytes > 0 ) {
			$data = $this->get_data( 0, $bytes );

			$headers += array(
				'Content-Type'   => self::HEADER_CONTENT_TYPE,
				'Content-Length' => \strlen( $data ),
			);
		}

		if ( $this->is_partial() ) {
			$headers += array( 'Upload-Concat' => 'partial' );
		}

		$response = $this->do_post_request(
			$this->api_url,
			array(
				'body'    => $data,
				'headers' => $headers,
			)
		);

		if ( is_wp_error( $response ) ) {
			throw new Tus_Exception( 'Error reaching the server.' );
		}

		$status_code = wp_remote_retrieve_response_code( $response );

		if ( WP_Http::CREATED !== $status_code ) {
			$body          = json_decode( wp_remote_retrieve_body( $response ) );
			$error_message = __( 'Unable to create resource.', 'jetpack-videopress-pkg' );
			if ( ! empty( $body->message ) ) {
				$error_message = $body->message;
				if ( ! empty( $body->error ) ) {
					$error_message = $body->error . ': ' . $error_message;
				}
			}
			// server can respond in a few different ways.
			if ( isset( $body->success ) && false === $body->success ) {
				if ( ! empty( $body->data ) && ! empty( $body->data->message ) ) {
					$error_message = $body->data->message;
				}
			}
			throw new Tus_Exception( $error_message, $status_code );
		}

		$upload_offset   = $bytes > 0 ? wp_remote_retrieve_header( $response, 'upload-offset' ) : 0;
		$upload_location = wp_remote_retrieve_header( $response, 'location' );

		$cache = $this->get_cache();

		$cache->set(
			$this->get_key(),
			array(
				'location'      => $upload_location,
				'expires_at'    => gmdate( $cache::RFC_7231, time() + $cache->get_ttl() ),
				'token_for_key' => wp_remote_retrieve_header( $response, 'x-videopress-upload-key-token' ),
			)
		);

		return array(
			'location' => $upload_location,
			'offset'   => $upload_offset,
		);
	}

	/**
	 * Set as partial request.
	 *
	 * @param bool $state
	 *
	 * @throws InvalidArgumentException
	 * @return void
	 */
	protected function partial( $state = true ) {
		if ( ! is_bool( $state ) ) {
			throw new InvalidArgumentException( '$state needs to be a boolean' );
		}
		$this->partial = $state;

		if ( ! $this->partial ) {
			return;
		}

		$key = $this->get_key();

		if ( false !== strpos( $key, self::PARTIAL_UPLOAD_NAME_SEPARATOR ) ) {
			list($key, /* $partialKey */) = explode( self::PARTIAL_UPLOAD_NAME_SEPARATOR, $key );
		}

		$this->key = $key . self::PARTIAL_UPLOAD_NAME_SEPARATOR . wp_generate_uuid4();
	}

	/**
	 * Send HEAD request and retrieves offset.
	 *
	 * @return bool|int|WP_Error integer with the offset uploaded if file exists. False if file does not exist. WP_Error on connection error.
	 */
	public function get_offset() {
		$headers = $this->headers + array(
			'X-HTTP-Method-Override' => 'HEAD',
		);

		try {
			$response = $this->do_get_request(
				$this->get_url(),
				array( 'headers' => $headers )
			);
		} catch ( File_Exception $e ) {
			return false;
		}

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$response_code = wp_remote_retrieve_response_code( $response );

		if ( WP_Http::OK !== $response_code ) {
			return false;
		}

		return (int) wp_remote_retrieve_header( $response, 'upload-offset' );
	}

	/**
	 * Send PATCH request.
	 *
	 * @param int $bytes
	 * @param int $offset
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return int
	 */
	protected function send_patch_request( $bytes, $offset ) {
		if ( ! is_int( $bytes ) || ! is_int( $offset ) ) {
			throw new InvalidArgumentException( '$bytes and $offset need to be integers' );
		}
		$data    = $this->get_data( $offset, $bytes );
		$headers = $this->headers + array(
			'Content-Type'           => self::HEADER_CONTENT_TYPE,
			'Content-Length'         => \strlen( $data ),
			'Upload-Checksum'        => $this->get_upload_checksum_header(),
			'X-HTTP-Method-Override' => 'PATCH',

		);

		$token                                = $this->get_cache_attribute( 'token_for_key' );
		$headers['x-videopress-upload-token'] = $token;

		if ( $this->is_partial() ) {
			$headers += array( 'Upload-Concat' => self::UPLOAD_TYPE_PARTIAL );
		} else {
			$headers += array( 'Upload-Offset' => $offset );
		}

		$response = $this->do_post_request(
			$this->get_url(),
			array(
				'body'    => $data,
				'headers' => $headers,
			)
		);

		$response_code = wp_remote_retrieve_response_code( $response );
		if ( WP_Http::NO_CONTENT !== $response_code ) {
			throw $this->handle_patch_exception( $response );
		}

		$guid       = wp_remote_retrieve_header( $response, 'x-videopress-upload-guid' );
		$media_id   = (int) wp_remote_retrieve_header( $response, 'x-videopress-upload-media-id' );
		$upload_src = wp_remote_retrieve_header( $response, 'x-videopress-upload-src-url' );

		if ( $guid && $media_id && $upload_src ) {
			$this->set_uploaded_video_details( $guid, $media_id, $upload_src );
		}

		return (int) wp_remote_retrieve_header( $response, 'upload-offset' );
	}

	/**
	 * Handle client exception during patch request.
	 *
	 * @param array $response The response from the PATCH request.
	 *
	 * @return \Exception
	 */
	protected function handle_patch_exception( $response ) {

		if ( is_wp_error( $response ) ) {
			return new Tus_Exception( $response->get_error_message() );
		}

		$response_code = wp_remote_retrieve_response_code( $response );

		if ( WP_Http::REQUESTED_RANGE_NOT_SATISFIABLE === $response_code ) {
			return new Tus_Exception( 'The uploaded file is corrupt.' );
		}

		if ( WP_Http::HTTP_CONTINUE === $response_code ) {
			return new Tus_Exception( 'Connection aborted by user.' );
		}

		if ( WP_Http::UNSUPPORTED_MEDIA_TYPE === $response_code ) {
			return new Tus_Exception( 'Unsupported media types.' );
		}

		return new Tus_Exception( (string) wp_remote_retrieve_body( $response ), $response_code );
	}

	/**
	 * Get X bytes of data from file.
	 *
	 * @param int $offset
	 * @param int $bytes
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return string
	 */
	protected function get_data( $offset, $bytes ) {
		if ( ! is_int( $bytes ) || ! is_int( $offset ) ) {
			throw new InvalidArgumentException( '$bytes and $offset need to be integers' );
		}
		$file   = new Tus_File();
		$handle = $file->open( $this->get_file_path(), $file::READ_BINARY );

		$file->seek( $handle, $offset );

		$data = $file->read( $handle, $bytes );

		$file->close( $handle );

		return $data;
	}

	/**
	 * Get upload checksum header.
	 *
	 * @return string
	 */
	protected function get_upload_checksum_header() {
		return $this->get_checksum_algorithm() . ' ' . base64_encode( $this->get_checksum() ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * Do HTTP request
	 *
	 * @param string $url The URL to make the request to.
	 * @param array  $args Request arguments.
	 * @return array|WP_Error WordPress Http response
	 */
	protected function do_request( $url, $args ) {
		$args = wp_parse_args(
			$args,
			array(
				'timeout' => 25,
			)
		);
		return wp_remote_request( $url, $args );
	}

	/**
	 * Do a GET HTTP request
	 *
	 * @param string $url The URL to make the request to.
	 * @param array  $args Request arguments.
	 * @return array|WP_Error WordPress Http response
	 */
	protected function do_get_request( $url, $args ) {
		$args = wp_parse_args(
			$args,
			array(
				'method' => 'GET',
			)
		);
		return $this->do_request( $url, $args );
	}

	/**
	 * Do a POST HTTP request
	 *
	 * @param string $url The URL to make the request to.
	 * @param array  $args Request arguments.
	 * @return array|WP_Error WordPress Http response
	 */
	protected function do_post_request( $url, $args ) {
		$args = wp_parse_args(
			$args,
			array(
				'method' => 'POST',
			)
		);
		return $this->do_request( $url, $args );
	}
}
