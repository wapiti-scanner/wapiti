<?php
/**
 * VideoPress Uploader
 *
 * @package automattic/jetpack-videopress
 */

namespace Automattic\Jetpack\VideoPress;

use Jetpack_Options;
use VideoPressUploader\File_Exception;
use VideoPressUploader\Tus_Client;

/**
 * VideoPress Uploader class
 *
 * Handles the upload from the Media Library to VideoPress servers
 */
class Uploader {

	/**
	 * The key of the post meta that holds the ID of the attachment that holds the VideoPress video, in case this attachment was uploaded before.
	 *
	 * @var string
	 */
	const UPLOADED_KEY = '_videopress_uploaded_id';

	/**
	 * The chunk size of each upload step
	 *
	 * @var int
	 */
	const CHUNK_SIZE = 5000000;

	/**
	 * The Tus Client instance
	 *
	 * @var Tus_Client
	 */
	protected $client = null;

	/**
	 * The attachment ID
	 *
	 * @var int
	 */
	protected $attachment_id;

	/**
	 * Checks whether this feature is supported by the server
	 *
	 * @param int $attachment_id The ID of the video attachment we want to upload to VideoPress.
	 * @return boolean
	 */
	public static function is_valid_attachment_id( $attachment_id ) {
		$file_path = get_attached_file( $attachment_id );
		if ( ! $file_path || ! is_readable( $file_path ) ) {
			return false;
		}
		if ( 0 !== strpos( get_post_mime_type( $attachment_id ), 'video/' ) ) {
			return false;
		}
		return true;
	}

	/**
	 * Constructs the object
	 *
	 * @throws Upload_Exception If attachment is invalid or server does not support it.
	 * @param int $attachment_id The ID of the video attachment we want to upload to VideoPress.
	 */
	public function __construct( $attachment_id ) {
		$this->attachment_id = $attachment_id;
		if ( ! $this->get_file_path() ) {
			throw new Upload_Exception( __( 'Invalid attachment ID', 'jetpack-videopress-pkg' ), Upload_Exception::ERROR_INVALID_ATTACHMENT_ID );
		}
		if ( ! is_readable( $this->get_file_path() ) ) {
			throw new Upload_Exception( __( 'File not found', 'jetpack-videopress-pkg' ), Upload_Exception::ERROR_FILE_NOT_FOUND );
		}
		if ( ! $this->file_has_supported_mime_type() ) {
			throw new Upload_Exception( __( 'Mime type not supported', 'jetpack-videopress-pkg' ), Upload_Exception::ERROR_MIME_TYPE_NOT_SUPPORTED );
		}
	}

	/**
	 * Gets the path of the video file
	 *
	 * @return string
	 */
	public function get_file_path() {
		return get_attached_file( $this->attachment_id );
	}

	/**
	 * Gets the mime type of the attachment
	 *
	 * @return string
	 */
	public function get_file_mime_type() {
		return get_post_mime_type( $this->attachment_id );
	}

	/**
	 * Gets the name of the video file
	 *
	 * @return string
	 */
	public function get_file_name() {
		return basename( $this->get_file_path() );
	}

	/**
	 * Gets the size of the video file
	 *
	 * @return int
	 */
	public function get_file_size() {
		return filesize( $this->get_file_path() );
	}

	/**
	 * Checks if the mime type of the attachment is supported to be uploaded
	 *
	 * @return boolean
	 */
	public function file_has_supported_mime_type() {
		return 0 === strpos( $this->get_file_mime_type(), 'video/' );
	}

	/**
	 * Gets the VideoPress upload token
	 *
	 * @throws Upload_Exception If it fails to fetch the token.
	 *
	 * @return string
	 */
	public function get_upload_token() {
		return VideoPressToken::videopress_upload_jwt();
	}

	/**
	 * Gets a unique upload key for this attachment
	 *
	 * @return string
	 */
	public function get_key() {
		return sprintf( 's-%d-v-%d', Jetpack_Options::get_option( 'id' ), $this->attachment_id );
	}

	/**
	 * Sets the current attachment as uploaded and stores the ID of the VideoPress video attachment ID
	 *
	 * @param int $new_attachment_id The ID of the new attachment created to hold the VideoPress video.
	 * @return void
	 */
	protected function mark_as_uploaded( $new_attachment_id ) {
		update_post_meta( $this->attachment_id, self::UPLOADED_KEY, $new_attachment_id );
	}

	/**
	 * Sets the current attachment as not being uploaded before. Deletes the reference to the videopress attachment
	 *
	 * @return void
	 */
	protected function unmark_as_uploaded() {
		delete_post_meta( $this->attachment_id, self::UPLOADED_KEY );
	}

	/**
	 * Checks whether this attachment was uploaded before
	 *
	 * @return boolean
	 */
	public function is_uploaded() {
		return ! empty( $this->get_uploaded_attachment_id() );
	}

	/**
	 * Gets the ID of the VideoPress video attachment in case this attachment was uploaded before
	 *
	 * @return boolean|string False if value is absent. Post ID on success.
	 */
	public function get_uploaded_attachment_id() {
		return get_post_meta( $this->attachment_id, self::UPLOADED_KEY, true );
	}

	/**
	 * Retrieves the instance of the Tus_Client
	 *
	 * @return Tus_Client
	 */
	public function get_client() {
		if ( $this->client !== null ) {
			return $this->client;
		}

		$this->client = new Tus_Client( $this->get_key(), $this->get_upload_token(), Jetpack_Options::get_option( 'id' ) );

		return $this->client;
	}

	/**
	 * Uploads a chunk of the file
	 *
	 * @return array With the status of the upload
	 */
	public function upload() {
		if ( $this->is_uploaded() ) {
			return $this->check_status();
		}
		try {
			$this->get_client()->file( $this->get_file_path(), $this->get_file_name() );

			$bytes_uploaded = $this->get_client()->upload( self::CHUNK_SIZE );

			if ( $bytes_uploaded === $this->get_file_size() ) {
				$this->mark_as_uploaded( $this->get_client()->get_uploaded_video_details()['media_id'] );
				return array(
					'status'           => 'complete',
					'bytes_uploaded'   => $bytes_uploaded,
					'file_size'        => $this->get_file_size(),
					'file_name'        => $this->get_file_name(),
					'upload_key'       => $this->get_key(),
					'uploaded_details' => $this->get_client()->get_uploaded_video_details(),
				);
			}

			return array(
				'status'         => 'uploading',
				'bytes_uploaded' => $bytes_uploaded,
				'file_size'      => $this->get_file_size(),
				'file_name'      => $this->get_file_name(),
				'upload_key'     => $this->get_key(),
			);
		} catch ( \Exception $e ) {
			return array(
				'status'         => 'error',
				'bytes_uploaded' => -1,
				'file_size'      => $this->get_file_size(),
				'file_name'      => $this->get_file_name(),
				'upload_key'     => $this->get_key(),
				'error'          => $e->getCode() . ': ' . $e->getMessage(),
			);
		}
	}

	/**
	 * Checks the status of the upload of this attachment
	 *
	 * @return array
	 */
	public function check_status() {

		if ( $this->is_uploaded() ) {
			$uploaded_attachment_id = $this->get_uploaded_attachment_id();
			$uploaded_video_guid    = get_post_meta( $uploaded_attachment_id, 'videopress_guid', true );
			if ( $uploaded_video_guid ) {
				return array(
					'status'              => 'uploaded',
					'upload_key'          => $this->get_key(),
					'uploaded_post_id'    => $uploaded_attachment_id,
					'uploaded_video_guid' => $uploaded_video_guid,
				);
			} else {
				// VideoPress attachment is gone, allow user to upload it again.
				$this->unmark_as_uploaded();
			}
		}

		try {
			$offset = $this->get_client()->get_offset();
			$status = false !== $offset ? 'resume' : 'new';
			$offset = false === $offset ? 0 : $offset;

			return array(
				'status'         => $status,
				'bytes_uploaded' => $offset,
				'file_size'      => $this->get_file_size(),
				'file_name'      => $this->get_file_name(),
				'upload_key'     => $this->get_key(),
			);
		} catch ( File_Exception $e ) {
			return array(
				'status'         => 'resume',
				'bytes_uploaded' => 0,
				'file_size'      => $this->get_file_size(),
				'file_name'      => $this->get_file_name(),
				'upload_key'     => $this->get_key(),
			);
		} catch ( \Exception $e ) {
			return array(
				'status'         => 'error',
				'bytes_uploaded' => -1,
				'file_size'      => $this->get_file_size(),
				'file_name'      => $this->get_file_name(),
				'message'        => $e->getMessage(),
			);
		}
	}

}
