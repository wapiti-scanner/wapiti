<?php
namespace W3TC;

class Util_WpFile_FilesystemCopyException extends Util_WpFile_FilesystemOperationException {
	private $source_filename;
	private $destination_filename;

	public function __construct( $message, $credentials_form,
		$source_filename, $destination_filename ) {
		parent::__construct( $message, $credentials_form );

		$this->source_filename = $source_filename;
		$this->destination_filename = $destination_filename;
	}

	public function source_filename() {
		return $this->source_filename;
	}

	public function destination_filename() {
		return $this->destination_filename;
	}
}
