<?php
namespace W3TC;

class Util_WpFile_FilesystemWriteException extends Util_WpFile_FilesystemOperationException {
	private $filename;
	private $file_contents;

	public function __construct( $message, $credentials_form, $filename,
		$file_contents ) {
		parent::__construct( $message, $credentials_form );

		$this->filename = $filename;
		$this->file_contents = $file_contents;
	}

	public function filename() {
		return $this->filename;
	}

	public function file_contents() {
		return $this->file_contents;
	}
}
