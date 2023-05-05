<?php
namespace W3TC;

class Util_WpFile_FilesystemRmException extends Util_WpFile_FilesystemOperationException {
	private $filename;

	public function __construct( $message, $credentials_form, $filename ) {
		parent::__construct( $message, $credentials_form );

		$this->filename = $filename;
	}

	public function filename() {
		return $this->filename;
	}
}
