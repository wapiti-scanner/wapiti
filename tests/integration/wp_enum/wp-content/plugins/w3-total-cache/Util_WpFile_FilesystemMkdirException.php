<?php
namespace W3TC;

class Util_WpFile_FilesystemMkdirException extends Util_WpFile_FilesystemOperationException {
	private $folder;

	public function __construct( $message, $credentials_form, $folder ) {
		parent::__construct( $message, $credentials_form );

		$this->folder = $folder;
	}

	public function folder() {
		return $this->folder;
	}
}
