<?php
namespace W3TC;

class Util_WpFile_FilesystemChmodException extends Util_WpFile_FilesystemOperationException {
	private $filename;
	private $permission;

	public function __construct( $message, $credentials_form, $filename, $permission ) {
		parent::__construct( $message, $credentials_form );

		$this->filename = $filename;
		$this->permission = $permission;
	}

	public function filename() {
		return $this->filename;
	}

	public function permission() {
		return $this->permission;
	}
}
