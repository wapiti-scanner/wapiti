<?php
namespace W3TC;

class Util_WpFile_FilesystemModifyException extends Util_WpFile_FilesystemOperationException {
	private $modification_description;
	private $filename;
	private $file_contents;

	public function __construct( $message, $credentials_form,
		$modification_description, $filename, $file_contents = '' ) {
		parent::__construct( $message, $credentials_form );

		$this->modification_description = $modification_description;
		$this->filename = $filename;
		$this->file_contents = $file_contents;
	}

	function modification_description() {
		return $this->modification_description;
	}

	public function filename() {
		return $this->filename;
	}

	public function file_contents() {
		return $this->file_contents;
	}
}
