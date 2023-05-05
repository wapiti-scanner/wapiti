<?php
namespace W3TC;

/**
 * Thrown when the plugin fails to get correct filesystem rights when it tries to modify manipulate filesystem.
 */
class Util_WpFile_FilesystemOperationException extends \Exception {
	private $credentials_form;

	public function __construct( $message, $credentials_form = null ) {
		parent::__construct( $message );
		$this->credentials_form = $credentials_form;
	}

	public function credentials_form() {
		return $this->credentials_form;

	}
}
