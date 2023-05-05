<?php
namespace W3TC;

class Util_Environment_Exception extends \Exception {
	private $technical_message;

	public function __construct( $message, $technical_message = '' ) {
		parent::__construct( $message );
		$this->technical_message = $technical_message;
	}

	public function technical_message() {
		return $this->technical_message;
	}
}
