<?php
namespace W3TC;

class Util_Environment_Exceptions extends \Exception {
	private $exceptions;
	private $credentials_form;

	public function __construct() {
		parent::__construct();

		$this->exceptions = array();
	}

	public function push( $ex ) {
		if ( $ex instanceof Util_Environment_Exceptions ) {
			foreach ( $ex->exceptions() as $ex2 )
				$this->push( $ex2 );
		} else {
			if ( $this->credentials_form == null &&
				$ex instanceof Util_WpFile_FilesystemOperationException &&
				$ex->credentials_form() != null )
				$this->credentials_form = $ex->credentials_form();
			$this->exceptions[] = $ex;
		}
	}

	/**
	 *
	 *
	 * @return Exception[]
	 */
	public function exceptions() {
		return $this->exceptions;
	}

	public function credentials_form() {
		return $this->credentials_form;
	}

	public function getCombinedMessage() {
		$s = '';
		foreach ( $this->exceptions as $m ) {
			$s .= $m->getMessage() . "\r\n";
		}

		return $s;
	}

}
