<?php
namespace W3TC;

class UserExperience_LazyLoad_Mutator_Unmutable {
	private $placeholders = array();



	public function __construct() {
		$this->placeholder_base = 'w3tc_lazyload_' .
			md5( isset( $_SERVER['REQUEST_TIME'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_TIME'] ) ) : '' ) . '_';
	}



	public function remove_unmutable( $buffer ) {
		// scripts
		$buffer = preg_replace_callback(
			'~<script(\b[^>]*)>(.*?)</script>~is',
			array( $this, 'placeholder' ), $buffer );

		// styles
		$buffer = preg_replace_callback(
			'~\s*<style(\b[^>]*)>(.*?)</style>~is',
			array($this, 'placeholder'), $buffer);

		return $buffer;
	}



	public function restore_unmutable( $buffer ) {
		return str_replace(
			array_keys( $this->placeholders ),
			array_values( $this->placeholders ),
			$buffer
		);
	}



	public function placeholder( $matches ) {
		$key = '{' .$this->placeholder_base . count( $this->placeholders ) . '}';
		$this->placeholders[$key] = $matches[0];
		return $key;
	}
}
