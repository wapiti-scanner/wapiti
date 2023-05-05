<?php
namespace W3TC;

class Util_Bus {
	/**
	 * Add W3TC action callback
	 *
	 * @param string  $key
	 * @param mixed   $callback
	 * @return void
	 */
	static public function add_ob_callback( $key, $callback ) {
		$GLOBALS['_w3tc_ob_callbacks'][$key] = $callback;
	}

	static public function do_ob_callbacks( $order, $value ) {
		foreach ( $order as $key ) {
			if ( isset( $GLOBALS['_w3tc_ob_callbacks'][$key] ) ) {
				$callback = $GLOBALS['_w3tc_ob_callbacks'][$key];
				if ( is_callable( $callback ) ) {
					$value = call_user_func( $callback, $value );
				}
			}
		}
		return $value;
	}
}
