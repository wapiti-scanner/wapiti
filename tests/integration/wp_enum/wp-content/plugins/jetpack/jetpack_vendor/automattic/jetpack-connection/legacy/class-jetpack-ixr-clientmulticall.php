<?php
/**
 * IXR_ClientMulticall
 *
 * @package automattic/jetpack-connection
 *
 * @since 1.7.0
 * @since-jetpack 1.5
 * @since-jetpack 7.7 Moved to the jetpack-connection package.
 */

/**
 * A Jetpack implementation of the WordPress core IXR client, capable of multiple calls in a single request.
 */
class Jetpack_IXR_ClientMulticall extends Jetpack_IXR_Client {
	/**
	 * Storage for the IXR calls.
	 *
	 * @var array
	 */
	public $calls = array();

	/**
	 * Add a IXR call to the client.
	 * First argument is the method name.
	 * The rest of the arguments are the params specified to the method.
	 *
	 * @param string[] ...$args IXR args.
	 */
	public function addCall( ...$args ) {
		$method_name   = array_shift( $args );
		$struct        = array(
			'methodName' => $method_name,
			'params'     => $args,
		);
		$this->calls[] = $struct;
	}

	/**
	 * Perform the IXR multicall request.
	 *
	 * @param string[] ...$args IXR args.
	 *
	 * @return bool True if request succeeded, false otherwise.
	 */
	public function query( ...$args ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$this->calls = $this->sort_calls( $this->calls );

		// Prepare multicall, then call the parent::query() method.
		return parent::query( 'system.multicall', $this->calls );
	}

	/**
	 * Sort the IXR calls.
	 * Make sure syncs are always done first preserving relative order.
	 *
	 * @param array $calls Calls to sort.
	 * @return array Sorted calls.
	 */
	public function sort_calls( $calls ) {
		$sync_calls  = array();
		$other_calls = array();

		foreach ( $calls as $call ) {
			if ( 'jetpack.syncContent' === $call['methodName'] ) {
				$sync_calls[] = $call;
			} else {
				$other_calls[] = $call;
			}
		}

		return array_merge( $sync_calls, $other_calls );
	}
}
