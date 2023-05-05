<?php
namespace W3TC;



class UsageStatistics_Core {
	private $shutdown_handler_added = false;
	private $storage;
	private $hotspot_flushing_state_on_exit_attempt = null;



	public function __construct() {
		$this->storage = new UsageStatistics_StorageWriter();
	}



	public function add_shutdown_handler() {
		$this->shutdown_handler_added = true;
		add_action( 'shutdown', array(
				$this,
				'shutdown'
			), 100000, 0 );

		if ( !is_null( $this->hotspot_flushing_state_on_exit_attempt ) )
			add_action( 'init', array(
					$this, 'init_when_exit_requested' ) );
	}



	public function is_shutdown_handler_added() {
		return $this->shutdown_handler_added;
	}



	public function init_when_exit_requested() {
		exit();
	}



	public function shutdown() {
		if ( !is_null( $this->hotspot_flushing_state_on_exit_attempt ) )
			$this->storage->finish_flush_hotspot_data();
		else
			$this->storage->maybe_flush_hotspot_data();

		do_action( 'w3tc_usage_statistics_of_request', $this->storage );
	}



	/**
	 * $metrics_function has to be added by add_action on plugin load
	 */
	public function apply_metrics_before_init_and_exit( $metrics_function ) {
		// plugin already loaded, metrics will be added normal way
		// by shutdown

		if ( $this->shutdown_handler_added ) {
			return;
		}

		$this->hotspot_flushing_state_on_exit_attempt =
			$this->storage->begin_flush_hotspot_data();

		// flush wants to happen in that process, need to pass through whole
		// wp request processing further
		if ( $this->hotspot_flushing_state_on_exit_attempt != 'not_needed' ) {
			return;
		}

		call_user_func( $metrics_function, $this->storage );
		exit();
	}

}
