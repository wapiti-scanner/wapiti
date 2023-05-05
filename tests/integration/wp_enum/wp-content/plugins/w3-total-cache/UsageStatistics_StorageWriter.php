<?php
namespace W3TC;

/**
 * Manages data statistics.
 * Metrics:
 *
 */
class UsageStatistics_StorageWriter {
	private $slot_interval_seconds;
	private $slots_count;
	private $keep_history_interval_seconds;

	private $cache_storage;

	/**
	 * Cached values, just keep state between calls
	 */
	private $hotspot_endtime;
	private $new_hotspot_endtime = 0;
	private $now;

	/**
	 * begin_ sets the state what should it perform later
	 * finish reacts to that state and finishes flushing
	 * values:
	 *   not_needed - no flushinig required now
	 *   require_db - database access has to be available to decide
	 *   flushing_began_by_cache - that process has been selected to
	 *     flush hotspot data based on cache data state, still that has to be
	 *     verified in database
	 */
	private $flush_state;



	public function __construct() {
		$this->cache_storage = Dispatcher::get_usage_statistics_cache();

		$c = Dispatcher::config();
		$this->slot_interval_seconds = $c->get_integer( 'stats.slot_seconds' );

		$this->keep_history_interval_seconds =
			$c->get_integer( 'stats.slots_count' ) *
			$this->slot_interval_seconds;
		$this->slots_count = $c->get_integer( 'stats.slots_count' );
	}



	public function reset() {
		if ( !is_null( $this->cache_storage ) ) {
			$this->cache_storage->set( 'hotspot_endtime', 
			array( 'content' => 0 ) );
		}

		update_site_option( 'w3tc_stats_hotspot_start', time() );
		update_site_option( 'w3tc_stats_history', '' );
	}



	public function counter_add( $metric, $value ) {
		if ( !is_null( $this->cache_storage ) ) {
			$this->cache_storage->counter_add( $metric, $value );
		}
	}



	public function get_hotspot_end() {
		if ( is_null( $this->hotspot_endtime ) ) {
			$v = $this->cache_storage->get( 'hotspot_endtime' );
			$this->hotspot_endtime = ( isset( $v['content'] ) ? $v['content'] : 0 );
		}

		return $this->hotspot_endtime;
	}



	private function get_option_storage() {
		if ( is_multisite() )
			return new _OptionStorageWpmu();
		else
			return new _OptionStorageSingleSite();
	}


	public function maybe_flush_hotspot_data() {
		$result = $this->begin_flush_hotspot_data();
		if ( $result == 'not_needed' )
			return;

		$this->finish_flush_hotspot_data();
	}



	/**
	 * Returns if finish_* should be called.
	 * It tries to pass as litte processes as possible to
	 * flushing_begin if multiple processes come here
	 * at the same time when hotspot time ended.
	 */
	public function begin_flush_hotspot_data() {
		$hotspot_endtime = $this->get_hotspot_end();
		if ( is_null( $hotspot_endtime ) ) {
			// if cache not recognized - means nothing is cached at all
			// so stats not collected
			return 'not_needed';
		}

		$hotspot_endtime_int = (int)$hotspot_endtime;
		$this->now = time();

		if ( $hotspot_endtime_int <= 0 ) {
			$this->flush_state = 'require_db';
		} elseif ( $this->now < $hotspot_endtime_int ) {
			$this->flush_state = 'not_needed';
		} else {
			// rand value makes value unique for each process,
			// so as a result next replace works as a lock
			// passing only single process further
			$this->new_hotspot_endtime = $this->now + $this->slot_interval_seconds +
				( rand( 1, 9999 ) / 10000.0 );

			$succeeded = $this->cache_storage->set_if_maybe_equals( 'hotspot_endtime',
				array( 'content' => $hotspot_endtime ),
				array( 'content' => $this->new_hotspot_endtime ) );
			$this->flush_state =
				( $succeeded ? 'flushing_began_by_cache' : 'not_needed' );
		}

		return $this->flush_state;
	}



	public function finish_flush_hotspot_data() {
		$option_storage = $this->get_option_storage();

		if ( $this->flush_state == 'not_needed' )
			return;

		if ( $this->flush_state != 'require_db' &&
			$this->flush_state != 'flushing_began_by_cache' )
			throw new Exception( 'unknown usage stats state ' . $this->flush_state );

		// check whats there in db
		$this->hotspot_endtime = $option_storage->get_hotspot_end();
		$hotspot_endtime_int = (int)$this->hotspot_endtime;

		if ( $this->now < $hotspot_endtime_int ) {
			// update cache, since there is something old/missing in cache
			$this->cache_storage->set( 'hotspot_endtime',
				array( 'content' => $this->hotspot_endtime ) );
			return;   // not neeeded really, db state after
		}
		if ( $this->new_hotspot_endtime <= 0 )
			$this->new_hotspot_endtime = $this->now +
				$this->slot_interval_seconds +
				( rand( 1, 9999 ) / 10000.0 );

		if ( $hotspot_endtime_int <= 0 ) {
			// no data in options, initialization
			$this->cache_storage->set( 'hotspot_endtime',
				array( 'content' => $this->new_hotspot_endtime ) );
			update_site_option( 'w3tc_stats_hotspot_start', time() );
			$option_storage->set_hotspot_end( $this->new_hotspot_endtime );
			return;
		}

		// try to become the process who makes flushing by
		// performing atomic database update

		// rand value makes value unique for each process,
		// so as a result next replace works as a lock
		// passing only single process further
		$succeeded = $option_storage->prolong_hotspot_end(
			$this->hotspot_endtime, $this->new_hotspot_endtime );
		if ( !$succeeded )
			return;

		$this->cache_storage->set( 'hotspot_endtime',
			array( 'content' => $this->new_hotspot_endtime ) );


		// flush data
		$metrics = array();
		$metrics = apply_filters( 'w3tc_usage_statistics_metrics', $metrics );

		$metric_values = array();
		$metric_values['timestamp_start'] = get_site_option( 'w3tc_stats_hotspot_start' );
		$metric_values['timestamp_end'] = $hotspot_endtime_int;

		// try to limit time between get and reset of counter value
		// to loose as small as posssible
		foreach ( $metrics as $metric ) {
			$metric_values[$metric] = $this->cache_storage->counter_get( $metric );
			$this->cache_storage->counter_set( $metric, 0 );
		}

		$metric_values = apply_filters( 'w3tc_usage_statistics_metric_values',
			$metric_values );

		$history_encoded = get_site_option( 'w3tc_stats_history' );
		$history = null;
		if ( !empty( $history_encoded ) )
			$history = json_decode( $history_encoded, true );
		if ( !is_array( $history ) )
			$history = array();

		$time_keep_border = time() - $this->keep_history_interval_seconds;

		if ( $hotspot_endtime_int < $time_keep_border )
			$history = array(
				array(
					'timestamp_start' => $time_keep_border,
					'timestamp_end' => (int)$this->new_hotspot_endtime -
					$this->slot_interval_seconds - 1
				)
			);   // this was started too much time from now
		else {
			// add collected
			$history[] = $metric_values;

			// if we empty place later - fill it
			for ( ;; ) {
				$metric_values = array(
					'timestamp_start' => $metric_values['timestamp_end']
				);
				$metric_values['timestamp_end'] =
					$metric_values['timestamp_start'] + $this->slot_interval_seconds;
				if ( $metric_values['timestamp_end'] < $this->now )
					$history[] = $metric_values;
				else
					break;
			}

			// make sure we have at least one value in history
			for ( ;count( $history ) > $this->slots_count; ) {
				if ( !isset( $history[0]['timestamp_end'] ) ||
					$history[0]['timestamp_end'] < $time_keep_border )
					array_shift( $history );
				else
					break;
			}
		}

		$history = apply_filters(
			'w3tc_usage_statistics_history_set', $history );

		update_site_option( 'w3tc_stats_hotspot_start', $this->now );
		update_site_option( 'w3tc_stats_history', json_encode( $history ) );
	}
}



/**
 * Can update option by directly incrementing current value,
 * not via get+set operation
 */
class _OptionStorageSingleSite {
	private $option_hotspot_end = 'w3tc_stats_hotspot_end';



	public function get_hotspot_end() {
		global $wpdb;

		$row = $wpdb->get_row( $wpdb->prepare(
				'SELECT option_value ' .
				'FROM ' . $wpdb->options . ' ' .
				'WHERE option_name = %s LIMIT 1',
				$this->option_hotspot_end ) );

		if ( !is_object( $row ) )
			return false;

		$v = $row->option_value;
		return $v;
	}



	public function set_hotspot_end( $new_value ) {
		update_site_option( $this->option_hotspot_end, $new_value );
	}



	/**
	 * Performs atomic update of option value
	 * from old to new value. Makes sure that only single process updates it.
	 * Only single process gets true return value when multiple tries to do that.
	 */
	public function prolong_hotspot_end( $old_value, $new_value ) {
		global $wpdb;

		$q = $wpdb->prepare(
			'UPDATE ' . $wpdb->options . ' ' .
			'SET option_value = %s ' .
			'WHERE option_name = %s AND option_value = %s', $new_value,
			$this->option_hotspot_end, $old_value );

		$result = $wpdb->query( $q );
		$succeeded = ( $result > 0 );

		return $succeeded;
	}
}



/**
 * Can update option by directly incrementing current value,
 * not via get+set operation
 */
class _OptionStorageWpmu {
	private $option_hotspot_end = 'w3tc_stats_hotspot_end';



	public function get_hotspot_end() {
		global $wpdb;

		$row = $wpdb->get_row( $wpdb->prepare(
				'SELECT meta_value ' .
				'FROM ' . $wpdb->sitemeta . ' ' .
				'WHERE site_id = %d AND meta_key = %s',
				$wpdb->siteid, $this->option_hotspot_end ) );

		if ( !is_object( $row ) )
			return false;

		$v = $row->meta_value;
		return $v;
	}

	/**
	 * Performs atomic update of option value
	 * from old to new value. Makes sure that only single process updates it.
	 * Only single process gets true return value when multiple tries to do that.
	 */
	public function set_hotspot_end( $new_value ) {
		update_site_option( $this->option_hotspot_end, $new_value );
	}



	/**
	 * Performs atomic update of option value
	 * from old to new value. Makes sure that only single process updates it.
	 * Only single process gets true return value when multiple tries to do that.
	 */
	public function prolong_hotspot_end( $old_value, $new_value ) {
		global $wpdb;

		$result = $wpdb->query( $wpdb->prepare(
				'UPDATE ' . $wpdb->sitemeta . ' ' .
				'SET meta_value = %s ' .
				'WHERE site_id = %d AND meta_key = %s AND meta_value = %s',
				$new_value, $wpdb->siteid, $this->option_hotspot_end, $old_value ) );
		$succeeded = ( $result > 0 );

		return $succeeded;
	}
}
