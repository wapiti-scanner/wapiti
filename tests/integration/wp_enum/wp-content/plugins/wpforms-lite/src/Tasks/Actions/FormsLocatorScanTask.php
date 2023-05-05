<?php

// phpcs:disable Generic.Commenting.DocComment.MissingShort
/** @noinspection PhpUnnecessaryCurlyVarSyntaxInspection */
/** @noinspection SqlResolve */
// phpcs:enable Generic.Commenting.DocComment.MissingShort

namespace WPForms\Tasks\Actions;

use WP_Post;
use WP_Query;
use WP_Screen;
use WPForms\Forms\Locator;
use WPForms\Tasks\Meta;
use WPForms\Tasks\Task;
use WPForms\Tasks\Tasks;

/**
 * Class FormLocatorScanTask.
 *
 * @since 1.7.4
 */
class FormsLocatorScanTask extends Task {

	/**
	 * Scan action name for this task.
	 *
	 * @since 1.7.4
	 */
	const SCAN_ACTION = 'wpforms_process_forms_locator_scan';

	/**
	 * Re-scan action name for this task.
	 *
	 * @since 1.7.4
	 */
	const RESCAN_ACTION = 'wpforms_process_forms_locator_rescan';

	/**
	 * Save action name for this task.
	 *
	 * @since 1.7.4
	 */
	const SAVE_ACTION = 'wpforms_process_forms_locator_save';

	/**
	 * Delete action name for this task.
	 *
	 * @since 1.7.4
	 */
	const DELETE_ACTION = 'wpforms_process_forms_locator_delete';

	/**
	 * Scan status option name.
	 *
	 * @since 1.7.4
	 */
	const SCAN_STATUS = 'wpforms_process_forms_locator_status';

	/**
	 * Scan status "In Progress".
	 *
	 * @since 1.7.4
	 */
	const SCAN_STATUS_IN_PROGRESS = 'in progress';

	/**
	 * Scan status "Completed".
	 *
	 * @since 1.7.4
	 */
	const SCAN_STATUS_COMPLETED = 'completed';

	/**
	 * Locations query arg.
	 *
	 * @since 1.7.4
	 */
	const LOCATIONS_QUERY_ARG = 'locations';

	/**
	 * Chunk size to use in get_form_locations().
	 * Specifies how many posts to load for scanning in one db request.
	 * Affects memory usage.
	 *
	 * @since 1.7.4
	 */
	const CHUNK_SIZE = 50;

	/**
	 * Locator class instance.
	 *
	 * @since 1.7.4
	 *
	 * @var Locator
	 */
	private $locator;

	/**
	 * Tasks class instance.
	 *
	 * @since 1.7.4
	 *
	 * @var Tasks
	 */
	private $tasks;

	/**
	 * Task recurring interval in seconds.
	 *
	 * @since 1.7.4
	 *
	 * @var int
	 */
	private $interval;

	/**
	 * Class constructor.
	 *
	 * @since 1.7.4
	 */
	public function __construct() {

		parent::__construct( self::SCAN_ACTION );
		$this->init();
	}

	/**
	 * Initialize the task with all the proper checks.
	 *
	 * @since 1.7.4
	 */
	public function init() {

		$this->locator = wpforms()->get( 'locator' );

		/**
		 * Give developers an ability to modify task interval.
		 *
		 * @since 1.7.4
		 *
		 * @param int $interval The task recurring interval in seconds. If <= 0, the task will be cancelled.
		 */
		$this->interval = (int) apply_filters( 'wpforms_tasks_actions_forms_locator_scan_task_interval', DAY_IN_SECONDS );

		$this->hooks();

		$this->tasks = wpforms()->get( 'tasks' );

		// Do not add a new one if scheduled.
		if ( $this->tasks->is_scheduled( self::SCAN_ACTION ) !== false ) {

			if ( $this->interval <= 0 ) {
				$this->cancel();
			}

			return;
		}

		$this->add_scan_task();
	}

	/**
	 * Add scan task.
	 *
	 * @since 1.7.4
	 */
	private function add_scan_task() {

		if ( $this->interval <= 0 ) {
			return;
		}

		// Add a new task if none exists.
		$this->recurring( time(), $this->interval )
			->params()
			->register();
	}

	/**
	 * Add hooks.
	 *
	 * @since 1.7.4
	 */
	private function hooks() {

		// Register hidden action for testing and support.
		add_action( 'current_screen', [ $this, 'maybe_run_actions_in_admin' ] );

		// Register Action Scheduler actions.
		add_action( self::SCAN_ACTION, [ $this, 'scan' ] );
		add_action( self::RESCAN_ACTION, [ $this, 'rescan' ] );
		add_action( self::SAVE_ACTION, [ $this, 'save' ] );
		add_action( self::DELETE_ACTION, [ $this, 'delete' ] );
		add_action( 'action_scheduler_after_process_queue', [ $this, 'after_process_queue' ] );
	}

	/**
	 * Maybe rescan or delete locations.
	 * Hidden undocumented actions for tests and support.
	 *
	 * @since 1.7.4
	 *
	 * @param WP_Screen $current_screen Current WP_Screen object.
	 */
	public function maybe_run_actions_in_admin( $current_screen ) {

		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		if (
			! $current_screen ||
			$current_screen->id !== 'toplevel_page_wpforms-overview' ||
			! isset( $_GET[ self::LOCATIONS_QUERY_ARG ] ) ||
			! wpforms_debug()
		) {
			return;
		}

		if ( $_GET[ self::LOCATIONS_QUERY_ARG ] === 'delete' ) {
			$this->delete();
		}

		if ( $_GET[ self::LOCATIONS_QUERY_ARG ] === 'scan' ) {
			$this->rescan();
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		wp_safe_redirect( remove_query_arg( [ self::LOCATIONS_QUERY_ARG ] ) );
		exit;
	}

	/**
	 * Run scan task.
	 *
	 * @since 1.7.4
	 */
	public function scan() {

		if ( ! $this->tasks ) {
			return;
		}

		// Bail out if scan is already in progress.
		if ( self::SCAN_STATUS_IN_PROGRESS === (string) get_option( self::SCAN_STATUS ) ) {
			return;
		}

		// Mark that scan is in progress.
		update_option( self::SCAN_STATUS, self::SCAN_STATUS_IN_PROGRESS );

		$this->log( 'Forms Locator scan action started.' );

		// This part of the scan shouldn't take more than 1 second even on big sites.
		$post_ids            = $this->search_in_posts();
		$post_locations      = $this->get_form_locations( $post_ids );
		$widget_locations    = $this->locator->search_in_widgets();
		$locations           = array_merge( $post_locations, $widget_locations );
		$form_location_metas = $this->get_form_location_metas( $locations );

		/**
		 * This part of the scan can take a while.
		 * Saving hundreds of metas with a potentially very high number of locations could be time and memory consuming.
		 * That is why we perform save via Action Scheduler.
		 */
		$meta_chunks = array_chunk( $form_location_metas, self::CHUNK_SIZE, true );
		$count       = count( $meta_chunks );

		foreach ( $meta_chunks as $index => $meta_chunk ) {
			$this->tasks->create( self::SAVE_ACTION )->async()->params( $meta_chunk, $index, $count )->register();
		}

		$this->log( 'Save tasks created.' );
	}

	/**
	 * Run immediate scan.
	 *
	 * @since 1.7.4
	 */
	public function rescan() {

		$this->cancel();
		$this->add_scan_task();
	}

	/**
	 * Save form locations.
	 *
	 * @since 1.7.4
	 *
	 * @param int $meta_id Action meta id.
	 */
	public function save( $meta_id ) {

		$params = ( new Meta() )->get( $meta_id );

		if ( ! $params ) {
			return;
		}

		list( $meta_chunk, $index, $count ) = $params->data;

		foreach ( $meta_chunk as $form_id => $meta ) {
			update_post_meta( $form_id, Locator::LOCATIONS_META, $meta );
		}

		$this->log(
			sprintf(
				'Forms Locator save action %1$d/%2$d completed.',
				$index + 1,
				$count
			)
		);
	}

	/**
	 * Delete form locations.
	 *
	 * @since 1.7.4
	 */
	public function delete() {

		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->postmeta} WHERE meta_key = %s",
				Locator::LOCATIONS_META
			)
		);

		delete_option( self::SCAN_STATUS );

		wp_cache_flush();
	}

	/**
	 * After process queue action.
	 * Delete transient to indicate that scanning is completed.
	 *
	 * @since 1.7.4
	 */
	public function after_process_queue() {

		if ( $this->tasks->is_scheduled( self::SAVE_ACTION ) ) {
			return;
		}

		// Mark that scan is finished.
		if ( (string) get_option( self::SCAN_STATUS ) === self::SCAN_STATUS_IN_PROGRESS ) {
			update_option( self::SCAN_STATUS, self::SCAN_STATUS_COMPLETED );
			$this->log( 'Forms Locator scan action completed.' );
		}
	}

	/**
	 * Search form in posts.
	 *
	 * @since 1.7.4
	 *
	 * @return int[]
	 */
	private function search_in_posts() {

		global $wpdb;

		$post_statuses = wpforms_wpdb_prepare_in( $this->locator->get_post_statuses() );
		$post_types    = wpforms_wpdb_prepare_in( $this->locator->get_post_types() );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$ids = $wpdb->get_col(
			"SELECT p.ID
					FROM (SELECT ID
						FROM {$wpdb->posts}
						WHERE post_status IN ({$post_statuses}) AND post_type IN ({$post_types}) ) AS ids
						INNER JOIN {$wpdb->posts} as p ON ids.ID = p.ID
					WHERE p.post_content REGEXP '\\\[wpforms|wpforms/form-selector'"
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		return array_map( 'intval', $ids );
	}

	/**
	 * Filters the SELECT clause of the query.
	 * Get minimal set of fields from the post record.
	 *
	 * @since 1.7.4
	 *
	 * @param string   $fields The SELECT clause of the query.
	 * @param WP_Query $query  The WP_Query instance (passed by reference).
	 *
	 * @return string
	 *
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function posts_fields_filter( $fields, $query ) {

		global $wpdb;

		$fields_arr = [ 'ID', 'post_title', 'post_status', 'post_type', 'post_content', 'post_name' ];
		$fields_arr = array_map(
			static function ( $field ) use ( $wpdb ) {

				return "$wpdb->posts." . $field;
			},
			$fields_arr
		);

		return implode( ', ', $fields_arr );
	}

	/**
	 * Get form locations.
	 *
	 * @since 1.7.4
	 *
	 * @param int[] $post_ids Post IDs.
	 *
	 * @return array
	 */
	private function get_form_locations( $post_ids ) { // phpcs:ignore WPForms.PHP.HooksMethod.InvalidPlaceForAddingHooks

		/**
		 * Block caching here, as caching produces unneeded db requests in
		 * update_object_term_cache() and update_postmeta_cache().
		 */
		$query_args = [
			'post_type'      => $this->locator->get_post_types(),
			'post_status'    => $this->locator->get_post_statuses(),
			'post__in'       => $post_ids,
			'no_found_rows'  => true,
			'posts_per_page' => - 1,
			'cache_results'  => false,
		];

		// Get form locations by chunks to prevent out of memory issue.
		$post_id_chunks = array_chunk( $post_ids, self::CHUNK_SIZE );
		$locations      = [];

		add_filter( 'posts_fields', [ $this, 'posts_fields_filter' ], 10, 2 );

		foreach ( $post_id_chunks as $post_id_chunk ) {
			$query_args['post__in'] = $post_id_chunk;
			$query                  = new WP_Query( $query_args );
			$locations              = $this->get_form_locations_from_posts( $query->posts, $locations );
		}

		remove_filter( 'posts_fields', [ $this, 'posts_fields_filter' ] );

		return $locations;
	}

	/**
	 * Get locations from posts.
	 *
	 * @since 1.7.4
	 *
	 * @param WP_Post[] $posts     Posts.
	 * @param array     $locations Locations.
	 *
	 * @return array
	 */
	private function get_form_locations_from_posts( $posts, $locations = [] ) {

		$home_url = home_url();

		foreach ( $posts as $post ) {

			$form_ids = $this->locator->get_form_ids( $post->post_content );

			if ( ! $form_ids ) {
				continue;
			}

			$url = get_permalink( $post );
			$url = ( $url === false || is_wp_error( $url ) ) ? '' : $url;
			$url = str_replace( $home_url, '', $url );

			foreach ( $form_ids as $form_id ) {
				$locations[] = [
					'type'    => $post->post_type,
					'title'   => $post->post_title,
					'form_id' => $form_id,
					'id'      => $post->ID,
					'status'  => $post->post_status,
					'url'     => $url,
				];
			}
		}

		return $locations;
	}

	/**
	 * Get form location metas.
	 *
	 * @param array $locations Locations.
	 *
	 * @since 1.7.4
	 *
	 * @return array
	 */
	private function get_form_location_metas( $locations ) {

		$metas = [];

		foreach ( $locations as $location ) {
			$metas[ $location['form_id'] ][] = $location;
		}

		return $metas;
	}

	/**
	 * Log message to WPForms logger and standard debug.log file.
	 *
	 * @since 1.7.4
	 *
	 * @param string $message The error message that should be logged.
	 *
	 * @noinspection ForgottenDebugOutputInspection
	 */
	private function log( $message ) {

		if ( defined( 'WPFORMS_DEBUG' ) && WPFORMS_DEBUG ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			error_log( $message );
			wpforms_log( 'Forms Locator', $message, [ 'type' => 'log' ] );
		}
	}
}
