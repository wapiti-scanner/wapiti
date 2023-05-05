<?php

namespace WPForms\Tasks;

/**
 * Class Task.
 *
 * @since 1.5.9
 */
class Task {

	/**
	 * This task is async (runs asap).
	 *
	 * @since 1.5.9
	 */
	const TYPE_ASYNC = 'async';

	/**
	 * This task is a recurring.
	 *
	 * @since 1.5.9
	 */
	const TYPE_RECURRING = 'scheduled';

	/**
	 * This task is run once.
	 *
	 * @since 1.5.9
	 */
	const TYPE_ONCE = 'once';

	/**
	 * Type of the task.
	 *
	 * @since 1.5.9
	 *
	 * @var string
	 */
	private $type;

	/**
	 * Action that will be used as a hook.
	 *
	 * @since 1.5.9
	 *
	 * @var string
	 */
	private $action;

	/**
	 * Task meta ID.
	 *
	 * @since 1.5.9
	 *
	 * @var int
	 */
	private $meta_id;

	/**
	 * All the params that should be passed to the hook.
	 *
	 * @since 1.5.9
	 *
	 * @var array
	 */
	private $params;

	/**
	 * When the first instance of the job will run.
	 * Used for ONCE ane RECURRING tasks.
	 *
	 * @since 1.5.9
	 *
	 * @var int
	 */
	private $timestamp;

	/**
	 * How long to wait between runs.
	 * Used for RECURRING tasks.
	 *
	 * @since 1.5.9
	 *
	 * @var int
	 */
	private $interval;

	/**
	 * Task meta.
	 *
	 * @since 1.7.0
	 *
	 * @var Meta
	 */
	private $meta;

	/**
	 * Task constructor.
	 *
	 * @since 1.5.9
	 *
	 * @param string $action Action of the task.
	 *
	 * @throws \InvalidArgumentException When action is not a string.
	 * @throws \UnexpectedValueException When action is empty.
	 */
	public function __construct( $action ) {

		if ( ! is_string( $action ) ) {
			throw new \InvalidArgumentException( 'Task action should be a string.' );
		}

		$this->action = sanitize_key( $action );
		$this->meta   = new Meta();

		if ( empty( $this->action ) ) {
			throw new \UnexpectedValueException( 'Task action cannot be empty.' );
		}
	}

	/**
	 * Define the type of the task as async.
	 *
	 * @since 1.5.9
	 *
	 * @return \WPForms\Tasks\Task
	 */
	public function async() {

		$this->type = self::TYPE_ASYNC;

		return $this;
	}

	/**
	 * Define the type of the task as recurring.
	 *
	 * @since 1.5.9
	 *
	 * @param int $timestamp When the first instance of the job will run.
	 * @param int $interval  How long to wait between runs.
	 *
	 * @return \WPForms\Tasks\Task
	 */
	public function recurring( $timestamp, $interval ) {

		$this->type      = self::TYPE_RECURRING;
		$this->timestamp = (int) $timestamp;
		$this->interval  = (int) $interval;

		return $this;
	}

	/**
	 * Define the type of the task as one-time.
	 *
	 * @since 1.5.9
	 *
	 * @param int $timestamp When the first instance of the job will run.
	 *
	 * @return \WPForms\Tasks\Task
	 */
	public function once( $timestamp ) {

		$this->type      = self::TYPE_ONCE;
		$this->timestamp = (int) $timestamp;

		return $this;
	}

	/**
	 * Pass any number of params that should be saved to Meta table.
	 *
	 * @since 1.5.9
	 *
	 * @return \WPForms\Tasks\Task
	 */
	public function params() {

		$this->params = func_get_args();

		return $this;
	}

	/**
	 * Register the action.
	 * Should be the final call in a chain.
	 *
	 * @since 1.5.9
	 *
	 * @return null|string Action ID.
	 */
	public function register() {

		$action_id = null;

		// No processing if ActionScheduler is not usable.
		if ( ! wpforms()->get( 'tasks' )->is_usable() ) {
			return $action_id;
		}

		// Save data to tasks meta table.
		if ( $this->params !== null ) {
			$this->meta_id = $this->meta->add(
				[
					'action' => $this->action,
					'data'   => $this->params,
				]
			);

			if ( empty( $this->meta_id ) ) {
				return $action_id;
			}
		}

		// Prevent 500 errors when Action Scheduler tables don't exist.
		try {

			switch ( $this->type ) {
				case self::TYPE_ASYNC:
					$action_id = $this->register_async();
					break;

				case self::TYPE_RECURRING:
					$action_id = $this->register_recurring();
					break;

				case self::TYPE_ONCE:
					$action_id = $this->register_once();
					break;
			}
		} catch ( \RuntimeException $exception ) {
			$action_id = null;
		}

		return $action_id;
	}

	/**
	 * Register the async task.
	 *
	 * @since 1.5.9
	 *
	 * @return null|string Action ID.
	 */
	protected function register_async() {

		if ( ! function_exists( 'as_enqueue_async_action' ) ) {
			return null;
		}

		return as_enqueue_async_action(
			$this->action,
			[ 'tasks_meta_id' => $this->meta_id ],
			Tasks::GROUP
		);
	}

	/**
	 * Register the recurring task.
	 *
	 * @since 1.5.9
	 *
	 * @return null|string Action ID.
	 */
	protected function register_recurring() {

		if ( ! function_exists( 'as_schedule_recurring_action' ) ) {
			return null;
		}

		return as_schedule_recurring_action(
			$this->timestamp,
			$this->interval,
			$this->action,
			[ 'tasks_meta_id' => $this->meta_id ],
			Tasks::GROUP
		);
	}

	/**
	 * Register the one-time task.
	 *
	 * @since 1.5.9
	 *
	 * @return null|string Action ID.
	 */
	protected function register_once() {

		if ( ! function_exists( 'as_schedule_single_action' ) ) {
			return null;
		}

		return as_schedule_single_action(
			$this->timestamp,
			$this->action,
			[ 'tasks_meta_id' => $this->meta_id ],
			Tasks::GROUP
		);
	}

	/**
	 * Cancel all occurrences of this task.
	 *
	 * @since 1.6.1
	 *
	 * @return null|bool|string Null if no matching action found,
	 *                          false if AS library is missing,
	 *                          true if scheduled task has no params,
	 *                          string of the scheduled action ID if a scheduled action was found and unscheduled.
	 */
	public function cancel() {

		if ( ! function_exists( 'as_unschedule_all_actions' ) ) {
			return false;
		}

		if ( $this->params === null ) {
			as_unschedule_all_actions( $this->action );

			return true;
		}

		$this->meta_id = $this->meta->get_meta_id( $this->action, $this->params );

		if ( $this->meta_id === null ) {
			return null;
		}

		return as_unschedule_action( $this->action, [ 'tasks_meta_id' => $this->meta_id ], Tasks::GROUP );
	}
}
