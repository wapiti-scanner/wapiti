<?php // phpcs:ignore WordPress.Files.FileName
/**
 * VideoPress CLI
 *
 * @package automattic/jetpack
 */

if ( defined( 'WP_CLI' ) && WP_CLI ) {

	/**
	 * VideoPress command line utilities.
	 */
	class VideoPress_CLI extends WP_CLI_Command {
		/**
		 * Import a VideoPress Video
		 *
		 * ## OPTIONS
		 *
		 * <guid>: Import the video with the specified guid
		 *
		 * ## EXAMPLES
		 *
		 * wp videopress import kUJmAcSf
		 *
		 * @param array $args CLI arguments.
		 */
		public function import( $args ) {
			$guid          = $args[0];
			$attachment_id = create_local_media_library_for_videopress_guid( $guid );
			if ( $attachment_id && ! is_wp_error( $attachment_id ) ) {
				/* translators: %d: attachment id */
				WP_CLI::success( sprintf( __( 'The video has been imported as Attachment ID %d', 'jetpack' ), $attachment_id ) );
			} else {
				WP_CLI::error( __( 'An error has been encountered.', 'jetpack' ) );
			}
		}

		/**
		 * Manually runs the job to cleanup videos from the media library that failed during the upload process.
		 *
		 * ## EXAMPLES
		 *
		 * wp videopress cleanup_videos
		 */
		public function cleanup_videos() {
			$num_cleaned = videopress_cleanup_media_library();

			/* translators: %d: number of videos cleaned */
			WP_CLI::success( sprintf( _n( 'Cleaned up %d video.', 'Cleaned up a total of %d videos.', $num_cleaned, 'jetpack' ), $num_cleaned ) );
		}

		/**
		 * List out all of the crons that can be run.
		 *
		 * ## EXAMPLES
		 *
		 * wp videopress list_crons
		 */
		public function list_crons() {

			$scheduler = VideoPress_Scheduler::init();
			$crons     = $scheduler->get_crons();

			$schedules = wp_get_schedules();

			if ( count( $crons ) === 0 ) {
				WP_CLI::success( __( 'Found no available cron jobs.', 'jetpack' ) );

			} else {
				/* translators: %d is the number of crons */
				WP_CLI::success( sprintf( _n( 'Found %d available cron job.', 'Found %d available cron jobs.', count( $crons ), 'jetpack' ), count( $crons ) ) );
			}

			foreach ( $crons as $cron_name => $cron ) {
				$interval  = isset( $schedules[ $cron['interval'] ]['display'] ) ? $schedules[ $cron['interval'] ]['display'] : $cron['interval'];
				$runs_next = $scheduler->check_cron( $cron_name );
				$status    = $runs_next ? sprintf( 'Scheduled - Runs Next at %s GMT', gmdate( 'Y-m-d H:i:s', $runs_next ) ) : 'Not Scheduled';

				WP_CLI::log( 'Name: ' . $cron_name );
				WP_CLI::log( 'Method: ' . $cron['method'] );
				WP_CLI::log( 'Interval: ' . $interval );
				WP_CLI::log( 'Status: ' . $status );
			}
		}

		/**
		 * Checks for the current status of a cron job.
		 *
		 * ## OPTIONS
		 *
		 * <cron_name>: The name of the cron job to check
		 *
		 * ## EXAMPLES
		 *
		 * wp videopress cron_status cleanup
		 *
		 * @param array $args CLI args.
		 */
		public function cron_status( $args ) {

			if ( ! isset( $args[0] ) ) {
				return WP_CLI::error( __( 'You need to provide the name of the cronjob to schedule.', 'jetpack' ) );
			}

			$scheduler = VideoPress_Scheduler::init();

			if ( ! $scheduler->is_cron_valid( $args[0] ) ) {
				/* translators: name of a cron job */
				WP_CLI::error( sprintf( __( 'There is no cron named %s.', 'jetpack' ), $args[0] ) );
			}

			$time = $scheduler->check_cron( $args[0] );

			if ( ! $time ) {
				WP_CLI::success( __( 'The cron is not scheduled to run.', 'jetpack' ) );

			} else {
				/* translators: date/time */
				WP_CLI::success( sprintf( __( 'Cron will run at: %s GMT', 'jetpack' ), gmdate( 'Y-m-d H:i:s', $time ) ) );
			}
		}

		/**
		 * Actives the given cron job
		 *
		 * ## OPTIONS
		 *
		 * <cron_name>: The name of the cron job to check
		 *
		 * ## EXAMPLES
		 *
		 * wp videopress activate_cron cleanup
		 *
		 * @param array $args CLI args.
		 */
		public function activate_cron( $args ) {

			if ( ! isset( $args[0] ) ) {
				WP_CLI::error( __( 'You need to provide the name of the cronjob to schedule.', 'jetpack' ) );
			}

			$scheduler = VideoPress_Scheduler::init();

			if ( ! $scheduler->is_cron_valid( $args[0] ) ) {
				/* translators: name of a cron job */
				WP_CLI::error( sprintf( __( 'There is no cron named %s.', 'jetpack' ), $args[0] ) );
			}

			$scheduler->activate_cron( $args[0] );

			/* translators: name of a cron job */
			WP_CLI::success( sprintf( __( 'The cron named `%s` was scheduled.', 'jetpack' ), $args[0] ) );
		}

		/**
		 * Actives the given cron job
		 *
		 * ## OPTIONS
		 *
		 * <cron_name>: The name of the cron job to check
		 *
		 * ## EXAMPLES
		 *
		 * wp videopress deactivate_cron cleanup
		 *
		 * @param array $args CLI args.
		 */
		public function deactivate_cron( $args ) {

			if ( ! isset( $args[0] ) ) {
				WP_CLI::error( __( 'You need to provide the name of the cronjob to schedule.', 'jetpack' ) );
			}

			$scheduler = VideoPress_Scheduler::init();

			if ( ! $scheduler->is_cron_valid( $args[0] ) ) {
				/* translators: name of a cron job */
				WP_CLI::error( sprintf( __( 'There is no cron named %s.', 'jetpack' ), $args[0] ) );
			}

			$scheduler->deactivate_cron( $args[0] );

			/* translators: name of a cron job */
			WP_CLI::success( sprintf( __( 'The cron named `%s` was removed from the schedule.', 'jetpack' ), $args[0] ) );
		}
	}

	WP_CLI::add_command( 'videopress', 'VideoPress_CLI' );
}
