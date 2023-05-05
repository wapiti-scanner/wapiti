<?php

namespace WPForms\Admin\Tools\Views;

use ActionScheduler as Scheduler;
use ActionScheduler_ListTable;

/**
 * Action Scheduler list table.
 *
 * @since 1.7.6
 */
class ActionSchedulerList extends ActionScheduler_ListTable {

	/**
	 * ActionSchedulerList constructor.
	 *
	 * @since 1.7.6
	 */
	public function __construct() {

		parent::__construct(
			Scheduler::store(),
			Scheduler::logger(),
			Scheduler::runner()
		);

		$this->process_actions();
	}

	/**
	 * Display the table heading.
	 *
	 * @since 1.7.6
	 */
	protected function display_header() {

		?>
		<h1><?php echo esc_html__( 'Scheduled Actions', 'wpforms-lite' ); ?></h1>

		<p>
			<?php
			echo sprintf(
				wp_kses( /* translators: %s - Action Scheduler website URL. */
					__( 'WPForms is using the <a href="%s" target="_blank" rel="noopener noreferrer">Action Scheduler</a> library, which allows it to queue and process bigger tasks in the background without making your site slower for your visitors. Below you can see the list of all tasks and their status. This table can be very useful when debugging certain issues.', 'wpforms-lite' ),
					[
						'a' => [
							'href'   => [],
							'rel'    => [],
							'target' => [],
						],
					]
				),
				'https://actionscheduler.org/'
			);
			?>
		</p>

		<p>
			<?php echo esc_html__( 'Action Scheduler library is also used by other plugins, like WP Mail SMTP and WooCommerce, so you might see tasks that are not related to our plugin in the table below.', 'wpforms-lite' ); ?>
		</p>

		<?php
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! empty( $_GET['s'] ) ) {
			?>
			<div id="wpforms-reset-filter">
				<?php
				echo wp_kses(
					sprintf( /* translators: %s - search term. */
						__( 'Search results for <strong>%s</strong>', 'wpforms-lite' ),
						// phpcs:ignore WordPress.Security.NonceVerification.Recommended
						sanitize_text_field( wp_unslash( $_GET['s'] ) )
					),
					[
						'strong' => [],
					]
				);
				?>
				<a href="<?php echo esc_url( remove_query_arg( 's' ) ); ?>">
					<span class="reset fa fa-times-circle"></span>
				</a>
			</div>
			<?php
		}
	}
}
