<?php

namespace WPForms\Admin\Tools\Views;

use WPForms\Logger\Log;

/**
 * Class Logs.
 *
 * @since 1.6.6
 */
class Logs extends View {

	/**
	 * View slug.
	 *
	 * @since 1.6.6
	 *
	 * @var string
	 */
	protected $slug = 'logs';

	/**
	 * ListTable instance.
	 *
	 * @since 1.6.6
	 *
	 * @var \WPForms\Logger\ListTable
	 */
	private $list_table = [];

	/**
	 * Init view.
	 *
	 * @since 1.6.6
	 */
	public function init() {

		$this->logs_controller();
	}

	/**
	 * Get view label.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 */
	public function get_label() {

		return esc_html__( 'Logs', 'wpforms-lite' );
	}

	/**
	 * Checking user capability to view.
	 *
	 * @since 1.6.6
	 *
	 * @return bool
	 */
	public function check_capability() {

		return wpforms_current_user_can();
	}

	/**
	 * Get ListTable instance.
	 *
	 * @since 1.6.6
	 *
	 * @return \WPForms\Logger\ListTable
	 */
	private function get_list_table() {

		if ( empty( $this->list_table ) ) {
			$this->list_table = wpforms()->get( 'log' )->get_list_table();
		}

		return $this->list_table;
	}

	/**
	 * Display view content.
	 *
	 * @since 1.6.6
	 */
	public function display() {
		?>

		<form action="<?php echo esc_url( $this->get_link() ); ?>" method="POST">
			<?php $this->nonce_field(); ?>
			<div class="wpforms-setting-row tools">
				<h4><?php esc_html_e( 'Logs', 'wpforms-lite' ); ?></h4>
				<p><?php esc_html_e( 'On this page, you can enable and configure the logging functionality while debugging behavior of various parts of the plugin, including forms and entries processing.', 'wpforms-lite' ); ?></p>
			</div>
			<div class="wpforms-setting-row tools wpforms-setting-row-checkbox wpforms-clear"
				 id="wpforms-setting-row-logs-enable">
				<div class="wpforms-setting-label">
					<label
						for="wpforms-setting-logs-enable"><?php esc_html_e( 'Enable Logs', 'wpforms-lite' ); ?></label>
				</div>
				<div class="wpforms-setting-field">
					<input type="checkbox" id="wpforms-setting-logs-enable" name="logs-enable" value="1"
						<?php checked( wpforms_setting( 'logs-enable' ) ); ?>>
					<p class="desc">
						<?php esc_html_e( 'Check this option to start logging WPForms-related events. This is recommended only while debugging.', 'wpforms-lite' ); ?>
					</p>
				</div>
			</div>
			<?php
			if ( wpforms_setting( 'logs-enable' ) ) {

				$this->types_block();

				$this->user_roles_block();

				$this->users_block();

			}
			?>
			<p class="submit">
				<button class="wpforms-btn wpforms-btn-md wpforms-btn-orange" name="wpforms-settings-submit">
					<?php esc_html_e( 'Save Settings', 'wpforms-lite' ); ?>
				</button>
			</p>
		</form>

		<?php
		$logs_list_table = $this->get_list_table();

		if ( wpforms_setting( 'logs-enable' ) || $logs_list_table->get_total() ) {
			$logs_list_table->display_page();
		}
	}

	/**
	 * Types block.
	 *
	 * @since 1.6.6
	 */
	private function types_block() {
		?>

		<div class="wpforms-setting-row tools wpforms-setting-row-select wpforms-clear"
			 id="wpforms-setting-row-log-types">
			<div class="wpforms-setting-label">
				<label for="wpforms-setting-logs-types"><?php esc_html_e( 'Log Types', 'wpforms-lite' ); ?></label>
			</div>
			<div class="wpforms-setting-field">
				<span class="choicesjs-select-wrap">
					<select id="wpforms-setting-logs-types" class="choicesjs-select" name="logs-types[]" multiple>
						<?php
						$log_types = wpforms_setting( 'logs-types', [] );

						foreach ( Log::get_log_types() as $slug => $name ) {
							?>
							<option value="<?php echo esc_attr( $slug ); ?>" <?php selected( in_array( $slug, $log_types, true ) ); ?> >
								<?php echo esc_html( $name ); ?>
							</option>
						<?php } ?>
					</select>
				</span>
				<p class="desc"><?php esc_html_e( 'Select the types of events you want to log. Everything is logged by default.', 'wpforms-lite' ); ?></p>
			</div>
		</div>
	<?php
	}

	/**
	 * User roles block.
	 *
	 * @since 1.6.6
	 */
	private function user_roles_block() {
		?>

		<div class="wpforms-setting-row tools wpforms-setting-row-select wpforms-clear"
			 id="wpforms-setting-row-log-user-roles">
			<div class="wpforms-setting-label">
				<label for="wpforms-setting-logs-user-roles"><?php esc_html_e( 'User Roles', 'wpforms-lite' ); ?></label>
			</div>
			<div class="wpforms-setting-field">
				<span class="choicesjs-select-wrap">
					<?php
					$logs_user_roles = wpforms_setting( 'logs-user-roles', [] );
					$roles           = wp_list_pluck( get_editable_roles(), 'name' );

					?>
					<select id="wpforms-setting-logs-user-roles" class="choicesjs-select" name="logs-user-roles[]" multiple>
						<?php foreach ( $roles as $slug => $name ) { ?>
							<option value="<?php echo esc_attr( $slug ); ?>" <?php selected( in_array( $slug, $logs_user_roles, true ) ); ?> >
								<?php echo esc_html( $name ); ?>
							</option>
						<?php } ?>
					</select>
					<span class="hidden" id="wpforms-setting-logs-user-roles-selectform-spinner">
						<i class="fa fa-cog fa-spin fa-lg"></i>
					</span>
				</span>
				<p class="desc">
					<?php esc_html_e( 'Select the user roles you want to log. All roles are logged by default.', 'wpforms-lite' ); ?>
				</p>
			</div>
		</div>
	<?php
	}

	/**
	 * Users block.
	 *
	 * @since 1.6.6
	 */
	private function users_block() {
		?>

		<div class="wpforms-setting-row tools wpforms-setting-row-select wpforms-clear"
			 id="wpforms-setting-row-log-users">
			<div class="wpforms-setting-label">
				<label for="wpforms-setting-logs-users"><?php esc_html_e( 'Users', 'wpforms-lite' ); ?></label>
			</div>
			<div class="wpforms-setting-field">
				<span class="choicesjs-select-wrap">
					<select id="wpforms-setting-logs-users" class="choicesjs-select" name="logs-users[]" multiple>
						<?php
						$users      = get_users( [ 'fields' => [ 'ID', 'display_name' ] ] );
						$users      = wp_list_pluck( $users, 'display_name', 'ID' );
						$logs_users = wpforms_setting( 'logs-users', [] );

						foreach ( $users as $slug => $name ) {
							?>
							<option value="<?php echo esc_attr( $slug ); ?>" <?php selected( in_array( $slug, $logs_users, true ) ); ?> >
								<?php echo esc_html( $name ); ?>
							</option>
						<?php } ?>
					</select>
					<span class="hidden" id="wpforms-setting-logs-users-selectform-spinner">
						<i class="fa fa-cog fa-spin fa-lg"></i>
					</span>
				</span>
				<p class="desc">
					<?php esc_html_e( 'Log events for specific users only. All users are logged by default.', 'wpforms-lite' ); ?>
				</p>
			</div>
		</div>
	<?php
	}

	/**
	 * Controller.
	 *
	 * @since 1.6.6
	 */
	private function logs_controller() {

		$log = wpforms()->get( 'log' );

		$log->create_table();
		if ( $this->verify_nonce() ) {
			$settings                = get_option( 'wpforms_settings' );
			$was_enabled             = ! empty( $settings['logs-enable'] ) ? $settings['logs-enable'] : 0;
			$settings['logs-enable'] = filter_input( INPUT_POST, 'logs-enable', FILTER_VALIDATE_BOOLEAN );
			$logs_types              = filter_input( INPUT_POST, 'logs-types', FILTER_SANITIZE_FULL_SPECIAL_CHARS, FILTER_REQUIRE_ARRAY );
			$logs_user_roles         = filter_input( INPUT_POST, 'logs-user-roles', FILTER_SANITIZE_FULL_SPECIAL_CHARS, FILTER_REQUIRE_ARRAY );
			$logs_users              = filter_input( INPUT_POST, 'logs-users', FILTER_SANITIZE_NUMBER_INT, FILTER_REQUIRE_ARRAY );

			if ( $was_enabled ) {
				$settings['logs-types']      = $logs_types ? $logs_types : [];
				$settings['logs-user-roles'] = $logs_user_roles ? $logs_user_roles : [];
				$settings['logs-users']      = $logs_users ? array_map( 'absint', $logs_users ) : [];
			}

			wpforms_update_settings( $settings );
		}

		$logs_list_table = $this->get_list_table();

		$logs_list_table->process_admin_ui();
	}

}
