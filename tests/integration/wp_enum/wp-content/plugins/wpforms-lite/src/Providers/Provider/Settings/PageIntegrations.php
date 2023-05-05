<?php

namespace WPForms\Providers\Provider\Settings;

use WPForms\Providers\Provider\Core;

/**
 * Class PageIntegrations handles the WPForms -> Settings -> Integrations page.
 *
 * @since 1.4.7
 */
abstract class PageIntegrations implements PageIntegrationsInterface {

	/**
	 * Get the Core loader class of a provider.
	 *
	 * @since 1.4.7
	 *
	 * @var Core
	 */
	protected $core;

	/**
	 * Integrations constructor.
	 *
	 * @since 1.4.7
	 *
	 * @param Core $core Core provider object.
	 */
	public function __construct( Core $core ) {
		$this->core = $core;

		$this->ajax();
	}

	/**
	 * Process the default ajax functionality.
	 *
	 * @since 1.4.7
	 */
	protected function ajax() {

		// Remove provider from Settings Integrations tab.
		add_action( "wp_ajax_wpforms_settings_provider_disconnect_{$this->core->slug}", [ $this, 'ajax_disconnect' ] );

		// Add new provider from Settings Integrations tab.
		add_action( "wp_ajax_wpforms_settings_provider_add_{$this->core->slug}", [ $this, 'ajax_connect' ] );
	}

	/**
	 * @inheritdoc
	 */
	public function display( $active, $settings ) {

		$connected = ! empty( $active[ $this->core->slug ] );
		$accounts  = ! empty( $settings[ $this->core->slug ] ) ? $settings[ $this->core->slug ] : [];
		$class     = $connected && $accounts ? 'connected' : '';
		$arrow     = 'right';

		// This lets us highlight a specific service by a special link.
		if ( ! empty( $_GET['wpforms-integration'] ) ) { //phpcs:ignore
			if ( $this->core->slug === $_GET['wpforms-integration'] ) { //phpcs:ignore
				$class .= ' focus-in';
				$arrow  = 'down';
			} else {
				$class .= ' focus-out';
			}
		}
		?>

		<div id="wpforms-integration-<?php echo \esc_attr( $this->core->slug ); ?>"
			class="wpforms-settings-provider wpforms-clear <?php echo \esc_attr( $this->core->slug ); ?> <?php echo \esc_attr( $class ); ?>">

			<div class="wpforms-settings-provider-header wpforms-clear" data-provider="<?php echo \esc_attr( $this->core->slug ); ?>">

				<div class="wpforms-settings-provider-logo">
					<i title="<?php \esc_attr_e( 'Show Accounts', 'wpforms-lite' ); ?>" class="fa fa-chevron-<?php echo \esc_attr( $arrow ); ?>"></i>
					<img src="<?php echo \esc_url( $this->core->icon ); ?>">
				</div>

				<div class="wpforms-settings-provider-info">
					<h3><?php echo \esc_html( $this->core->name ); ?></h3>
					<p>
						<?php
						/* translators: %s - provider name. */
						\printf( \esc_html__( 'Integrate %s with WPForms', 'wpforms-lite' ), \esc_html( $this->core->name ) );
						?>
					</p>
					<span class="connected-indicator green"><i class="fa fa-check-circle-o"></i>&nbsp;<?php \esc_html_e( 'Connected', 'wpforms-lite' ); ?></span>
				</div>

			</div>

			<div class="wpforms-settings-provider-accounts" id="provider-<?php echo \esc_attr( $this->core->slug ); ?>">

				<div class="wpforms-settings-provider-accounts-list">
					<ul>
						<?php
						if ( ! empty( $accounts ) ) {
							foreach ( $accounts as $account_id => $account ) {
								if ( empty( $account_id ) ) {
									continue;
								}

								$this->display_connected_account( $account_id, $account );
							}
						}
						?>
					</ul>
				</div>

				<?php $this->display_add_new(); ?>

			</div>

		</div>

		<?php
	}

	/**
	 * Display connected account.
	 *
	 * @since 1.7.5
	 *
	 * @param string $account_id Account ID.
	 * @param array  $account    Account data.
	 */
	protected function display_connected_account( $account_id, $account ) {

		$account_connected = ! empty( $account['date'] )
			? wpforms_date_format( $account['date'] )
			: esc_html__( 'N/A', 'wpforms-lite' );

		echo '<li class="wpforms-clear">';

		/**
		 * Allow adding markup before connected account item.
		 *
		 * @since 1.7.5
		 *
		 * @param string $account_id Account ID.
		 * @param array  $account    Account data.
		 */
		do_action( 'wpforms_providers_provider_settings_page_integrations_display_connected_account_item_before', $account_id, $account );

		echo '<span class="label">';
		echo ! empty( $account['label'] ) ? esc_html( $account['label'] ) : '<em>' . esc_html__( 'No Label', 'wpforms-lite' ) . '</em>';
		echo '</span>';

		/* translators: %s - Connection date. */
		echo '<span class="date">' . sprintf( esc_html__( 'Connected on: %s', 'wpforms-lite' ), esc_html( $account_connected ) ) . '</span>';
		echo '<span class="remove"><a href="#" data-provider="' . esc_attr( $this->core->slug ) . '" data-key="' . esc_attr( $account_id ) . '">' . esc_html__( 'Disconnect', 'wpforms-lite' ) . '</a></span>';

		/**
		 * Allow adding markup after connected account item.
		 *
		 * @since 1.7.5
		 *
		 * @param string $account_id Account ID.
		 * @param array  $account    Account data.
		 */
		do_action( 'wpforms_providers_provider_settings_page_integrations_display_connected_account_item_after', $account_id, $account );

		echo '</li>';
	}

	/**
	 * Any new connection should be added.
	 * So display the content of that.
	 *
	 * @since 1.4.7
	 */
	protected function display_add_new() {

		?>

		<p class="wpforms-settings-provider-accounts-toggle">
			<a class="wpforms-btn wpforms-btn-md wpforms-btn-light-grey" href="#" data-provider="<?php echo esc_attr( $this->core->slug ); ?>">
				<i class="fa fa-plus"></i> <?php esc_html_e( 'Add New Account', 'wpforms-lite' ); ?>
			</a>
		</p>

		<div class="wpforms-settings-provider-accounts-connect">

			<form>
				<p><?php esc_html_e( 'Please fill out all of the fields below to add your new provider account.', 'wpforms-lite' ); ?></span></p>

				<p class="wpforms-settings-provider-accounts-connect-fields">
					<?php $this->display_add_new_connection_fields(); ?>
				</p>

				<?php $this->display_add_new_connection_submit_button(); ?>
			</form>
		</div>

		<?php
	}

	/**
	 * Some providers may or may not have fields.
	 *
	 * @since 1.4.7
	 */
	protected function display_add_new_connection_fields() {
	}

	/**
	 * Some providers may modify the form button and add their form handler.
	 *
	 * @since 1.7.4
	 */
	protected function display_add_new_connection_submit_button() {

		/* translators: %s - provider name. */
		$title = sprintf( __( 'Connect to %s', 'wpforms-lite' ), $this->core->name );
		?>
		<button type="submit" class="wpforms-btn wpforms-btn-md wpforms-btn-orange wpforms-settings-provider-connect"
				data-provider="<?php echo esc_attr( $this->core->slug ); ?>" title="<?php echo esc_attr( $title ); ?>">
			<?php echo esc_html( $title ); ?>
		</button>
		<?php
	}

	/**
	 * AJAX to disconnect a provider from the settings integrations tab.
	 *
	 * @since 1.4.7
	 */
	public function ajax_disconnect() {

		// Run a security check.
		if ( ! \check_ajax_referer( 'wpforms-admin', 'nonce', false ) ) {
			\wp_send_json_error(
				[
					'error_msg' => \esc_html__( 'Your session expired. Please reload the page.', 'wpforms-lite' ),
				]
			);
		}

		// Check for permissions.
		if ( ! \wpforms_current_user_can() ) {
			\wp_send_json_error(
				[
					'error_msg' => \esc_html__( 'You do not have permission.', 'wpforms-lite' ),
				]
			);
		}

		if ( empty( $_POST['provider'] ) || empty( $_POST['key'] ) ) {
			\wp_send_json_error(
				[
					'error_msg' => \esc_html__( 'Missing data.', 'wpforms-lite' ),
				]
			);
		}

		$providers = \wpforms_get_providers_options();

		if ( ! empty( $providers[ $_POST['provider'] ][ $_POST['key'] ] ) ) {

			unset( $providers[ $_POST['provider'] ][ $_POST['key'] ] );
			\update_option( 'wpforms_providers', $providers );
			\wp_send_json_success();

		} else {
			\wp_send_json_error(
				[
					'error_msg' => \esc_html__( 'Connection missing.', 'wpforms-lite' ),
				]
			);
		}
	}

	/**
	 * AJAX to add a provider from the settings integrations tab.
	 *
	 * @since 1.4.7
	 */
	public function ajax_connect() {

		// Run a security check.
		if ( ! \check_ajax_referer( 'wpforms-admin', 'nonce', false ) ) {
			\wp_send_json_error(
				[
					'error_msg' => \esc_html__( 'Your session expired. Please reload the page.', 'wpforms-lite' ),
				]
			);
		}

		// Check for permissions.
		if ( ! \wpforms_current_user_can() ) {
			\wp_send_json_error(
				[
					'error_msg' => \esc_html__( 'You do not have permissions.', 'wpforms-lite' ),
				]
			);
		}

		if ( empty( $_POST['data'] ) ) {
			\wp_send_json_error(
				[
					'error_msg' => \esc_html__( 'Missing required data in payload.', 'wpforms-lite' ),
				]
			);
		}
	}
}
