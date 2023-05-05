<?php

namespace WPForms\Admin\Tools\Views;

use WPForms\Admin\Tools\Importers;

/**
 * Class Importer.
 *
 * @since 1.6.6
 */
class Importer extends View {

	/**
	 * View slug.
	 *
	 * @since 1.6.6
	 *
	 * @var string
	 */
	protected $slug = 'import';

	/**
	 * Registered importers.
	 *
	 * @since 1.6.6
	 *
	 * @var array
	 */
	public $importers = [];

	/**
	 * Available forms for a specific importer.
	 *
	 * @since 1.6.6
	 *
	 * @var array
	 */
	public $importer_forms = [];

	/**
	 * Init view.
	 *
	 * @since 1.6.6
	 */
	public function init() {

		$importers = new Importers();

		$this->importers = $importers->get_importers();

		if ( ! empty( $_GET['provider'] ) ) { //phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$this->importer_forms = $importers->get_importer_forms( sanitize_key( $_GET['provider'] ) );//phpcs:ignore WordPress.Security.NonceVerification.Recommended
		}

		// Load the Underscores templates for importers.
		add_action( 'admin_print_scripts', [ $this, 'importer_templates' ] );
	}

	/**
	 * Get view label.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 */
	public function get_label() {

		return '';
	}

	/**
	 * Checking user capability to view.
	 *
	 * @since 1.6.6
	 *
	 * @return bool
	 */
	public function check_capability() {

		return wpforms_current_user_can( 'create_forms' );
	}

	/**
	 * Checking if needs display in navigation.
	 *
	 * @since 1.6.6
	 *
	 * @return bool
	 */
	public function hide_from_nav() {

		return true;
	}

	/**
	 * Importer view content.
	 *
	 * @since 1.6.6
	 */
	public function display() {

		$this->heading_block();

		$this->forms_block();

		$this->analyze_block();

		$this->process_block();
	}

	/**
	 * Get provider.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 */
	private function get_provider_name() {

		//phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$slug = ! empty( $_GET['provider'] ) ? sanitize_key( $_GET['provider'] ) : '';

		return isset( $this->importers[ $slug ] ) ? $this->importers[ $slug ]['name'] : '';
	}

	/**
	 * Heading block.
	 *
	 * @since 1.6.6
	 */
	private function heading_block() {
		?>

		<div class="wpforms-setting-row tools wpforms-clear section-heading no-desc">
			<div class="wpforms-setting-field">
				<h4><?php esc_html_e( 'Form Import', 'wpforms-lite' ); ?></h4>
			</div>
		</div>
		<?php
	}

	/**
	 * Forms block.
	 *
	 * @since 1.6.6
	 */
	private function forms_block() {
		?>

		<div id="wpforms-importer-forms">
			<div class="wpforms-setting-row tools">
				<p><?php esc_html_e( 'Select the forms you would like to import.', 'wpforms-lite' ); ?></p>

				<div class="checkbox-multiselect-columns">
					<div class="first-column">
						<h5 class="header"><?php esc_html_e( 'Available Forms', 'wpforms-lite' ); ?></h5>

						<ul>
							<?php
							if ( empty( $this->importer_forms ) ) {
								echo '<li>' . esc_html__( 'No forms found.', 'wpforms-lite' ) . '</li>';
							} else {
								foreach ( $this->importer_forms as $id => $form ) {
									printf(
										'<li><label><input type="checkbox" name="forms[]" value="%s">%s</label></li>',
										esc_attr( $id ),
										esc_attr( sanitize_text_field( $form ) )
									);
								}
							}
							?>
						</ul>

						<?php if ( ! empty( $this->importer_forms ) ) : ?>
							<a href="#" class="all"><?php esc_html_e( 'Select All', 'wpforms-lite' ); ?></a>
						<?php endif; ?>

					</div>
					<div class="second-column">
						<h5 class="header"><?php esc_html_e( 'Forms to Import', 'wpforms-lite' ); ?></h5>
						<ul></ul>
					</div>
				</div>
			</div>

			<?php if ( ! empty( $this->importer_forms ) ) : ?>
				<p class="submit">
					<button class="wpforms-btn wpforms-btn-md wpforms-btn-orange"
							id="wpforms-importer-forms-submit"><?php esc_html_e( 'Import', 'wpforms-lite' ); ?></button>
				</p>
			<?php endif; ?>
		</div>
	<?php
	}

	/**
	 * Analyze block.
	 *
	 * @since 1.6.6
	 */
	private function analyze_block() {
		?>

		<div id="wpforms-importer-analyze">
			<p class="process-analyze">
				<i class="fa fa-spinner fa-spin" aria-hidden="true"></i>
				<?php
				printf(
					wp_kses( /* translators: %s - Provider name. */
						__( 'Analyzing <span class="form-current">1</span> of <span class="form-total">0</span> forms from %s.', 'wpforms-lite' ),
						[
							'span' => [
								'class' => [],
							],
						]
					),
					esc_attr( sanitize_text_field( $this->get_provider_name() ) )
				);
				?>
			</p>
			<div class="upgrade">
				<h5><?php esc_html_e( 'Heads up!', 'wpforms-lite' ); ?></h5>
				<p><?php esc_html_e( 'One or more of your forms contain fields that are not available in WPForms Lite. To properly import these fields, we recommend upgrading to WPForms Pro.', 'wpforms-lite' ); ?></p>
				<p><?php esc_html_e( 'You can continue with the import without upgrading, and we will do our best to match the fields. However, some of them will be omitted due to compatibility issues.', 'wpforms-lite' ); ?></p>
				<p>
					<a href="<?php echo esc_url( wpforms_admin_upgrade_link( 'tools-import' ) ); ?>" target="_blank"
					   rel="noopener noreferrer"
					   class="wpforms-btn wpforms-btn-md wpforms-btn-orange wpforms-upgrade-modal"><?php esc_html_e( 'Upgrade to WPForms Pro', 'wpforms-lite' ); ?></a>
					<a href="#" class="wpforms-btn wpforms-btn-md wpforms-btn-light-grey"
					   id="wpforms-importer-continue-submit"><?php esc_html_e( 'Continue Import without Upgrading', 'wpforms-lite' ); ?></a>
				</p>
				<hr>
				<p><?php esc_html_e( 'Below is the list of form fields that may be impacted:', 'wpforms-lite' ); ?></p>
			</div>
		</div>
	<?php
	}

	/**
	 * Process block.
	 *
	 * @since 1.6.6
	 */
	private function process_block() {
		?>

		<div id="wpforms-importer-process">

			<p class="process-count">
				<i class="fa fa-spinner fa-spin" aria-hidden="true"></i>
				<?php
				printf(
					wp_kses( /* translators: %s - Provider name. */
						__( 'Importing <span class="form-current">1</span> of <span class="form-total">0</span> forms from %s.', 'wpforms-lite' ),
						[
							'span' => [
								'class' => [],
							],
						]
					),
					esc_attr( sanitize_text_field( $this->get_provider_name() ) )
				);
				?>
			</p>

			<p class="process-completed">
				<?php
				echo wp_kses(
					__( 'Congrats, the import process has finished! We have successfully imported <span class="forms-completed"></span> forms. You can review the results below.', 'wpforms-lite' ),
					[
						'span' => [
							'class' => [],
						],
					]
				);
				?>
			</p>
			<div class="status"></div>
		</div>
	<?php
	}


	/**
	 * Various Underscores templates for form importing.
	 *
	 * @since 1.6.6
	 */
	public function importer_templates() {
		?>

		<script type="text/html" id="tmpl-wpforms-importer-upgrade">
			<# _.each( data, function( item, key ) { #>
				<ul>
					<li class="form">{{ item.name }}</li>
					<# _.each( item.fields, function( val, key ) { #>
						<li>{{ val }}</li>
						<# }) #>
				</ul>
				<# }) #>
		</script>
		<script type="text/html" id="tmpl-wpforms-importer-status-error">
			<div class="item">
				<div class="wpforms-clear">
					<span class="name">
						<i class="status-icon fa fa-times" aria-hidden="true"></i>
						{{ data.name }}
					</span>
				</div>
				<p>{{ data.msg }}</p>
			</div>
		</script>
		<script type="text/html" id="tmpl-wpforms-importer-status-update">
			<div class="item">
				<div class="wpforms-clear">
					<span class="name">
						<# if ( ! _.isEmpty( data.upgrade_omit ) ) { #>
							<i class="status-icon fa fa-exclamation-circle" aria-hidden="true"></i>
						<# } else if ( ! _.isEmpty( data.upgrade_plain ) ) { #>
							<i class="status-icon fa fa-exclamation-triangle" aria-hidden="true"></i>
						<# } else if ( ! _.isEmpty( data.unsupported ) ) { #>
							<i class="status-icon fa fa-info-circle" aria-hidden="true"></i>
						<# } else { #>
							<i class="status-icon fa fa-check" aria-hidden="true"></i>
						<# } #>
						{{ data.name }}
					</span>
					<span class="actions">
						<a href="{{ data.edit }}" target="_blank"><?php esc_html_e( 'Edit', 'wpforms-lite' ); ?></a>
						<span class="sep">|</span>
						<a href="{{ data.preview }}" target="_blank"><?php esc_html_e( 'Preview', 'wpforms-lite' ); ?></a>
					</span>
				</div>
				<# if ( ! _.isEmpty( data.upgrade_omit ) ) { #>
					<p><?php esc_html_e( 'The following fields are available in PRO and were not imported:', 'wpforms-lite' ); ?></p>
					<ul>
						<# _.each( data.upgrade_omit, function( val, key ) { #>
							<li>{{ val }}</li>
							<# }) #>
					</ul>
					<# } #>
						<# if ( ! _.isEmpty( data.upgrade_plain ) ) { #>
							<p><?php esc_html_e( 'The following fields are available in PRO and were imported as text fields:', 'wpforms-lite' ); ?></p>
							<ul>
								<# _.each( data.upgrade_plain, function( val, key ) { #>
									<li>{{ val }}</li>
									<# }) #>
							</ul>
							<# } #>
								<# if ( ! _.isEmpty( data.unsupported ) ) { #>
									<p><?php esc_html_e( 'The following fields are not supported and were not imported:', 'wpforms-lite' ); ?></p>
									<ul>
										<# _.each( data.unsupported, function( val, key ) { #>
											<li>{{ val }}</li>
											<# }) #>
									</ul>
									<# } #>
										<# if ( ! _.isEmpty( data.upgrade_plain ) || ! _.isEmpty( data.upgrade_omit ) ) { #>
											<p>
												<?php esc_html_e( 'Upgrade to the PRO plan to import these fields.', 'wpforms-lite' ); ?><br><br>
												<a href="<?php echo esc_url( wpforms_admin_upgrade_link( 'tools-import' ) ); ?>" class="wpforms-btn wpforms-btn-orange wpforms-btn-md wpforms-upgrade-modal" target="_blank" rel="noopener noreferrer">
													<?php esc_html_e( 'Upgrade Now', 'wpforms-lite' ); ?>
												</a>
											</p>
											<# } #>
			</div>
		</script>
		<?php
	}

}
