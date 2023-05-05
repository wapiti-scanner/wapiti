<?php

namespace WPForms\Providers\Provider\Settings;

use WPForms\Providers\Provider\Core;
use WPForms\Providers\Provider\Status;

/**
 * Class FormBuilder handles functionality inside the form builder.
 *
 * @since 1.4.7
 */
abstract class FormBuilder implements FormBuilderInterface {

	/**
	 * Get the Core loader class of a provider.
	 *
	 * @since 1.4.7
	 *
	 * @var Core
	 */
	protected $core;

	/**
	 * Most of Marketing providers will have 'connection' type.
	 * Payment providers may have (or not) something different.
	 *
	 * @since 1.4.7
	 *
	 * @var string
	 */
	protected $type = 'connection';

	/**
	 * Form data and settings.
	 *
	 * @since 1.4.7
	 *
	 * @var array
	 */
	protected $form_data = [];

	/**
	 * Integrations constructor.
	 *
	 * @since 1.4.7
	 *
	 * @param Core $core Core provider class.
	 */
	public function __construct( Core $core ) {

		$this->core = $core;

		if ( ! empty( $_GET['form_id'] ) ) { // phpcs:ignore
			$this->form_data = \wpforms()->form->get(
				\absint( $_GET['form_id'] ), // phpcs:ignore
				[
					'content_only' => true,
				]
			);
		}

		$this->init_hooks();
	}

	/**
	 * Register all hooks (actions and filters) here.
	 *
	 * @since 1.4.7
	 */
	protected function init_hooks() {

		// Register builder HTML template(s).
		add_action( 'wpforms_builder_print_footer_scripts', [ $this, 'builder_templates' ], 10 );
		add_action( 'wpforms_builder_print_footer_scripts', [ $this, 'builder_custom_templates' ], 11 );

		// Process builder AJAX requests.
		add_action( "wp_ajax_wpforms_builder_provider_ajax_{$this->core->slug}", [ $this, 'process_ajax' ] );

		/*
		 * Enqueue assets.
		 */
		if (
			( ! empty( $_GET['page'] ) && $_GET['page'] === 'wpforms-builder' ) && // phpcs:ignore
			! empty( $_GET['form_id'] ) && // phpcs:ignore
			is_admin()
		) {
			add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_assets' ] );
		}
	}

	/**
	 * Used to register generic templates for all providers inside form builder.
	 *
	 * @since 1.4.7
	 * @since 1.6.2 Added sub-templates for conditional logic based on provider.
	 */
	public function builder_templates() {

		$cl_builder_block = wpforms_conditional_logic()->builder_block(
			[
				'form'       => $this->form_data,
				'type'       => 'panel',
				'parent'     => 'providers',
				'panel'      => esc_attr( $this->core->slug ),
				'subsection' => '%connection_id%',
				'reference'  => esc_html__( 'Marketing provider connection', 'wpforms-lite' ),
			],
			false
		);
		?>

		<!-- Single connection block sub-template: FIELDS -->
		<script type="text/html" id="tmpl-wpforms-providers-builder-content-connection-fields">
			<div class="wpforms-builder-provider-connection-block wpforms-builder-provider-connection-fields">

				<table class="wpforms-builder-provider-connection-fields-table">
					<thead>
						<tr>
							<th><?php \esc_html_e( 'Custom Field Name', 'wpforms-lite' ); ?></th>
							<th colspan="3"><?php \esc_html_e( 'Form Field Value', 'wpforms-lite' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<# if ( ! _.isEmpty( data.connection.fields_meta ) ) { #>
							<# _.each( data.connection.fields_meta, function( item, meta_id ) { #>
								<tr class="wpforms-builder-provider-connection-fields-table-row">
									<td>
										<# if ( ! _.isEmpty( data.provider.fields ) ) { #>
											<select class="wpforms-builder-provider-connection-field-name"
												name="providers[{{ data.provider.slug }}][{{ data.connection.id }}][fields_meta][{{ meta_id }}][name]">
												<option value=""><# if ( ! _.isEmpty( data.provider.placeholder ) ) { #>{{ data.provider.placeholder }}<# } else { #><?php esc_html_e( '--- Select Field ---', 'wpforms-lite' ); ?><# } #></option>

												<# _.each( data.provider.fields, function( field_name, field_id ) { #>
													<option value="{{ field_id }}"
														<# if ( field_id === item.name ) { #>selected="selected"<# } #>
													>
														{{ field_name }}
													</option>
												<# } ); #>

											</select>
										<# } else { #>
											<input type="text" value="{{ item.name }}"
												class="wpforms-builder-provider-connection-field-name"
												name="providers[{{ data.provider.slug }}][{{ data.connection.id }}][fields_meta][{{ meta_id }}][name]"
												placeholder="<?php \esc_attr_e( 'Field Name', 'wpforms-lite' ); ?>"
											/>
										<# } #>
									</td>
									<td>
										<select class="wpforms-builder-provider-connection-field-value"
											name="providers[{{ data.provider.slug }}][{{ data.connection.id }}][fields_meta][{{ meta_id }}][field_id]">
											<option value=""><?php esc_html_e( '--- Select Form Field ---', 'wpforms-lite' ); ?></option>

											<# _.each( data.fields, function( field, key ) { #>
												<option value="{{ field.id }}"
														<# if ( field.id === item.field_id ) { #>selected="selected"<# } #>
												>
												<# if ( ! _.isUndefined( field.label ) && field.label.toString().trim() !== '' ) { #>
													{{ field.label.toString().trim() }}
												<# } else { #>
													{{ wpforms_builder.field + ' #' + key }}
												<# } #>
												</option>
											<# } ); #>
										</select>
									</td>
									<td class="add">
										<button class="button-secondary js-wpforms-builder-provider-connection-fields-add"
										        title="<?php \esc_attr_e( 'Add Another', 'wpforms-lite' ); ?>">
											<i class="fa fa-plus-circle"></i>
										</button>
									</td>
									<td class="delete">
										<button class="button js-wpforms-builder-provider-connection-fields-delete <# if ( meta_id === 0 ) { #>hidden<# } #>"
										        title="<?php \esc_attr_e( 'Remove', 'wpforms-lite' ); ?>">
											<i class="fa fa-minus-circle"></i>
										</button>
									</td>
								</tr>
							<# } ); #>
						<# } else { #>
							<tr class="wpforms-builder-provider-connection-fields-table-row">
								<td>
									<# if ( ! _.isEmpty( data.provider.fields ) ) { #>
										<select class="wpforms-builder-provider-connection-field-name"
											name="providers[{{ data.provider.slug }}][{{ data.connection.id }}][fields_meta][0][name]">
											<option value=""><# if ( ! _.isEmpty( data.provider.placeholder ) ) { #>{{ data.provider.placeholder }}<# } else { #><?php esc_html_e( '--- Select Field ---', 'wpforms-lite' ); ?><# } #></option>

											<# _.each( data.provider.fields, function( field_name, field_id ) { #>
												<option value="{{ field_id }}">
													{{ field_name }}
												</option>
											<# } ); #>

										</select>
									<# } else { #>
										<input type="text" value=""
											class="wpforms-builder-provider-connection-field-name"
											name="providers[{{ data.provider.slug }}][{{ data.connection.id }}][fields_meta][0][name]"
											placeholder="<?php \esc_attr_e( 'Field Name', 'wpforms-lite' ); ?>"
										/>
									<# } #>
								</td>
								<td>
									<select class="wpforms-builder-provider-connection-field-value"
										name="providers[{{ data.provider.slug }}][{{ data.connection.id }}][fields_meta][0][field_id]">
										<option value=""><?php esc_html_e( '--- Select Form Field ---', 'wpforms-lite' ); ?></option>

										<# _.each( data.fields, function( field, key ) { #>
											<option value="{{ field.id }}">
												<# if ( ! _.isUndefined( field.label ) && field.label.toString().trim() !== '' ) { #>
													{{ field.label.toString().trim() }}
												<# } else { #>
													{{ wpforms_builder.field + ' #' + key }}
												<# } #>
											</option>
										<# } ); #>
									</select>
								</td>
								<td class="add">
									<button class="button-secondary js-wpforms-builder-provider-connection-fields-add"
									        title="<?php \esc_attr_e( 'Add Another', 'wpforms-lite' ); ?>">
										<i class="fa fa-plus-circle"></i>
									</button>
								</td>
								<td class="delete">
									<button class="button js-wpforms-builder-provider-connection-fields-delete hidden"
									        title="<?php \esc_attr_e( 'Delete', 'wpforms-lite' ); ?>">
										<i class="fa fa-minus-circle"></i>
									</button>
								</td>
							</tr>
						<# } #>
					</tbody>
				</table><!-- /.wpforms-builder-provider-connection-fields-table -->

				<p class="description">
					<?php \esc_html_e( 'Map custom fields (or properties) to form fields values.', 'wpforms-lite' ); ?>
				</p>

			</div><!-- /.wpforms-builder-provider-connection-fields -->
		</script>

		<!-- Single connection block sub-template: CONDITIONAL LOGIC -->
		<script type="text/html" id="tmpl-wpforms-<?php echo esc_attr( $this->core->slug ); ?>-builder-content-connection-conditionals">
			<?php echo $cl_builder_block; // phpcs:ignore ?>
		</script>

		<!-- DEPRECATED: Should be removed when we will make changes in our addons. -->
		<script type="text/html" id="tmpl-wpforms-providers-builder-content-connection-conditionals">
			<?php echo $cl_builder_block; // phpcs:ignore ?>
		</script>
		<?php
	}

	/**
	 * Enqueue JavaScript and CSS files if needed.
	 * When extending - include the `parent::enqueue_assets();` not to break things!
	 *
	 * @since 1.4.7
	 */
	public function enqueue_assets() {

		$min = \wpforms_get_min_suffix();

		\wp_enqueue_script(
			'wpforms-admin-builder-templates',
			WPFORMS_PLUGIN_URL . "assets/js/components/admin/builder/templates{$min}.js",
			[ 'wp-util' ],
			WPFORMS_VERSION,
			true
		);

		\wp_enqueue_script(
			'wpforms-admin-builder-providers',
			WPFORMS_PLUGIN_URL . "assets/js/components/admin/builder/providers{$min}.js",
			[ 'wpforms-utils', 'wpforms-builder', 'wpforms-admin-builder-templates' ],
			WPFORMS_VERSION,
			true
		);
	}

	/**
	 * Process the Builder AJAX requests.
	 *
	 * @since 1.4.7
	 */
	public function process_ajax() {

		// Run a security check.
		\check_ajax_referer( 'wpforms-builder', 'nonce' );

		// Check for permissions.
		if ( ! \wpforms_current_user_can( 'edit_forms' ) ) {
			\wp_send_json_error(
				[
					'error' => \esc_html__( 'You do not have permission to perform this action.', 'wpforms-lite' ),
				]
			);
		}

		// Process required values.
		$error = [ 'error' => esc_html__( 'Something went wrong while performing an AJAX request.', 'wpforms-lite' ) ];

		if (
			empty( $_POST['id'] ) ||
			empty( $_POST['task'] )
		) {
			\wp_send_json_error( $error );
		}

		$form_id = (int) $_POST['id'];
		$task    = sanitize_key( $_POST['task'] );

		$revisions = wpforms()->get( 'revisions' );
		$revision  = $revisions ? $revisions->get_revision() : null;

		if ( $revision ) {
			// Setup form data based on the revision_id, that we got from AJAX request.
			$this->form_data = wpforms_decode( $revision->post_content );
		} else {
			// Setup form data based on the ID, that we got from AJAX request.
			$form_handler    = wpforms()->get( 'form' );
			$this->form_data = $form_handler ? $form_handler->get( $form_id, [ 'content_only' => true ] ) : [];
		}

		// Do not allow to proceed further, as form_id may be incorrect.
		if ( empty( $this->form_data ) ) {
			\wp_send_json_error( $error );
		}

		$data = \apply_filters(
			'wpforms_providers_settings_builder_ajax_' . $task . '_' . $this->core->slug,
			null
		);

		if ( null !== $data ) {
			\wp_send_json_success( $data );
		}

		\wp_send_json_error( $error );
	}

	/**
	 * Display content inside the panel sidebar area.
	 *
	 * @since 1.4.7
	 */
	public function display_sidebar() {

		$configured = '';

		if ( ! empty( $this->form_data['id'] ) && Status::init( $this->core->slug )->is_ready( $this->form_data['id'] ) ) {
			$configured = 'configured';
		}

		$classes = [
			'wpforms-panel-sidebar-section',
			'icon',
			$configured,
			'wpforms-panel-sidebar-section-' . $this->core->slug,
		];
		?>

		<a href="#" class="<?php echo \esc_attr( \implode( ' ', $classes ) ); ?>"
		   data-section="<?php echo \esc_attr( $this->core->slug ); ?>">

			<img src="<?php echo \esc_url( $this->core->icon ); ?>">

			<?php echo \esc_html( $this->core->name ); ?>

			<i class="fa fa-angle-right wpforms-toggle-arrow"></i>

			<?php if ( ! empty( $configured ) ) : ?>
				<i class="fa fa-check-circle-o"></i>
			<?php endif; ?>

		</a>

		<?php
	}

	/**
	 * Wrap the builder section content with the required (for tabs switching) markup.
	 *
	 * @since 1.4.7
	 */
	public function display_content() {
		?>

		<div class="wpforms-panel-content-section wpforms-builder-provider wpforms-panel-content-section-<?php echo \esc_attr( $this->core->slug ); ?>" id="<?php echo \esc_attr( $this->core->slug ); ?>-provider" data-provider="<?php echo \esc_attr( $this->core->slug ); ?>">

			<!-- Provider content goes here. -->
			<?php

			$this->display_content_header();

			$form_id = ! empty( $this->form_data['id'] ) ? $this->form_data['id'] : '';

			self::display_content_default_screen(
				Status::init( $this->core->slug )->is_ready( $form_id ),
				$this->core->slug,
				$this->core->name,
				$this->core->icon
			);
			?>

			<div class="wpforms-builder-provider-body">
				<div class="wpforms-provider-connections-wrap wpforms-clear">
					<div class="wpforms-builder-provider-connections"></div>
				</div>
			</div>

		</div>

		<?php
	}

	/**
	 * Display provider default screen.
	 *
	 * @since 1.6.8
	 *
	 * @param bool   $is_connected True if connections are configured.
	 * @param string $slug         Provider slug.
	 * @param string $name         Provider name.
	 * @param string $icon         Provider icon.
	 */
	public static function display_content_default_screen( $is_connected, $slug, $name, $icon ) {

		// Hide provider default settings screen when it's already connected.
		$class = $is_connected ? ' wpforms-hidden' : '';
		?>
		<div class="wpforms-builder-provider-connections-default<?php echo esc_attr( $class ); ?>">
			<img src="<?php echo esc_url( $icon ); ?>">
			<div class="wpforms-builder-provider-settings-default-content">
				<?php
				/*
				 * Allows developers to change the default content of the provider's settings default screen.
				 *
				 * @since 1.6.8
				 *
				 * @param string $content Content of the provider's settings default screen.
				 */
				echo apply_filters( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					"wpforms_providers_provider_settings_formbuilder_display_content_default_screen_{$slug}",
					sprintf( /* translators: %s - Provider name. */
						'<p>' . esc_html__( 'Get the most out of WPForms &mdash; use it with an active %s account.', 'wpforms-lite' ) . '</p>',
						esc_html( $name )
					)
				);
				?>
			</div>
		</div>
		<?php
	}

	/**
	 * Section content header.
	 *
	 * @since 1.4.7
	 */
	protected function display_content_header() {

		$is_configured = Status::init( $this->core->slug )->is_configured();
		?>

		<div class="wpforms-builder-provider-title wpforms-panel-content-section-title">

			<?php echo \esc_html( $this->core->name ); ?>

			<span class="wpforms-builder-provider-title-spinner">
				<i class="wpforms-loading-spinner wpforms-loading-md wpforms-loading-inline"></i>
			</span>

			<button class="wpforms-builder-provider-title-add js-wpforms-builder-provider-connection-add <?php echo $is_configured ? '' : 'hidden'; ?>"
			        data-form_id="<?php echo \absint( $_GET['form_id'] ); ?>"
			        data-provider="<?php echo \esc_attr( $this->core->slug ); ?>">
				<?php \esc_html_e( 'Add New Connection', 'wpforms-lite' ); ?>
			</button>

			<button class="wpforms-builder-provider-title-add js-wpforms-builder-provider-account-add <?php echo ! $is_configured ? '' : 'hidden'; ?>"
			        data-form_id="<?php echo \absint( $_GET['form_id'] ); ?>"
			        data-provider="<?php echo \esc_attr( $this->core->slug ); ?>">
				<?php \esc_html_e( 'Add New Account', 'wpforms-lite' ); ?>
			</button>

		</div>

		<?php
	}
}
