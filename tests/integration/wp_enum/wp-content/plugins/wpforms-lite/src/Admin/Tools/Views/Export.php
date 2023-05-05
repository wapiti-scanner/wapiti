<?php

namespace WPForms\Admin\Tools\Views;

/**
 * Class Export.
 *
 * @since 1.6.6
 */
class Export extends View {

	/**
	 * View slug.
	 *
	 * @since 1.6.6
	 *
	 * @var string
	 */
	protected $slug = 'export';

	/**
	 * Template code if generated.
	 *
	 * @since 1.6.6
	 *
	 * @var string
	 */
	private $template = '';

	/**
	 * Existed forms.
	 *
	 * @since 1.6.6
	 *
	 * @var []
	 */
	private $forms = [];

	/**
	 * Init view.
	 *
	 * @since 1.6.6
	 */
	public function init() {

		add_action( 'wpforms_tools_init', [ $this, 'process' ] );
	}

	/**
	 * Get view label.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 */
	public function get_label() {

		return esc_html__( 'Export', 'wpforms-lite' );
	}

	/**
	 * Export process.
	 *
	 * @since 1.6.6
	 */
	public function process() {

		if (
			empty( $_POST['action'] ) || //phpcs:ignore WordPress.Security.NonceVerification
			! isset( $_POST['submit-export'] ) || //phpcs:ignore WordPress.Security.NonceVerification
			! $this->verify_nonce()
		) {
			return;
		}

		if ( $_POST['action'] === 'export_form' && ! empty( $_POST['forms'] ) ) { //phpcs:ignore WordPress.Security.NonceVerification
			$this->process_form();
		}

		if ( $_POST['action'] === 'export_template' && ! empty( $_POST['form'] ) ) { //phpcs:ignore WordPress.Security.NonceVerification
			$this->process_template();
		}
	}

	/**
	 * Checking user capability to view.
	 *
	 * @since 1.6.6
	 *
	 * @return bool
	 */
	public function check_capability() {

		return wpforms_current_user_can( [ 'edit_forms', 'view_entries' ] );
	}

	/**
	 * Get available forms.
	 *
	 * @since 1.6.6
	 *
	 * @return array
	 */
	public function get_forms() {

		$forms = wpforms()->form->get( '', [ 'orderby' => 'title' ] );

		return ! empty( $forms ) ? $forms : [];
	}

	/**
	 * Export view content.
	 *
	 * @since 1.6.6
	 */
	public function display() {

		$this->forms = $this->get_forms();

		if ( empty( $this->forms ) ) {

			echo wpforms_render( 'admin/empty-states/no-forms' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

			return;
		}

		do_action( 'wpforms_admin_tools_export_top' );

		$this->forms_export_block();

		$this->form_template_export_block();

		do_action( 'wpforms_admin_tools_export_bottom' );
	}

	/**
	 * Forms export block.
	 *
	 * @since 1.6.6
	 */
	private function forms_export_block() {
		?>

		<div class="wpforms-setting-row tools">

			<h4 id="form-export"><?php esc_html_e( 'Form Export', 'wpforms-lite' ); ?></h4>

			<p><?php esc_html_e( 'Form exports files can be used to create a backup of your forms or to import forms into another site.', 'wpforms-lite' ); ?></p>

			<?php if ( ! empty( $this->forms ) ) { ?>

				<form method="post" action="<?php echo esc_attr( $this->get_link() ); ?>">
					<?php $this->forms_select_html( 'wpforms-tools-form-export', 'forms[]', esc_html__( 'Select Form(s)', 'wpforms-lite' ) ); ?>
					<br>
					<input type="hidden" name="action" value="export_form">
					<?php $this->nonce_field(); ?>
					<button name="submit-export" class="wpforms-btn wpforms-btn-md wpforms-btn-orange">
						<?php esc_html_e( 'Export', 'wpforms-lite' ); ?>
					</button>
				</form>
			<?php } else { ?>
				<p><?php esc_html_e( 'You need to create a form before you can use form export.', 'wpforms-lite' ); ?></p>
			<?php } ?>
		</div>
	<?php
	}

	/**
	 * Forms export block.
	 *
	 * @since 1.6.6
	 */
	private function form_template_export_block() {
		?>

		<div class="wpforms-setting-row tools">

			<h4 id="template-export"><?php esc_html_e( 'Form Template Export', 'wpforms-lite' ); ?></h4>

			<?php
			if ( $this->template ) {

				$doc_link = sprintf(
					wp_kses( /* translators: %s - WPForms.com docs URL. */
						__( 'For more information <a href="%s" target="_blank" rel="noopener noreferrer">see our documentation</a>.', 'wpforms-lite' ),
						[
							'a' => [
								'href'   => [],
								'target' => [],
								'rel'    => [],
							],
						]
					),
					'https://wpforms.com/docs/how-to-create-a-custom-form-template/'
				);
			?>
			<p><?php esc_html_e( 'The following code can be used to register your custom form template. Copy and paste the following code to your theme\'s functions.php file or include it within an external file.', 'wpforms-lite' ); ?><p>
			<p><?php echo $doc_link; //phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?><p>
			<textarea class="info-area" readonly><?php echo esc_textarea( $this->template ); ?></textarea><br>
			<?php
			}
			?>

			<p><?php esc_html_e( 'Select a form to generate PHP code that can be used to register a custom form template.', 'wpforms-lite' ); ?></p>

			<?php if ( ! empty( $this->forms ) ) { ?>
				<form method="post" action="<?php echo esc_attr( $this->get_link() ); ?>">
					<?php $this->forms_select_html( 'wpforms-tools-form-template', 'form', esc_html__( 'Select a Template', 'wpforms-lite' ), false ); ?>
					<br>
					<input type="hidden" name="action" value="export_template">
					<?php $this->nonce_field(); ?>
					<button name="submit-export" class="wpforms-btn wpforms-btn-md wpforms-btn-orange">
						<?php esc_html_e( 'Export Template', 'wpforms-lite' ); ?>
					</button>
				</form>
			<?php } else { ?>
				<p><?php esc_html_e( 'You need to create a form before you can generate a template.', 'wpforms-lite' ); ?></p>
			<?php } ?>
		</div>
	<?php
	}

	/**
	 * Forms selector.
	 *
	 * @since 1.6.6
	 *
	 * @param string $select_id   Select id.
	 * @param string $select_name Select name.
	 * @param string $placeholder Placeholder.
	 * @param bool   $multiple    Is multiple select.
	 */
	private function forms_select_html( $select_id, $select_name, $placeholder, $multiple = true ) {
		?>

		<span class="choicesjs-select-wrap">
			<select id="<?php echo esc_attr( $select_id ); ?>" class="choicesjs-select" name="<?php echo esc_attr( $select_name ); ?>" <?php if ( $multiple ) { //phpcs:ignore ?> multiple <?php } ?> data-search="true">
				<option value=""><?php echo esc_attr( $placeholder ); ?></option>
				<?php foreach ( $this->forms as $form ) { ?>
					<option value="<?php echo absint( $form->ID ); ?>"><?php echo esc_html( $form->post_title ); ?></option>
				<?php } ?>
			</select>
		</span>
		<?php
	}

	/**
	 * Export processing.
	 *
	 * @since 1.6.6
	 */
	private function process_form() {

		$export = [];
		$forms  = get_posts(
			[
				'post_type' => 'wpforms',
				'nopaging'  => true,
				'post__in'  => isset( $_POST['forms'] ) ? array_map( 'intval', $_POST['forms'] ) : [], //phpcs:ignore WordPress.Security.NonceVerification
			]
		);

		foreach ( $forms as $form ) {
			$export[] = wpforms_decode( $form->post_content );
		}

		ignore_user_abort( true );

		wpforms_set_time_limit();

		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=wpforms-form-export-' . current_time( 'm-d-Y' ) . '.json' );
		header( 'Expires: 0' );

		echo wp_json_encode( $export );
		exit;
	}

	/**
	 * Export template processing.
	 *
	 * @since 1.6.6
	 */
	private function process_template() {

		$form_data = false;

		if ( isset( $_POST['form'] ) ) { //phpcs:ignore WordPress.Security.NonceVerification
			$form_data = wpforms()->form->get(
				absint( $_POST['form'] ), //phpcs:ignore WordPress.Security.NonceVerification
				[ 'content_only' => true ]
			);
		}

		if ( ! $form_data ) {
			return;
		}

		// Define basic data.
		$name  = sanitize_text_field( $form_data['settings']['form_title'] );
		$desc  = sanitize_text_field( $form_data['settings']['form_desc'] );
		$slug  = sanitize_key( str_replace( [ ' ', '-' ], '_', $form_data['settings']['form_title'] ) );
		$class = 'WPForms_Template_' . $slug;

		// Format template field and settings data.
		$data                     = $form_data;
		$data['meta']['template'] = $slug;
		$data['fields']           = isset( $data['fields'] ) ? wpforms_array_remove_empty_strings( $data['fields'] ) : [];
		$data['settings']         = wpforms_array_remove_empty_strings( $data['settings'] );

		unset( $data['id'] );

		$data = var_export( $data, true ); //phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export
		$data = str_replace( '  ', "\t", $data );
		$data = preg_replace( '/([\t\r\n]+?)array/', 'array', $data );

		// Build the final template string.
		$this->template = <<<EOT
if ( class_exists( 'WPForms_Template', false ) ) :
/**
 * {$name}
 * Template for WPForms.
 */
class {$class} extends WPForms_Template {

	/**
	 * Primary class constructor.
	 *
	 * @since 1.0.0
	 */
	public function init() {

		// Template name
		\$this->name = '{$name}';

		// Template slug
		\$this->slug = '{$slug}';

		// Template description
		\$this->description = '{$desc}';

		// Template field and settings
		\$this->data = {$data};
	}
}
new {$class}();
endif;
EOT;
	}

}
