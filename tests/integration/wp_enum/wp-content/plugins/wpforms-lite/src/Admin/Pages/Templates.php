<?php

namespace WPForms\Admin\Pages;

use WPForms\Admin\Traits\FormTemplates;

/**
 * Main Templates page class.
 *
 * @since 1.7.7
 */
class Templates {

	use FormTemplates;

	/**
	 * Page slug.
	 *
	 * @since 1.7.7
	 *
	 * @var string
	 */
	const SLUG = 'wpforms-templates';

	/**
	 * Initialize class.
	 *
	 * @since 1.7.7
	 */
	public function init() {

		if ( ! wpforms_is_admin_page( 'templates' ) ) {
			return;
		}

		$this->addons_obj = wpforms()->get( 'addons' );

		$this->hooks();
	}

	/**
	 * Register hooks.
	 *
	 * @since 1.7.7
	 */
	private function hooks() {

		add_action( 'wpforms_admin_page', [ $this, 'output' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueues' ] );
	}

	/**
	 * Enqueue assets.
	 *
	 * @since 1.7.7
	 */
	public function enqueues() {

		$min = wpforms_get_min_suffix();

		wp_enqueue_style(
			'wpforms-form-templates',
			WPFORMS_PLUGIN_URL . "assets/css/admin/admin-form-templates{$min}.css",
			[],
			WPFORMS_VERSION
		);

		wp_enqueue_script(
			'wpforms-admin-form-templates',
			WPFORMS_PLUGIN_URL . "assets/js/components/admin/pages/form-templates{$min}.js",
			[],
			WPFORMS_VERSION,
			true
		);

		wp_localize_script(
			'wpforms-admin-form-templates',
			'wpforms_admin_form_templates',
			[
				'nonce' => wp_create_nonce( 'wpforms-builder' ),
			]
		);
	}

	/**
	 * Build the output for the Form Templates admin page.
	 *
	 * @since 1.7.7
	 */
	public function output() {
		?>

		<div id="wpforms-form-templates" class="wrap wpforms-admin-wrap">

			<h1 class="page-title"><?php esc_html_e( 'Form Templates', 'wpforms-lite' ); ?></h1>

			<div class="wpforms-form-setup-content" >
				<div class="wpforms-setup-title">
					<?php esc_html_e( 'Get a Head Start With Our Pre-Made Form Templates', 'wpforms-lite' ); ?>
				</div>

				<p class="wpforms-setup-desc secondary-text">
					<?php
					printf(
						wp_kses( /* translators: %1$s - Create template doc link; %2$s - Contact us page link. */
							__( 'Choose a template to speed up the process of creating your form. You can also start with a <a href="#" class="wpforms-trigger-blank">blank form</a> or <a href="%1$s" target="_blank" rel="noopener noreferrer">create your own</a>. <br>Have a suggestion for a new template? <a href="%2$s" target="_blank" rel="noopener noreferrer">We’d love to hear it</a>!', 'wpforms-lite' ),
							[
								'strong' => [],
								'br'     => [],
								'a'      => [
									'href'   => [],
									'class'  => [],
									'target' => [],
									'rel'    => [],
								],
							]
						),
						esc_url( wpforms_utm_link( 'https://wpforms.com/docs/how-to-create-a-custom-form-template/', 'Form Templates Subpage', 'Create Your Own Template' ) ),
						esc_url( wpforms_utm_link( 'https://wpforms.com/form-template-suggestion/', 'Form Templates Subpage', 'Form Template Suggestion' ) )
					);
					?>
				</p>

				<?php $this->output_templates_content(); ?>
			</div>
		</div>
		<?php
	}

}
