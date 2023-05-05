<?php

/**
 * Setup panel.
 *
 * @since 1.0.0
 * @since 1.6.8 Form Builder Refresh.
 */
class WPForms_Builder_Panel_Setup extends WPForms_Builder_Panel {

	use \WPForms\Admin\Traits\FormTemplates;

	/**
	 * All systems go.
	 *
	 * @since 1.0.0
	 */
	public function init() {

		// Define panel information.
		$this->name  = esc_html__( 'Setup', 'wpforms-lite' );
		$this->slug  = 'setup';
		$this->icon  = 'fa-cog';
		$this->order = 5;

		$this->addons_obj = wpforms()->get( 'addons' );
	}

	/**
	 * Enqueue assets for the Setup panel.
	 *
	 * @since 1.0.0
	 * @since 1.6.8 All the builder stylesheets enqueues moved to the `\WPForms_Builder::enqueues()`.
	 */
	public function enqueues() {

		$min = wpforms_get_min_suffix();

		wp_enqueue_script(
			'wpforms-builder-setup',
			WPFORMS_PLUGIN_URL . "assets/js/components/admin/builder/setup{$min}.js",
			[ 'wpforms-builder', 'listjs' ],
			WPFORMS_VERSION,
			true
		);
	}

	/**
	 * Output the Settings panel primary content.
	 *
	 * @since 1.0.0
	 */
	public function panel_content() {

		?>
		<div id="wpforms-setup-form-name">
			<label for="wpforms-setup-name"><?php esc_html_e( 'Name Your Form', 'wpforms-lite' ); ?></label>
			<input type="text" id="wpforms-setup-name" placeholder="<?php esc_attr_e( 'Enter your form name here&hellip;', 'wpforms-lite' ); ?>">
		</div>

		<div class="wpforms-setup-title">
			<?php esc_html_e( 'Select a Template', 'wpforms-lite' ); ?>
			<span class="wpforms-setup-title-after"></span>
		</div>

		<p class="wpforms-setup-desc secondary-text">
			<?php
			printf(
				wp_kses( /* translators: %1$s - Create template doc link; %2$s - Contact us page link. */
					__( 'To speed up the process you can select from one of our pre-made templates, start with a <a href="#" class="wpforms-trigger-blank">blank form</a> or <a href="%1$s" target="_blank" rel="noopener noreferrer">create your own</a>. Have a suggestion for a new template? <a href="%2$s" target="_blank" rel="noopener noreferrer">We’d love to hear it</a>!', 'wpforms-lite' ),
					[
						'strong' => [],
						'a'      => [
							'href'   => [],
							'class'  => [],
							'target' => [],
							'rel'    => [],
						],
					]
				),
				esc_url( wpforms_utm_link( 'https://wpforms.com/docs/how-to-create-a-custom-form-template/', 'builder-templates', 'Create Your Own Template Documentation' ) ),
				esc_url( wpforms_utm_link( 'https://wpforms.com/form-template-suggestion/', 'builder-templates', 'Suggest a Template' ) )
			);
			?>
		</p>

		<?php
		$this->output_templates_content();

		/**
		 * Fires after WPForms builder setup panel.
		 *
		 * @since 1.0.6
		 */
		do_action( 'wpforms_setup_panel_after' ); // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName
	}
}

new WPForms_Builder_Panel_Setup();
