<?php

/**
 * Base form template.
 *
 * @since 1.0.0
 */
abstract class WPForms_Template {

	/**
	 * Full name of the template, eg "Contact Form".
	 *
	 * @since 1.0.0
	 *
	 * @var string
	 */
	public $name;

	/**
	 * Slug of the template, eg "contact-form" - no spaces.
	 *
	 * @since 1.0.0
	 *
	 * @var string
	 */
	public $slug;

	/**
	 * Source of the template.
	 *
	 * @since 1.6.8
	 *
	 * @var array
	 */
	public $source;

	/**
	 * Categories array.
	 *
	 * @since 1.6.8
	 *
	 * @var array
	 */
	public $categories;

	/**
	 * Short description the template.
	 *
	 * @since 1.0.0
	 *
	 * @var string
	 */
	public $description = '';

	/**
	 * Short description of the fields included with the template.
	 *
	 * @since 1.0.0
	 *
	 * @var string
	 */
	public $includes = '';

	/**
	 * URL of the icon to display in the admin area.
	 *
	 * @since 1.0.0
	 *
	 * @var string
	 */
	public $icon = '';

	/**
	 * Form template preview URL.
	 *
	 * @since 1.7.5.3
	 *
	 * @var string
	 */
	public $url = '';

	/**
	 * Array of data that is assigned to the post_content on form creation.
	 *
	 * @since 1.0.0
	 *
	 * @var array
	 */
	public $data;

	/**
	 * Priority to show in the list of available templates.
	 *
	 * @since 1.0.0
	 *
	 * @var int
	 */
	public $priority = 20;

	/**
	 * Core or additional template.
	 *
	 * @since 1.4.0
	 *
	 * @var bool
	 */
	public $core = false;

	/**
	 * Modal message to display when the template is applied.
	 *
	 * @since 1.0.0
	 *
	 * @var array
	 */
	public $modal = '';

	/**
	 * Primary class constructor.
	 *
	 * @since 1.0.0
	 */
	public function __construct() {

		// Bootstrap.
		$this->init();

		$type = $this->core ? '_core' : '';

		add_filter( "wpforms_form_templates{$type}", [ $this, 'template_details' ], $this->priority );
		add_filter( 'wpforms_create_form_args', [ $this, 'template_data' ], 10, 2 );
		add_filter( 'wpforms_save_form_args', [ $this, 'template_replace' ], 10, 3 );
		add_filter( 'wpforms_builder_template_active', [ $this, 'template_active' ], 10, 2 );
	}

	/**
	 * Let's get started.
	 *
	 * @since 1.0.0
	 */
	public function init() {}

	/**
	 * Add basic template details to the Add New Form admin screen.
	 *
	 * @since 1.0.0
	 *
	 * @param array $templates Templates array.
	 *
	 * @return array
	 */
	public function template_details( $templates ) {

		$templates[] = [
			'name'        => $this->name,
			'slug'        => $this->slug,
			'source'      => $this->source,
			'categories'  => $this->categories,
			'description' => $this->description,
			'includes'    => $this->includes,
			'icon'        => $this->icon,
			'url'         => ! empty( $this->url ) ? $this->url : '',
			'plugin_dir'  => $this->get_plugin_dir(),
		];

		return $templates;
	}

	/**
	 * Get the directory name of the plugin in which current template resides.
	 *
	 * @since 1.6.9
	 *
	 * @return string
	 */
	private function get_plugin_dir() {

		$reflection         = new \ReflectionClass( $this );
		$template_file_path = wp_normalize_path( $reflection->getFileName() );

		// Cutting out the WP_PLUGIN_DIR from the beginning of the template file path.
		$template_file_path = preg_replace( '{^' . wp_slash( wp_normalize_path( WP_PLUGIN_DIR ) ) . '}', '', $template_file_path );

		$template_file_chunks = explode( '/', $template_file_path );

		return $template_file_chunks[1];
	}

	/**
	 * Add template data when form is created.
	 *
	 * @since 1.0.0
	 *
	 * @param array $args Create form arguments.
	 * @param array $data Template data.
	 *
	 * @return array
	 */
	public function template_data( $args, $data ) {

		if ( ! empty( $data ) && ! empty( $data['template'] ) ) {
			if ( $data['template'] === $this->slug ) {

				// Enable Notifications by default.
				$this->data['settings']['notification_enable'] = isset( $this->data['settings']['notification_enable'] )
					? $this->data['settings']['notification_enable']
					: 1;

				$args['post_content'] = wpforms_encode( $this->data );
			}
		}

		return $args;
	}

	/**
	 * Replace template on post update if triggered.
	 *
	 * @since 1.0.0
	 *
	 * @param array $form Form post data.
	 * @param array $data Form data.
	 * @param array $args Update form arguments.
	 *
	 * @return array
	 */
	public function template_replace( $form, $data, $args ) {

		// We should proceed only if the template slug passed via $args['template'] is equal to the current template slug.
		// This will work only for offline templates: Blank Form, all the Addons Templates, and all the custom templates.
		// All the online (modern) templates use the hash as the identifier,
		// and they are handled by `\WPForms\Admin\Builder\Templates::apply_to_existing_form()`.
		if ( empty( $args['template'] ) || $args['template'] !== $this->slug ) {
			return $form;
		}

		$form_data = wpforms_decode( wp_unslash( $form['post_content'] ) );

		// Something is wrong with the form data.
		if ( empty( $form_data ) ) {
			return $form;
		}

		// Compile the new form data preserving needed data from the existing form.
		$new                     = $this->data;
		$new['id']               = isset( $form_data['id'] ) ? $form_data['id'] : 0;
		$new['settings']         = isset( $form_data['settings'] ) ? $form_data['settings'] : [];
		$new['payments']         = isset( $form_data['payments'] ) ? $form_data['payments'] : [];
		$new['meta']             = isset( $form_data['meta'] ) ? $form_data['meta'] : [];
		$new['meta']['template'] = isset( $this->data['meta']['template'] ) ? $this->data['meta']['template'] : '';

		/**
		 * Allow modifying form data when a template is replaced.
		 *
		 * @since 1.7.9
		 *
		 * @param array $new       Updated form data.
		 * @param array $form_data Current form data.
		 * @param array $template  Template data.
		 */
		$new = (array) apply_filters( 'wpforms_templates_class_base_template_replace_modify_data', $new, $form_data, $this );

		// Update the form with new data.
		$form['post_content'] = wpforms_encode( $new );

		return $form;
	}

	/**
	 * Pass information about the active template back to the builder.
	 *
	 * @since 1.0.0
	 *
	 * @param array  $details Details.
	 * @param object $form    Form data.
	 *
	 * @return array|void
	 */
	public function template_active( $details, $form ) {

		if ( empty( $form ) ) {
			return;
		}

		$form_data = wpforms_decode( $form->post_content );

		if ( empty( $this->modal ) || empty( $form_data['meta']['template'] ) || $this->slug !== $form_data['meta']['template'] ) {
			return $details;
		} else {
			$display = $this->template_modal_conditional( $form_data );
		}

		return [
			'name'          => $this->name,
			'slug'          => $this->slug,
			'description'   => $this->description,
			'includes'      => $this->includes,
			'icon'          => $this->icon,
			'modal'         => $this->modal,
			'modal_display' => $display,
		];
	}

	/**
	 * Conditional to determine if the template informational modal screens
	 * should display.
	 *
	 * @since 1.0.0
	 *
	 * @param array $form_data Form data and settings.
	 *
	 * @return bool
	 */
	public function template_modal_conditional( $form_data ) {

		return false;
	}
}
