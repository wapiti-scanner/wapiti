<?php

namespace WPForms\Admin\Traits;

/**
 * Form Templates trait.
 *
 * @since 1.7.7
 */
trait FormTemplates {

	// phpcs:disable WPForms.PHP.BackSlash.UseShortSyntax
	/**
	 * Addons data handler class instance.
	 *
	 * @since 1.7.7
	 *
	 * @var \WPForms\Admin\Addons\Addons
	 */
	private $addons_obj;
	// phpcs:enable WPForms.PHP.BackSlash.UseShortSyntax

	/**
	 * Is addon templates available?
	 *
	 * @since 1.7.7
	 *
	 * @var bool
	 */
	private $is_addon_templates_available = false;

	/**
	 * Is custom templates available?
	 *
	 * @since 1.7.7
	 *
	 * @var bool
	 */
	private $is_custom_templates_available = false;

	/**
	 * Prepared templates list.
	 *
	 * @since 1.7.7
	 *
	 * @var array
	 */
	private $prepared_templates = [];

	/**
	 * Output templates content section.
	 *
	 * @since 1.7.7
	 */
	private function output_templates_content() {

		$this->prepare_templates_data();
		?>

		<div class="wpforms-setup-templates">
			<div class="wpforms-setup-templates-sidebar">

				<div class="wpforms-setup-templates-search-wrap">
					<i class="fa fa-search"></i>
					<label>
						<input type="text" id="wpforms-setup-template-search" value="" placeholder="<?php esc_attr_e( 'Search Templates', 'wpforms-lite' ); ?>">
					</label>
				</div>

				<ul class="wpforms-setup-templates-categories">
					<?php $this->template_categories(); ?>
				</ul>

			</div>

			<div id="wpforms-setup-templates-list">
				<div class="list">
					<?php $this->template_select_options(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
				</div>
				<div class="wpforms-templates-no-results">
					<p>
						<?php esc_html_e( 'Sorry, we didn\'t find any templates that match your criteria.', 'wpforms-lite' ); ?>
					</p>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Prepare templates data for output.
	 *
	 * @since 1.7.7
	 */
	private function prepare_templates_data() {

		$templates = wpforms()->get( 'builder_templates' )->get_templates();

		if ( empty( $templates ) ) {
			return;
		}

		// Loop through each available template.
		foreach ( $templates as $id => $template ) {

			$this->prepared_templates[ $id ] = $this->prepare_template_render_arguments( $template );
		}
	}

	/**
	 * Generate and display categories menu.
	 *
	 * @since 1.7.7
	 */
	private function template_categories() {

		$templates_count = $this->get_count_in_categories();

		$generic_categories = [
			'all' => esc_html__( 'All Templates', 'wpforms-lite' ),
		];

		if ( isset( $templates_count['all'], $templates_count['available'] ) && $templates_count['all'] !== $templates_count['available'] ) {
			$generic_categories['available'] = esc_html__( 'Available Templates', 'wpforms-lite' );
		}

		$generic_categories['favorites'] = esc_html__( 'Favorite Templates', 'wpforms-lite' );
		$generic_categories['new']       = esc_html__( 'New Templates', 'wpforms-lite' );

		$this->output_categories( $generic_categories, $templates_count );

		printf( '<li class="divider"></li>' );

		$common_categories = [];

		if ( $this->is_custom_templates_available ) {
			$common_categories['custom'] = esc_html__( 'Custom Templates', 'wpforms-lite' );
		}

		if ( $this->is_addon_templates_available ) {
			$common_categories['addons'] = esc_html__( 'Addon Templates', 'wpforms-lite' );
		}

		$categories = array_merge(
			$common_categories,
			wpforms()->get( 'builder_templates' )->get_categories()
		);

		$this->output_categories( $categories, $templates_count );
	}

	/**
	 * Output categories list.
	 *
	 * @since 1.7.7
	 *
	 * @param array $categories      Categories list.
	 * @param array $templates_count Templates count by categories.
	 */
	private function output_categories( $categories, $templates_count ) {

		foreach ( $categories as $slug => $name ) {

			$class = '';

			if ( $slug === 'all' ) {
				$class = ' class="active"';
			} elseif ( empty( $templates_count[ $slug ] ) ) {
				$class = ' class="wpforms-hidden"';
			}

			$count = isset( $templates_count[ $slug ] ) ? $templates_count[ $slug ] : '0';

			printf(
				'<li data-category="%1$s"%2$s>%3$s<span>%4$s</span></li>',
				esc_attr( $slug ),
				$class, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				esc_html( $name ),
				esc_html( $count )
			);
		}
	}

	/**
	 * Generate a block of templates to choose from.
	 *
	 * @since 1.7.7
	 *
	 * @param array  $templates Deprecated.
	 * @param string $slug      Deprecated.
	 */
	public function template_select_options( $templates = [], $slug = '' ) {

		foreach ( $this->prepared_templates as $template ) {

			echo wpforms_render( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				'builder/templates-item',
				$template,
				true
			);
		}
	}

	/**
	 * Prepare arguments for rendering template item.
	 *
	 * @since 1.7.7
	 *
	 * @param array $template Template data.
	 *
	 * @return array Arguments.
	 */
	private function prepare_template_render_arguments( $template ) { // phpcs:ignore Generic.Metrics.CyclomaticComplexity.MaxExceeded

		$template['plugin_dir'] = isset( $template['plugin_dir'] ) ? $template['plugin_dir'] : '';
		$template['source']     = $this->get_template_source( $template );
		$template['url']        = ! empty( $template['url'] ) ? $template['url'] : '';
		$template['has_access'] = ! empty( $template['license'] ) ? $template['has_access'] : true;
		$template['favorite']   = isset( $template['favorite'] ) ? $template['favorite'] : wpforms()->get( 'builder_templates' )->is_favorite( $template['slug'] );

		$args = [];

		$args['template_id'] = ! empty( $template['id'] ) ? $template['id'] : $template['slug'];
		$args['categories']  = $this->get_template_categories( $template );
		$args['demo_url']    = '';

		if ( ! empty( $template['url'] ) ) {
			$medium           = wpforms_is_admin_page( 'templates' ) ? 'Form Templates Subpage' : 'builder-templates';
			$args['demo_url'] = wpforms_utm_link( $template['url'], $medium, $template['name'] );
		}

		$template_license = ! empty( $template['license'] ) ? $template['license'] : '';
		$template_name    = sprintf( /* translators: %s - Form template name. */
			esc_html__( '%s template', 'wpforms-lite' ),
			esc_html( $template['name'] )
		);

		$args['badge_text']           = '';
		$args['license_class']        = '';
		$args['education_class']      = '';
		$args['education_attributes'] = '';

		if ( $template['source'] === 'wpforms-addon' ) {
			$args['badge_text'] = esc_html__( 'Addon', 'wpforms-lite' );

			// At least one addon template available.
			$this->is_addon_templates_available = true;
		}

		if ( $template['source'] === 'wpforms-custom' ) {
			$args['badge_text'] = esc_html__( 'Custom', 'wpforms-lite' );

			// At least one custom template available.
			$this->is_custom_templates_available = true;
		}

		$args['action_text'] = $this->get_action_button_text( $template );

		if ( empty( $template['has_access'] ) ) {
			$args['license_class']        = ' pro';
			$args['badge_text']           = $template_license;
			$args['education_class']      = ' education-modal';
			$args['education_attributes'] = sprintf(
				' data-name="%1$s" data-license="%2$s" data-action="upgrade"',
				esc_attr( $template_name ),
				esc_attr( $template_license )
			);
		}

		$args['addons_attributes'] = $this->prepare_addons_attributes( $template );

		$args['selected']       = ! empty( $this->form_data['meta']['template'] ) && $this->form_data['meta']['template'] === $args['template_id'];
		$args['selected_class'] = $args['selected'] ? ' selected' : '';
		$args['badge_text']     = $args['selected'] ? esc_html__( 'Selected', 'wpforms-lite' ) : $args['badge_text'];
		$args['badge_class']    = ! empty( $args['badge_text'] ) ? ' badge' : '';
		$args['template']       = $template;

		return $args;
	}

	/**
	 * Get action button text.
	 *
	 * @since 1.7.7
	 *
	 * @param array $template Template data.
	 *
	 * @return string
	 */
	private function get_action_button_text( $template ) {

		if ( $template['slug'] === 'blank' ) {
			 return __( 'Create Blank Form', 'wpforms-lite' );
		}

		if ( wpforms_is_admin_page( 'templates' ) ) {
			 return __( 'Create Form', 'wpforms-lite' );
		}

		return __( 'Use Template', 'wpforms-lite' );
	}

	/**
	 * Generate addon attributes.
	 *
	 * @since 1.7.7
	 *
	 * @param array $template Template data.
	 *
	 * @return string Addon attributes.
	 */
	private function prepare_addons_attributes( $template ) {

		$addons_attributes = '';
		$required_addons   = false;

		if ( ! empty( $template['addons'] ) && is_array( $template['addons'] ) ) {
			$required_addons = $this->addons_obj->get_by_slugs( $template['addons'] );

			foreach ( $required_addons as $i => $addon ) {
				if (
					! isset( $addon['action'], $addon['title'], $addon['slug'] ) ||
					! in_array( $addon['action'], [ 'install', 'activate' ], true )
				) {
					unset( $required_addons[ $i ] );
				}
			}
		}

		if ( ! empty( $required_addons ) ) {
			$addons_names = implode( ', ', wp_list_pluck( $required_addons, 'title' ) );
			$addons_slugs = implode( ',', wp_list_pluck( $required_addons, 'slug' ) );

			$addons_attributes = sprintf(
				' data-addons-names="%1$s" data-addons="%2$s"',
				esc_attr( $addons_names ),
				esc_attr( $addons_slugs )
			);
		}

		return $addons_attributes;
	}

	/**
	 * Determine a template source.
	 *
	 * @since 1.7.7
	 *
	 * @param array $template Template data.
	 *
	 * @return string Template source.
	 */
	private function get_template_source( $template ) {

		if ( ! empty( $template['source'] ) ) {
			return $template['source'];
		}

		$source = 'wpforms-addon';

		static $addons = null;

		if ( $addons === null ) {
			$addons = array_keys( $this->addons_obj->get_all() );
		}

		if ( $template['plugin_dir'] === 'wpforms' || $template['plugin_dir'] === 'wpforms-lite' ) {
			$source = 'wpforms-core';
		}

		if ( $source !== 'wpforms-core' && ! in_array( $template['plugin_dir'], $addons, true ) ) {
			$source = 'wpforms-custom';
		}

		return $source;
	}

	/**
	 * Determine template categories.
	 *
	 * @since 1.7.7
	 *
	 * @param array $template Template data.
	 *
	 * @return string Template categories coma separated.
	 */
	private function get_template_categories( $template ) {

		$categories = ! empty( $template['categories'] ) ? (array) $template['categories'] : [];
		$source     = $this->get_template_source( $template );

		if ( $source === 'wpforms-addon' ) {
			$categories[] = 'addons';
		}

		if ( $source === 'wpforms-custom' ) {
			$categories[] = 'custom';
		}

		if ( isset( $template['created_at'] ) && strtotime( $template['created_at'] ) > strtotime( '-3 Months' ) ) {
			$categories[] = 'new';
		}

		return implode( ',', $categories );
	}

	/**
	 * Get categories templates count.
	 *
	 * @since 1.7.7
	 *
	 * @return array
	 */
	private function get_count_in_categories() {

		$all_categories            = [];
		$available_templates_count = 0;
		$favorites_templates_count = 0;

		foreach ( $this->prepared_templates as $template_data ) {

			$template   = $template_data['template'];
			$categories = explode( ',', $template_data['categories'] );

			if ( $template['has_access'] ) {
				$available_templates_count ++;
			}

			if ( $template['favorite'] ) {
				$favorites_templates_count++;
			}

			if ( is_array( $categories ) ) {
				array_push( $all_categories, ...$categories );
				continue;
			}

			$all_categories[] = $categories;
		}

		$categories_count              = array_count_values( $all_categories );
		$categories_count['all']       = count( $this->prepared_templates );
		$categories_count['available'] = $available_templates_count;
		$categories_count['favorites'] = $favorites_templates_count;

		return $categories_count;
	}
}
