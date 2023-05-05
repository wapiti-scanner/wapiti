<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Main class file for the Widget Visibility module.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Assets;

/**
 * Hide or show legacy widgets conditionally.
 *
 * This class has two responsiblities - administrating the conditions in which legacy widgets may be hidden or shown
 * and hiding/showing the legacy widgets on the front-end of the site, depending upon the evaluation of those conditions.
 *
 * Administrating the conditions can be done in one of four different WordPress screens, plus direct use of the API and
 * is supplemented with a legacy widget preview screen. The four different admin screens are
 *
 * Gutenberg widget experience - widget admin (widgets.php + API + legacy widget preview)
 * Gutenberg widget experience - Customizer (customizer screen/API + API + legacy widget preview)
 * Classic widget experience - widget admin (widgets.php + admin-ajax XHR requests)
 * Classic widget experience - Customizer (customizer screen/API)
 *
 * An introduction to the API endpoints can be found here: https://make.wordpress.org/core/2021/06/29/rest-api-changes-in-wordpress-5-8/
 */
class Jetpack_Widget_Conditions {
	/**
	 * Stores condition for template_redirect action.
	 *
	 * @var bool
	 */
	public static $passed_template_redirect = false;

	/**
	 * Class initializer.
	 */
	public static function init() {
		global $pagenow;

		// The Gutenberg based widget experience will show a preview of legacy widgets by including a URL beginning
		// widgets.php?legacy-widget-preview inside an iframe. Previews don't need widget editing loaded and also don't
		// want to run the filter - if the widget is filtered out it'll be empty, which would be confusing.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['legacy-widget-preview'] ) ) {
			return;
		}

		// If action is posted and it's save-widget then it's relevant to widget conditions, otherwise it's something
		// else and it's not worth registering hooks.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( isset( $_POST['action'] ) && ! isset( $_POST['customize_changeset_uuid'] ) && ! in_array( $_POST['action'], array( 'save-widget', 'update-widget' ), true ) ) {
			return;
		}

		// API call to *list* the widget types doesn't use editing visibility or display widgets.
		if ( isset( $_SERVER['REQUEST_URI'] ) && false !== strpos( $_SERVER['REQUEST_URI'], '/widget-types?' ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			return;
		}

		$add_data_assets_to_page = false;
		$add_html_to_form        = false;
		$handle_widget_updates   = false;
		$add_block_controls      = false;

		// Check to see if using the customizer, but not using the preview. The preview should filter out widgets,
		// the customizer controls in the sidebar should not (so they can be edited).
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$customizer_not_previewer = is_customize_preview() && ! isset( $_GET['customize_changeset_uuid'] );
		$using_classic_experience = ( ! function_exists( 'wp_use_widgets_block_editor' ) || ! wp_use_widgets_block_editor() );
		if ( $using_classic_experience &&
			( $customizer_not_previewer || 'widgets.php' === $pagenow ||
				// phpcs:ignore WordPress.Security.NonceVerification.Missing
				( 'admin-ajax.php' === $pagenow && array_key_exists( 'action', $_POST ) && 'save-widget' === $_POST['action'] )
			)
		) {
			$add_data_assets_to_page = true;
			$add_html_to_form        = true;
			$handle_widget_updates   = true;
		} else {
			// On a screen that is hosting the API in the gutenberg editing experience.
			if ( $customizer_not_previewer || 'widgets.php' === $pagenow ) {
				$add_data_assets_to_page = true;
				$add_block_controls      = true;
			}

			// Encoding for a particular widget end point.
			if ( isset( $_SERVER['REQUEST_URI'] ) && 1 === preg_match( '|/widget-types/.*/encode|', $_SERVER['REQUEST_URI'] ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				$add_html_to_form      = true;
				$handle_widget_updates = true;
			}

			// Batch API is usually saving but could be anything.
			$current_url = ! empty( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
			if ( false !== strpos( $current_url, '/wp-json/batch/v1' ) || 1 === preg_match( '/^\/wp\/v2\/sites\/\d+\/batch\/v1/', $current_url ) ) {
				$handle_widget_updates = true;
				$add_html_to_form      = true;
			}

			// Saving widgets via non-batch API. This isn't used within WordPress but could be used by third parties in theory.
			if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'GET' !== $_SERVER['REQUEST_METHOD'] && false !== strpos( $_SERVER['REQUEST_URI'], '/wp/v2/widgets' ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				$handle_widget_updates = true;
				$add_html_to_form      = true;
			}
		}

		if ( $add_html_to_form ) {
			add_action( 'in_widget_form', array( __CLASS__, 'widget_conditions_admin' ), 10, 3 );
		}

		if ( $handle_widget_updates ) {
			add_filter( 'widget_update_callback', array( __CLASS__, 'widget_update' ), 10, 3 );
		}

		if ( $add_data_assets_to_page ) {
			add_action( 'sidebar_admin_setup', array( __CLASS__, 'widget_admin_setup' ) );
		}

		if ( $add_block_controls ) {
			add_action( 'enqueue_block_editor_assets', array( __CLASS__, 'setup_block_controls' ) );
		}

		if ( ! $add_html_to_form && ! $handle_widget_updates && ! $add_data_assets_to_page &&
			! in_array( $pagenow, array( 'wp-login.php', 'wp-register.php' ), true )
		) {
			// Not hit any known widget admin endpoint, register widget display hooks instead.
			add_filter( 'widget_display_callback', array( __CLASS__, 'filter_widget' ) );
			add_filter( 'sidebars_widgets', array( __CLASS__, 'sidebars_widgets' ) );
			add_action( 'template_redirect', array( __CLASS__, 'template_redirect' ) );
		}
	}

	/**
	 * Enqueue the block-based widget visibility scripts.
	 */
	public static function setup_block_controls() {
		Assets::register_script(
			'widget-visibility-editor',
			'_inc/build/widget-visibility/editor/index.js',
			JETPACK__PLUGIN_FILE,
			array(
				'in_footer'  => true,
				'textdomain' => 'jetpack',
			)
		);
		Assets::enqueue_script( 'widget-visibility-editor' );
	}

	/**
	 * Add the 'conditions' attribute, where visibility rules are stored, to some blocks.
	 *
	 * We normally add the block attributes in the browser's javascript env only,
	 * but these blocks use a ServerSideRender dynamic preview, so the php env needs
	 * to know about the new attribute, too.
	 */
	public static function add_block_attributes_filter() {
		$blocks_to_add_visibility_conditions = array(
			// These use <ServerSideRender>.
			'core/calendar',
			'core/latest-comments',
			'core/rss',
			'core/archives',
			'core/tag-cloud',
			'core/page-list',
			'core/latest-posts',
			'woocommerce/product-categories',
		);

		$filter_metadata_registration = function ( $settings, $metadata ) use ( $blocks_to_add_visibility_conditions ) {
			if ( in_array( $metadata['name'], $blocks_to_add_visibility_conditions, true ) && ! empty( $settings['attributes'] ) ) {
				$settings['attributes']['conditions'] = array(
					'type' => 'object',
				);
			}
			return $settings;
		};

		add_filter( 'block_type_metadata_settings', $filter_metadata_registration, 10, 2 );
	}

	/**
	 * Prepare the interface for editing widgets - loading css, javascript & data
	 */
	public static function widget_admin_setup() {
		wp_enqueue_style( 'widget-conditions', plugins_url( 'widget-conditions/widget-conditions.css', __FILE__ ), array( 'widgets' ), JETPACK__VERSION );
		wp_style_add_data( 'widget-conditions', 'rtl', 'replace' );
		wp_enqueue_script(
			'widget-conditions',
			Assets::get_file_url_for_environment(
				'_inc/build/widget-visibility/widget-conditions/widget-conditions.min.js',
				'modules/widget-visibility/widget-conditions/widget-conditions.js'
			),
			array( 'jquery', 'jquery-ui-core' ),
			JETPACK__VERSION,
			true
		);

		// Set up a single copy of all of the data that Widget Visibility needs.
		// This allows all widget conditions to reuse the same data, keeping page size down
		// and eliminating the AJAX calls we used to have to use to fetch the minor rule options.
		$widget_conditions_data = array();

		$widget_conditions_data['category']   = array();
		$widget_conditions_data['category'][] = array( '', __( 'All category pages', 'jetpack' ) );

		$categories = get_categories(
			array(
				/**
				 * Specific a maximum number of categories to query for the Widget visibility UI.
				 *
				 * @module widget-visibility
				 *
				 * @since 9.1.0
				 *
				 * @param int $number Maximum number of categories displayed in the Widget visibility UI.
				 */
				'number'  => (int) apply_filters( 'jetpack_widget_visibility_max_number_categories', 1000 ),
				'orderby' => 'count',
				'order'   => 'DESC',
			)
		);
		usort( $categories, array( __CLASS__, 'strcasecmp_name' ) );

		foreach ( $categories as $category ) {
			$widget_conditions_data['category'][] = array( (string) $category->term_id, $category->name );
		}

		$widget_conditions_data['loggedin']   = array();
		$widget_conditions_data['loggedin'][] = array( 'loggedin', __( 'Logged In', 'jetpack' ) );
		$widget_conditions_data['loggedin'][] = array( 'loggedout', __( 'Logged Out', 'jetpack' ) );

		$widget_conditions_data['author']   = array();
		$widget_conditions_data['author'][] = array( '', __( 'All author pages', 'jetpack' ) );

		/*
		 * Query for users with publish caps.
		 */
		$authors_args = array(
			'orderby'    => 'name',
			'capability' => array( 'edit_posts' ),
			'fields'     => array( 'ID', 'display_name' ),
		);

		$authors = get_users( $authors_args );

		foreach ( $authors as $author ) {
			$widget_conditions_data['author'][] = array( (string) $author->ID, $author->display_name );
		}

		$widget_conditions_data['role'] = array();

		global $wp_roles;

		foreach ( $wp_roles->roles as $role_key => $role ) {
			$widget_conditions_data['role'][] = array( (string) $role_key, $role['name'] );
		}

		$widget_conditions_data['tag']   = array();
		$widget_conditions_data['tag'][] = array( '', __( 'All tag pages', 'jetpack' ) );

		$tags = get_tags(
			array(
				/**
				 * Specific a maximum number of tags to query for the Widget visibility UI.
				 *
				 * @module widget-visibility
				 *
				 * @since 9.1.0
				 *
				 * @param int $number Maximum number of tags displayed in the Widget visibility UI.
				 */
				'number'  => (int) apply_filters( 'jetpack_widget_visibility_max_number_tags', 1000 ),
				'orderby' => 'count',
				'order'   => 'DESC',
			)
		);
		usort( $tags, array( __CLASS__, 'strcasecmp_name' ) );

		foreach ( $tags as $tag ) {
			$widget_conditions_data['tag'][] = array( (string) $tag->term_id, $tag->name );
		}

		$widget_conditions_data['date']   = array();
		$widget_conditions_data['date'][] = array( '', __( 'All date archives', 'jetpack' ) );
		$widget_conditions_data['date'][] = array( 'day', __( 'Daily archives', 'jetpack' ) );
		$widget_conditions_data['date'][] = array( 'month', __( 'Monthly archives', 'jetpack' ) );
		$widget_conditions_data['date'][] = array( 'year', __( 'Yearly archives', 'jetpack' ) );

		$widget_conditions_data['page']   = array();
		$widget_conditions_data['page'][] = array( 'front', __( 'Front page', 'jetpack' ) );
		$widget_conditions_data['page'][] = array( 'posts', __( 'Posts page', 'jetpack' ) );
		$widget_conditions_data['page'][] = array( 'archive', __( 'Archive page', 'jetpack' ) );
		$widget_conditions_data['page'][] = array( '404', __( '404 error page', 'jetpack' ) );
		$widget_conditions_data['page'][] = array( 'search', __( 'Search results', 'jetpack' ) );

		$post_types = get_post_types( array( 'public' => true ), 'objects' );

		$widget_conditions_post_types         = array();
		$widget_conditions_post_type_archives = array();

		foreach ( $post_types as $post_type ) {
			$widget_conditions_post_types[]         = array( 'post_type-' . $post_type->name, $post_type->labels->singular_name );
			$widget_conditions_post_type_archives[] = array( 'post_type_archive-' . $post_type->name, $post_type->labels->name );
		}

		$widget_conditions_data['page'][] = array( __( 'Post type:', 'jetpack' ), $widget_conditions_post_types );

		$widget_conditions_data['page'][] = array( __( 'Post type Archives:', 'jetpack' ), $widget_conditions_post_type_archives );

		$pages = self::get_pages();

		$dropdown_tree_args = array(
			'depth'                 => 0,
			'child_of'              => 0,
			'selected'              => 0,
			'echo'                  => false,
			'name'                  => 'page_id',
			'id'                    => '',
			'class'                 => '',
			'show_option_none'      => '',
			'show_option_no_change' => '',
			'option_none_value'     => '',
			'value_field'           => 'ID',
		);
		$pages_dropdown     = walk_page_dropdown_tree( $pages, 0, $dropdown_tree_args );
		preg_match_all( '/value=.([0-9]+).[^>]*>([^<]+)</', $pages_dropdown, $page_ids_and_titles, PREG_SET_ORDER );
		$static_pages = array();

		foreach ( $page_ids_and_titles as $page_id_and_title ) {
			$static_pages[] = array( (string) $page_id_and_title[1], $page_id_and_title[2] );
		}

		$widget_conditions_data['page'][] = array( __( 'Static page:', 'jetpack' ), $static_pages );

		$widget_conditions_data['taxonomy']   = array();
		$widget_conditions_data['taxonomy'][] = array( '', __( 'All taxonomy pages', 'jetpack' ) );

		$taxonomies = get_taxonomies(
			/**
			 * Filters args passed to get_taxonomies.
			 *
			 * @see https://developer.wordpress.org/reference/functions/get_taxonomies/
			 *
			 * @since 5.3.0
			 *
			 * @module widget-visibility
			 *
			 * @param array $args Widget Visibility taxonomy arguments.
			 */
			apply_filters( 'jetpack_widget_visibility_tax_args', array( '_builtin' => false ) ),
			'objects'
		);

		usort( $taxonomies, array( __CLASS__, 'strcasecmp_name' ) );

		foreach ( $taxonomies as $taxonomy ) {
			$taxonomy_terms = get_terms(
				array( $taxonomy->name ),
				array(
					'number'     => 250,
					'hide_empty' => false,
				)
			);

			$widget_conditions_terms   = array();
			$widget_conditions_terms[] = array( $taxonomy->name, $taxonomy->labels->all_items );

			foreach ( $taxonomy_terms as $term ) {
				$widget_conditions_terms[] = array( $taxonomy->name . '_tax_' . $term->term_id, $term->name );
			}

			$widget_conditions_data['taxonomy'][] = array( $taxonomy->labels->name . ':', $widget_conditions_terms );
		}

		wp_localize_script( 'widget-conditions', 'widget_conditions_data', $widget_conditions_data );

		// Save a list of the IDs of all pages that have children for dynamically showing the "Include children" checkbox.
		$all_pages   = self::get_pages();
		$all_parents = array();

		foreach ( $all_pages as $page ) {
			if ( $page->post_parent ) {
				$all_parents[ (string) $page->post_parent ] = true;
			}
		}

		$front_page_id = get_option( 'page_on_front' );

		if ( isset( $all_parents[ $front_page_id ] ) ) {
			$all_parents['front'] = true;
		}

		wp_localize_script( 'widget-conditions', 'widget_conditions_parent_pages', $all_parents );
	}

	/**
	 * Retrieves a full list of all pages, containing just the IDs, post_parent, post_title, and post_status fields.
	 *
	 * Since the WordPress' `get_pages` function does not allow us to fetch only the fields mentioned
	 * above, we need to introduce a custom method using a direct SQL query fetching those.
	 *
	 * By fetching only those four fields and not populating the object cache for all the pages, we can
	 * improve the performance of the query on sites having a lot of pages.
	 *
	 * @see https://core.trac.wordpress.org/ticket/51469
	 *
	 * @return array List of all pages on the site (stdClass objects containing ID, post_title, post_parent, and post_status only).
	 */
	public static function get_pages() {
		global $wpdb;

		$last_changed = wp_cache_get_last_changed( 'posts' );
		$cache_key    = "get_pages:$last_changed";
		$pages        = wp_cache_get( $cache_key, 'widget_conditions' );
		if ( false === $pages ) {
			$pages = $wpdb->get_results( "SELECT {$wpdb->posts}.ID, {$wpdb->posts}.post_parent, {$wpdb->posts}.post_title, {$wpdb->posts}.post_status FROM {$wpdb->posts} WHERE {$wpdb->posts}.post_type = 'page' AND {$wpdb->posts}.post_status = 'publish' ORDER BY {$wpdb->posts}.post_title ASC" );
			wp_cache_set( $cache_key, $pages, 'widget_conditions' );
		}

		// Copy-pasted from the get_pages function. For usage in the `widget_conditions_get_pages` filter.
		$parsed_args = array(
			'child_of'     => 0,
			'sort_order'   => 'ASC',
			'sort_column'  => 'post_title',
			'hierarchical' => 1,
			'exclude'      => array(),
			'include'      => array(),
			'meta_key'     => '',
			'meta_value'   => '',
			'authors'      => '',
			'parent'       => -1,
			'exclude_tree' => array(),
			'number'       => '',
			'offset'       => 0,
			'post_type'    => 'page',
			'post_status'  => 'publish',
		);

		/**
		 * Filters the retrieved list of pages.
		 *
		 * @since 9.1.0
		 *
		 * @module widget-visibility
		 *
		 * @param stdClass[] $pages       Array of objects containing only the ID, post_parent, post_title, and post_status fields.
		 * @param array      $parsed_args Array of get_pages() arguments.
		 */
		return apply_filters( 'jetpack_widget_visibility_get_pages', $pages, $parsed_args );
	}

	/**
	 * Add the widget conditions to each widget in the admin.
	 *
	 * @param WP_Widget $widget Widget to add conditions settings to.
	 * @param null      $return unused.
	 * @param array     $instance The widget settings.
	 */
	public static function widget_conditions_admin( $widget, $return, $instance ) {
		$conditions = array();

		if ( isset( $instance['conditions'] ) ) {
			$conditions = $instance['conditions'];
		}

		if ( ! isset( $conditions['action'] ) ) {
			$conditions['action'] = 'show';
		}

		if ( empty( $conditions['rules'] ) ) {
			$conditions['rules'][] = array(
				'major'        => '',
				'minor'        => '',
				'has_children' => '',
			);
		}

		if ( empty( $conditions['match_all'] ) ) {
			$conditions['match_all'] = false;
		}

		?>
		<div
			class="
				widget-conditional
				<?php
				// $_POST['widget-conditions-visible'] is used in the classic widget experience to decide whether to
				// display the visibility panel open, e.g. when saving. In the gutenberg widget experience the POST
				// value will always be empty, but this is fine - it doesn't rerender the HTML when saving anyway.
				if (
						// phpcs:ignore WordPress.Security.NonceVerification.Missing
						empty( $_POST['widget-conditions-visible'] ) || '0' === $_POST['widget-conditions-visible']
					) {
					?>
						widget-conditional-hide
						<?php
				}
				?>
				<?php
				if ( ! empty( $conditions['match_all'] ) && $conditions['match_all'] ) {
					?>
						intersection
						<?php
				} else {
					?>
						conjunction
						<?php
				}
				?>
			">
			<input type="hidden" name="widget-conditions-visible" value="
			<?php
			if ( isset( $_POST['widget-conditions-visible'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
				echo esc_attr( filter_var( wp_unslash( $_POST['widget-conditions-visible'] ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
			} else {
				echo 0;
			}
			?>
			" />
			<?php
			if ( ! isset( $_POST['widget-conditions-visible'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
				?>
				<a href="#" class="button display-options"><?php esc_html_e( 'Visibility', 'jetpack' ); ?></a><?php } ?>
			<div class="widget-conditional-inner">
				<div class="condition-top">
					<?php
						printf(
							// translators: %s is a HTML select widget for widget visibility, 'show' and 'hide' are it's options. It will read like 'show if' or 'hide if'.
							esc_html_x( '%s if:', 'placeholder: dropdown menu to select widget visibility; hide if or show if', 'jetpack' ),
							'<select name="' . esc_attr( $widget->get_field_name( 'conditions[action]' ) ) . '">
											<option value="show" ' . selected( $conditions['action'], 'show', false ) . '>' . esc_html_x( 'Show', 'Used in the "%s if:" translation for the widget visibility dropdown', 'jetpack' ) . '</option>
											<option value="hide" ' . selected( $conditions['action'], 'hide', false ) . '>' . esc_html_x( 'Hide', 'Used in the "%s if:" translation for the widget visibility dropdown', 'jetpack' ) . '</option>
										</select>'
						);
					?>
				</div><!-- .condition-top -->

				<div class="conditions">
					<?php

					foreach ( $conditions['rules'] as $rule_index => $rule ) {
						$rule = wp_parse_args(
							$rule,
							array(
								'major'        => '',
								'minor'        => '',
								'has_children' => '',
							)
						);
						?>
						<div class="condition" data-rule-major="<?php echo esc_attr( $rule['major'] ); ?>" data-rule-minor="<?php echo esc_attr( $rule['minor'] ); ?>" data-rule-has-children="<?php echo esc_attr( $rule['has_children'] ); ?>">
							<div class="selection alignleft">
								<select class="conditions-rule-major" name="<?php echo esc_attr( $widget->get_field_name( 'conditions[rules_major][]' ) ); ?>">
									<option value="" <?php selected( '', $rule['major'] ); ?>><?php echo esc_html_x( '-- Select --', 'Used as the default option in a dropdown list', 'jetpack' ); ?></option>
									<option value="category" <?php selected( 'category', $rule['major'] ); ?>><?php esc_html_e( 'Category', 'jetpack' ); ?></option>
									<option value="author" <?php selected( 'author', $rule['major'] ); ?>><?php echo esc_html_x( 'Author', 'Noun, as in: "The author of this post is..."', 'jetpack' ); ?></option>

									<?php if ( ! ( defined( 'IS_WPCOM' ) && IS_WPCOM ) ) { // this doesn't work on .com because of caching. ?>
										<option value="loggedin" <?php selected( 'loggedin', $rule['major'] ); ?>><?php echo esc_html_x( 'User', 'Noun', 'jetpack' ); ?></option>
										<option value="role" <?php selected( 'role', $rule['major'] ); ?>><?php echo esc_html_x( 'Role', 'Noun, as in: "The user role of that can access this widget is..."', 'jetpack' ); ?></option>
									<?php } ?>

									<option value="tag" <?php selected( 'tag', $rule['major'] ); ?>><?php echo esc_html_x( 'Tag', 'Noun, as in: "This post has one tag."', 'jetpack' ); ?></option>
									<option value="date" <?php selected( 'date', $rule['major'] ); ?>><?php echo esc_html_x( 'Date', 'Noun, as in: "This page is a date archive."', 'jetpack' ); ?></option>
									<option value="page" <?php selected( 'page', $rule['major'] ); ?>><?php echo esc_html_x( 'Page', 'Example: The user is looking at a page, not a post.', 'jetpack' ); ?></option>
									<?php if ( get_taxonomies( array( '_builtin' => false ) ) ) : ?>
										<option value="taxonomy" <?php selected( 'taxonomy', $rule['major'] ); ?>><?php echo esc_html_x( 'Taxonomy', 'Noun, as in: "This post has one taxonomy."', 'jetpack' ); ?></option>
									<?php endif; ?>
								</select>

								<?php echo esc_html_x( 'is', 'Widget Visibility: {Rule Major [Page]} is {Rule Minor [Search results]}', 'jetpack' ); ?>

								<select class="conditions-rule-minor" name="<?php echo esc_attr( $widget->get_field_name( 'conditions[rules_minor][]' ) ); ?>"
								<?php
								if ( ! $rule['major'] ) {
									echo ' disabled="disabled"';
								}
								?>
								>
									<?php
									/*
									Include the currently selected value so that if the widget is saved without
									expanding the Visibility section, we don't lose the minor part of the rule.
									If it is opened, this list is cleared out and populated with all the values.
									*/
									?>
									<option value="<?php echo esc_attr( $rule['minor'] ); ?>" selected="selected"></option>
								</select>

								<span class="conditions-rule-has-children"
								<?php
								if ( ! $rule['has_children'] ) {
									echo ' style="display: none;"';
								}
								?>
								>
									<label>
										<input type="checkbox" name="<?php echo esc_attr( $widget->get_field_name( "conditions[page_children][$rule_index]" ) ); ?>" value="has" <?php checked( $rule['has_children'], true ); ?> />
										<?php echo esc_html_x( 'Include children', 'Checkbox on Widget Visibility if children of the selected page should be included in the visibility rule.', 'jetpack' ); ?>
									</label>
								</span>
							</div>

							<div class="condition-control">
								<span class="condition-conjunction">
									<?php echo esc_html_x( 'or', 'Shown between widget visibility conditions.', 'jetpack' ); ?>
								</span>
								<span class="condition-intersection">
									<?php echo esc_html_x( 'and', 'Shown between widget visibility conditions.', 'jetpack' ); ?>
								</span>
								<div class="actions alignright">
									<a href="#" class="delete-condition dashicons dashicons-no"><?php esc_html_e( 'Delete', 'jetpack' ); ?></a><a href="#" class="add-condition dashicons dashicons-plus"><?php esc_html_e( 'Add', 'jetpack' ); ?></a>
								</div>
							</div>

						</div><!-- .condition -->
						<?php
					}

					?>
				</div><!-- .conditions -->
				<div class="conditions">
					<div class="condition-top">
						<label>
							<input
								type="checkbox"
								name="<?php echo esc_attr( $widget->get_field_name( 'conditions[match_all]' ) ); ?>"
								value="1"
								class="conditions-match-all"
								<?php checked( $conditions['match_all'], '1' ); ?> />
							<?php esc_html_e( 'Match all conditions', 'jetpack' ); ?>
						</label>
					</div><!-- .condition-top -->
				</div><!-- .conditions -->
			</div><!-- .widget-conditional-inner -->
		</div><!-- .widget-conditional -->
		<?php
	}

	/**
	 * On an AJAX update of the widget settings, process the display conditions.
	 *
	 * @param array $instance The current instance's settings.
	 * @param array $new_instance New settings for this instance as input by the user.
	 * @param array $old_instance Old settings for this instance.
	 * @return array Modified settings.
	 */
	public static function widget_update( $instance, $new_instance, $old_instance ) {
		$conditions              = array();
		$conditions['action']    = isset( $new_instance['conditions']['action'] ) ? $new_instance['conditions']['action'] : null;
		$conditions['match_all'] = ! empty( $new_instance['conditions']['match_all'] ) ? '1' : '0';
		$conditions['rules']     = isset( $new_instance['conditions']['rules'] ) ? $new_instance['conditions']['rules'] : array();

		if ( isset( $new_instance['conditions']['rules_major'] ) ) {
			foreach ( $new_instance['conditions']['rules_major'] as $index => $major_rule ) {
				if ( ! $major_rule ) {
					continue;
				}

				$conditions['rules'][] = array(
					'major'        => $major_rule,
					'minor'        => isset( $new_instance['conditions']['rules_minor'][ $index ] ) ? $new_instance['conditions']['rules_minor'][ $index ] : '',
					'has_children' => isset( $new_instance['conditions']['page_children'][ $index ] ) ? true : false,
				);
			}
		}

		if ( ! empty( $conditions['rules'] ) ) {
			$instance['conditions'] = $conditions;
		} elseif ( empty( $new_instance['conditions']['rules'] ) ) {
			unset( $instance['conditions'] );
		}

		if (
				( isset( $instance['conditions'] ) && ! isset( $old_instance['conditions'] ) )
				||
				(
					isset( $instance['conditions'], $old_instance['conditions'] )
					&&
					serialize( $instance['conditions'] ) !== serialize( $old_instance['conditions'] ) // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize
				)
			) {

			/**
			 * Fires after the widget visibility conditions are saved.
			 *
			 * @module widget-visibility
			 *
			 * @since 2.4.0
			 */
			do_action( 'widget_conditions_save' );
		} elseif ( ! isset( $instance['conditions'] ) && isset( $old_instance['conditions'] ) ) {

			/**
			 * Fires after the widget visibility conditions are deleted.
			 *
			 * @module widget-visibility
			 *
			 * @since 2.4.0
			 */
			do_action( 'widget_conditions_delete' );
		}

		return $instance;
	}

	/**
	 * Filter the list of widgets for a sidebar so that active sidebars work as expected.
	 *
	 * @param array $widget_areas An array of widget areas and their widgets.
	 * @return array The modified $widget_area array.
	 */
	public static function sidebars_widgets( $widget_areas ) {
		$settings = array();

		if ( ! is_array( $widget_areas ) ) {
			return $widget_areas;
		}

		foreach ( $widget_areas as $widget_area => $widgets ) {
			if ( empty( $widgets ) ) {
				continue;
			}

			if ( ! is_array( $widgets ) ) {
				continue;
			}

			if ( 'wp_inactive_widgets' === $widget_area ) {
				continue;
			}

			foreach ( $widgets as $position => $widget_id ) {
				// Find the conditions for this widget.
				if ( preg_match( '/^(.+?)-(\d+)$/', $widget_id, $matches ) ) {
					$id_base       = $matches[1];
					$widget_number = (int) $matches[2];
				} else {
					$id_base       = $widget_id;
					$widget_number = null;
				}

				if ( ! isset( $settings[ $id_base ] ) ) {
					$settings[ $id_base ] = get_option( 'widget_' . $id_base );
				}

				// New multi widget (WP_Widget).
				if ( $widget_number !== null ) {
					if ( isset( $settings[ $id_base ][ $widget_number ] ) && false === self::filter_widget( $settings[ $id_base ][ $widget_number ] ) ) {
						unset( $widget_areas[ $widget_area ][ $position ] );
					}
				} elseif ( ! empty( $settings[ $id_base ] ) && false === self::filter_widget( $settings[ $id_base ] ) ) { // Old single widget.
					unset( $widget_areas[ $widget_area ][ $position ] );
				}
			}
		}

		return $widget_areas;
	}

	/**
	 * Set field $passed_template_redirect to true.
	 */
	public static function template_redirect() {
		self::$passed_template_redirect = true;
	}

	/**
	 * Generates a condition key based on the rule array.
	 *
	 * @param array $rule rule data.
	 * @return string key used to retrieve the condition.
	 */
	public static function generate_condition_key( $rule ) {
		if ( isset( $rule['has_children'] ) ) {
			return $rule['major'] . ':' . $rule['minor'] . ':' . $rule['has_children'];
		}
		return $rule['major'] . ':' . $rule['minor'];
	}

	/**
	 * Determine whether the widget should be displayed based on conditions set by the user.
	 *
	 * @param array $instance The widget settings.
	 * @return array Settings to display or bool false to hide.
	 */
	public static function filter_widget( $instance ) {
		// Don't filter widgets from the REST API when it's called via the widgets admin page - otherwise they could get
		// filtered out and become impossible to edit.
		if ( strpos( wp_get_raw_referer(), '/wp-admin/widgets.php' ) && isset( $_SERVER['REQUEST_URI'] ) && false !== strpos( filter_var( wp_unslash( $_SERVER['REQUEST_URI'] ) ), '/wp-json/' ) ) {
			return $instance;
		}
		// WordPress.com specific check - here, referer ends in /rest-proxy/ and doesn't tell us what's requesting.
		$current_url = ! empty( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$nonce       = ! empty( $_REQUEST['_gutenberg_nonce'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['_gutenberg_nonce'] ) ) : '';
		$context     = ! empty( $_REQUEST['context'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['context'] ) ) : '';
		if ( wp_verify_nonce( $nonce, 'gutenberg_request' ) &&
			1 === preg_match( '~^/wp/v2/sites/\d+/(sidebars|widgets)~', $current_url ) && 'edit' === $context ) {
			return $instance;
		}

		if ( ! empty( $instance['conditions']['rules'] ) ) {
			// Legacy widgets: visibility found.
			if ( self::filter_widget_check_conditions( $instance['conditions'] ) ) {
				return $instance;
			}
			return false;
		} elseif ( ! empty( $instance['content'] ) && has_blocks( $instance['content'] ) ) {
			// Block-Based widgets: We have gutenberg blocks that could have the 'conditions' attribute.
			$blocks = parse_blocks( $instance['content'] );
			if ( empty( $blocks[0]['attrs']['conditions']['rules'] ) ) {
				// No Rules: Display widget.
				return $instance;
			}
			if ( self::filter_widget_check_conditions( $blocks[0]['attrs']['conditions'] ) ) {
				// Rules passed checks: Display widget.
				return $instance;
			}
			// Rules failed checks: Hide widget.
			return false;
		}

		// No visibility found.
		return $instance;
	}

	/**
	 * Determine whether the widget should be displayed based on conditions set by the user.
	 *
	 * @param array $conditions Visibility Conditions: An array with keys 'rules', 'action', and 'match_all'.
	 * @return bool If the widget controlled by these conditions should show.
	 */
	public static function filter_widget_check_conditions( $conditions ) {
		global $wp_query;
		// Store the results of all in-page condition lookups so that multiple widgets with
		// the same visibility conditions don't result in duplicate DB queries.
		static $condition_result_cache = array();

		$condition_result = false;

		foreach ( $conditions['rules'] as $rule ) {
			$condition_result = false;
			$condition_key    = self::generate_condition_key( $rule );

			if ( isset( $condition_result_cache[ $condition_key ] ) ) {
				$condition_result = $condition_result_cache[ $condition_key ];
			} else {
				switch ( $rule['major'] ) {
					case 'date':
						switch ( $rule['minor'] ) {
							case '':
								$condition_result = is_date();
								break;
							case 'month':
								$condition_result = is_month();
								break;
							case 'day':
								$condition_result = is_day();
								break;
							case 'year':
								$condition_result = is_year();
								break;
						}
						break;
					case 'page':
						// Previously hardcoded post type options.
						if ( 'post' === $rule['minor'] ) {
							$rule['minor'] = 'post_type-post';
						} elseif ( ! $rule['minor'] ) {
							$rule['minor'] = 'post_type-page';
						}

						switch ( $rule['minor'] ) {
							case '404':
								$condition_result = is_404();
								break;
							case 'search':
								$condition_result = is_search();
								break;
							case 'archive':
								$condition_result = is_archive();
								break;
							case 'posts':
								$condition_result = $wp_query->is_posts_page;
								break;
							case 'home':
								$condition_result = is_home();
								break;
							case 'front':
								if ( current_theme_supports( 'infinite-scroll' ) ) {
									$condition_result = is_front_page();
								} else {
									$condition_result = is_front_page() && ! is_paged();
								}
								break;
							default:
								if ( substr( $rule['minor'], 0, 10 ) === 'post_type-' ) {
									$condition_result = is_singular( substr( $rule['minor'], 10 ) );
								} elseif ( substr( $rule['minor'], 0, 18 ) === 'post_type_archive-' ) {
									$condition_result = is_post_type_archive( substr( $rule['minor'], 18 ) );
								} elseif ( get_option( 'page_for_posts' ) === $rule['minor'] ) {
									// If $rule['minor'] is a page ID which is also the posts page.
									$condition_result = $wp_query->is_posts_page;
								} else {
									// $rule['minor'] is a page ID
									$condition_result = is_page() && ( get_the_ID() === (int) $rule['minor'] );

									// Check if $rule['minor'] is parent of page ID.
									if ( ! $condition_result && isset( $rule['has_children'] ) && $rule['has_children'] ) {
										$condition_result = wp_get_post_parent_id( get_the_ID() ) === (int) $rule['minor'];
									}
								}
								break;
						}
						break;
					case 'tag':
						// All tag pages.
						if ( ! $rule['minor'] ) {
							if ( is_tag() ) {
								$condition_result = true;
							} elseif ( is_singular() ) {
								if ( in_array( 'post_tag', get_post_taxonomies(), true ) ) {
									$condition_result = true;
								}
							}
							break;
						}

						// All pages with the specified tag term.
						if ( is_tag( $rule['minor'] ) ) {
							$condition_result = true;
						} elseif ( is_singular() && has_term( $rule['minor'], 'post_tag' ) ) {
							$condition_result = true;
						}
						break;
					case 'category':
						// All category pages.
						if ( ! $rule['minor'] ) {
							if ( is_category() ) {
								$condition_result = true;
							} elseif ( is_singular() ) {
								if ( in_array( 'category', get_post_taxonomies(), true ) ) {
									$condition_result = true;
								}
							}
							break;
						}

						// All pages with the specified category term.
						if ( is_category( $rule['minor'] ) ) {
							$condition_result = true;
						} elseif ( is_singular() && has_term( $rule['minor'], 'category' ) ) {
							$condition_result = true;
						}
						break;
					case 'loggedin':
						$condition_result = is_user_logged_in();
						if ( 'loggedin' !== $rule['minor'] ) {
							$condition_result = ! $condition_result;
						}
						break;
					case 'author':
						$post = get_post();
						if ( ! $rule['minor'] && is_author() ) {
							$condition_result = true;
						} elseif ( $rule['minor'] && is_author( $rule['minor'] ) ) {
							$condition_result = true;
						} elseif ( is_singular() && $rule['minor'] && $rule['minor'] === $post->post_author ) {
							$condition_result = true;
						}
						break;
					case 'role':
						if ( is_user_logged_in() ) {
							$current_user = wp_get_current_user();

							$user_roles = $current_user->roles;

							if ( in_array( $rule['minor'], $user_roles, true ) ) {
								$condition_result = true;
							} else {
								$condition_result = false;
							}
						} else {
							$condition_result = false;
						}
						break;
					case 'post_type':
						if ( substr( $rule['minor'], 0, 10 ) === 'post_type-' ) {
							$condition_result = is_singular( substr( $rule['minor'], 10 ) );
						} elseif ( substr( $rule['minor'], 0, 18 ) === 'post_type_archive-' ) {
							$condition_result = is_post_type_archive( substr( $rule['minor'], 18 ) );
						}
						break;
					case 'taxonomy':
						// All taxonomy pages.
						if ( ! $rule['minor'] ) {
							if ( is_archive() ) {
								if ( is_tag() || is_category() || is_tax() ) {
									$condition_result = true;
								}
							} elseif ( is_singular() ) {
								$post_taxonomies  = get_post_taxonomies();
								$condition_result = ! empty( $post_taxonomies );
							}
							break;
						}

						// Specified taxonomy page.
						$term = explode( '_tax_', $rule['minor'] ); // $term[0] is taxonomy name; $term[1] is term id.
						if ( isset( $term[0] ) && isset( $term[1] ) ) {
							$term[1] = self::maybe_get_split_term( $term[1], $term[0] );
						}

						// All pages of the specified taxonomy.
						if ( ! isset( $term[1] ) || ! $term[1] ) {
							if ( is_tax( $term[0] ) ) {
								$condition_result = true;
							} elseif ( is_singular() ) {
								if ( in_array( $term[0], get_post_taxonomies(), true ) ) {
									$condition_result = true;
								}
							}
							break;
						}

						// All pages with the specified taxonomy term.
						if ( is_tax( $term[0], $term[1] ) ) {
							$condition_result = true;
						} elseif ( is_singular() && has_term( $term[1], $term[0] ) ) {
							$condition_result = true;
						}
						break;
				}

				if ( $condition_result || self::$passed_template_redirect ) {
					// Some of the conditions will return false when checked before the template_redirect
					// action has been called, like is_page(). Only store positive lookup results, which
					// won't be false positives, before template_redirect, and everything after.
					$condition_result_cache[ $condition_key ] = $condition_result;
				}
			}

			if (
				isset( $conditions['match_all'] )
				&& '1' === $conditions['match_all']
				&& ! $condition_result
			) {

				// In case the match_all flag was set we quit on first failed condition.
				break;
			} elseif (
				(
					empty( $conditions['match_all'] )
					|| '1' !== $conditions['match_all']
				)
				&& $condition_result
			) {

				// Only quit on first condition if the match_all flag was not set.
				break;
			}
		}

		if (
			(
				'show' === $conditions['action']
				&& ! $condition_result
			) || (
				'hide' === $conditions['action']
				&& $condition_result
			)
		) {
			return false;
		}

		return true;
	}

	/**
	 * Helper function wrapping strcasecmp to compare term names.
	 *
	 * @param string $a str1.
	 * @param string $b str2.
	 */
	public static function strcasecmp_name( $a, $b ) {
		return strcasecmp( $a->name, $b->name );
	}

	/**
	 * Determine if provided term has been split.
	 *
	 * @param int    $old_term_id Old term id to test.
	 * @param string $taxonomy Taxonmy that $old_term_id belongs to.
	 */
	public static function maybe_get_split_term( $old_term_id = '', $taxonomy = '' ) {
		$term_id = $old_term_id;

		if ( 'tag' === $taxonomy ) {
			$taxonomy = 'post_tag';
		}

		$new_term_id = wp_get_split_term( $old_term_id, $taxonomy );
		if ( $new_term_id ) {
			$term_id = $new_term_id;
		}

		return $term_id;
	}

	/**
	 * Upgrade routine to go through all widgets and move the Post Type
	 * setting to its newer location.
	 *
	 * @since 4.7.1
	 */
	public static function migrate_post_type_rules() {
		global $wp_registered_widgets;

		$sidebars_widgets = get_option( 'sidebars_widgets' );

		// Going through all sidebars and through inactive and orphaned widgets.
		foreach ( $sidebars_widgets as $sidebar ) {
			if ( ! is_array( $sidebar ) ) {
				continue;
			}

			foreach ( $sidebar as $widget ) {
				// $widget is the id of the widget
				if ( empty( $wp_registered_widgets[ $widget ] ) ) {
					continue;
				}

				$opts      = $wp_registered_widgets[ $widget ];
				$instances = get_option( $opts['callback'][0]->option_name );

				if ( ! is_array( $instances ) || empty( $instances ) ) {
					continue;
				}

				// Going through each instance of the widget.
				foreach ( $instances as $number => $instance ) {
					if (
						! is_array( $instance ) ||
						empty( $instance['conditions'] ) ||
						empty( $instance['conditions']['rules'] )
					) {
						continue;
					}

					// Going through all visibility rules.
					foreach ( $instance['conditions']['rules'] as $index => $rule ) {

						// We only need Post Type rules.
						if ( 'post_type' !== $rule['major'] ) {
							continue;
						}

						$rule_type = false;

						// Post type or type archive rule.
						if ( 0 === strpos( $rule['minor'], 'post_type_archive' ) ) {
							$rule_type = 'post_type_archive';
						} elseif ( 0 === strpos( $rule['minor'], 'post_type' ) ) {
							$rule_type = 'post_type';
						}

						if ( $rule_type ) {
							$post_type     = substr( $rule['minor'], strlen( $rule_type ) + 1 );
							$rule['minor'] = $rule_type . '-' . $post_type;
							$rule['major'] = 'page';

							$instances[ $number ]['conditions']['rules'][ $index ] = $rule;
						}
					}
				}

				update_option( $opts['callback'][0]->option_name, $instances );
			}
		}
	}

}

add_action( 'init', array( 'Jetpack_Widget_Conditions', 'init' ) );

// Add the 'conditions' attribute to server side rendered blocks
// 'init' happens too late to hook on block registration.
global $pagenow;
$current_url = ! empty( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
if ( is_customize_preview()
	|| 'widgets.php' === $pagenow
	|| ( false !== strpos( $current_url, '/wp-json/wp/v2/block-renderer' ) )
	|| 1 === preg_match( '~^/wp/v2/sites/\d+/block-renderer~', $current_url )
) {
	Jetpack_Widget_Conditions::add_block_attributes_filter();
}
