<?php
/**
 * Template tags class used primarily for rendering widget-related HTML.
 *
 * @package    automattic/jetpack-search
 */

namespace Automattic\Jetpack\Search;

/**
 * Class that has various methods for outputting functionality into a theme that doesn't support widgets.
 * Additionally the widget itself makes use of these class.
 *
 * @since 5.8.0
 */
class Template_Tags {

	/**
	 * Renders all available filters that can be used to filter down search results on the frontend.
	 *
	 * @since 5.8.0
	 *
	 * @param array $filters    The available filters for the current query.
	 * @param array $post_types An array of post types to make filterable.
	 */
	public static function render_available_filters( $filters = null, $post_types = null ) {
		if ( $filters === null ) {
			$filters = Classic_Search::instance()->get_filters();
		}

		if ( $post_types === null ) {
			$post_types = get_post_types( array( 'exclude_from_search' => false ) );
		}

		/**
		 * If the post types specified by the widget differ from the default set of searchable post types,
		 * then we need to track their state.
		 */
		$active_post_types = array();
		if ( Helper::post_types_differ_searchable( $post_types ) ) {
			// get the active filter buckets from the query.
			$active_buckets          = Classic_Search::instance()->get_active_filter_buckets();
			$post_types_differ_query = Helper::post_types_differ_query( $post_types );

			// remove any post_type filters from display if the current query
			// already specifies to match all post types.
			if ( ! $post_types_differ_query ) {
				$active_buckets = array_filter( $active_buckets, array( __CLASS__, 'is_not_post_type_filter' ) );
			}

			$active_post_types = Helper::get_active_post_types( $active_buckets );
			if ( empty( $active_post_types ) ) {
				$active_post_types = $post_types;
			}

			if ( $post_types_differ_query ) {
				$filters = Helper::ensure_post_types_on_remove_url( $filters, $post_types );
			} else {
				$filters = Helper::remove_active_from_post_type_buckets( $filters );
			}
		} else {
			$post_types = array();
		}

		foreach ( (array) $filters as $filter ) {
			if ( 'post_type' === $filter['type'] ) {
				self::render_filter( $filter, $post_types );
			} else {
				self::render_filter( $filter, $active_post_types );
			}
		}
	}

	/**
	 * Renders filters for instant search.
	 *
	 * @param array $filters    The available filters for the current query.
	 */
	public static function render_instant_filters( $filters = null ) {
		if ( $filters === null ) {
			$filters = Classic_Search::instance()->get_filters();
		}

		foreach ( (array) $filters as $filter ) {
			self::render_instant_filter( $filter );
		}
	}

	/**
	 * Renders a single filter that can be applied to the current search.
	 *
	 * @since 5.8.0
	 *
	 * @param array $filter             The filter to render.
	 * @param array $default_post_types The default post types for this filter.
	 */
	public static function render_filter( $filter, $default_post_types ) {
		if ( empty( $filter ) || empty( $filter['buckets'] ) ) {
			return;
		}

		$query_vars = null;
		foreach ( $filter['buckets'] as $item ) {
			if ( $item['active'] ) {
				$query_vars = array_keys( $item['query_vars'] );
				break;
			}
		}
		$clear_url = null;
		if ( ! empty( $query_vars ) ) {
			$clear_url = Helper::remove_query_arg( $query_vars );
			if ( ! empty( $default_post_types ) ) {
				$clear_url = Helper::add_post_types_to_url( $clear_url, $default_post_types );
			}
		}

		?>
		<h4 class="jetpack-search-filters-widget__sub-heading">
			<?php echo esc_html( $filter['name'] ); ?>
		</h4>
		<?php if ( $clear_url ) : ?>
			<div class="jetpack-search-filters-widget__clear">
				<a href="<?php echo esc_url( $clear_url ); ?>">
					<?php esc_html_e( '< Clear Filters', 'jetpack-search-pkg' ); ?>
				</a>
			</div>
		<?php endif; ?>
		<ul class="jetpack-search-filters-widget__filter-list">
			<?php
			foreach ( $filter['buckets'] as $item ) :
				$url = ( empty( $item['active'] ) ) ? $item['url'] : $item['remove_url'];
				?>
				<li>
					<label>
						<input type="checkbox"<?php checked( ! empty( $item['active'] ) ); ?> disabled="disabled" />&nbsp;
						<a href="<?php echo esc_url( $url ); ?>">
							<?php
								echo esc_html( $item['name'] );
								echo '&nbsp;';
								echo esc_html(
									sprintf(
										'(%s)',
										number_format_i18n( absint( $item['count'] ) )
									)
								);
							?>
						</a>
					</label>
				</li>
			<?php endforeach; ?>
		</ul>
		<?php
	}

	/**
	 * Renders a single filter for instant search.
	 *
	 * @since 8.3.0
	 *
	 * @param array $filter             The filter to render.
	 */
	public static function render_instant_filter( $filter ) {
		if ( empty( $filter ) || empty( $filter['buckets'] ) ) {
			return;
		}

		$data_base = '';
		$qv        = $filter['buckets'][0]['query_vars'];
		$tax_key   = '';
		switch ( $filter['buckets'][0]['type'] ) {
			case 'taxonomy':
				$data_base = 'data-filter-type="' . esc_attr( $filter['buckets'][0]['type'] ) . '" ';
				$tax_key   = key( $qv );
				if ( 'category_name' === $tax_key ) {
					$data_base .= 'data-taxonomy="category"';
				} elseif ( 'tag' === $tax_key ) {
					$data_base .= 'data-taxonomy="post_tag"';
				} else {
					$data_base .= 'data-taxonomy="' . esc_attr( $tax_key ) . '"';
				}
				break;
			case 'post_type':
				$data_base = 'data-filter-type="post_types" ';
				break;
			case 'author':
				$data_base = 'data-filter-type="authors" ';
				break;
			case 'blog_id':
				$data_base = 'data-filter-type="blog_ids" ';
				break;
			case 'date_histogram':
				if ( $filter['buckets'][0]['query_vars']['monthnum'] ) {
					$data_base = 'data-filter-type="month_post_date" ';
				} else {
					$data_base = 'data-filter-type="year_post_date" ';
				}
				break;
		}

		?>
		<h4 class="jetpack-search-filters-widget__sub-heading">
			<?php echo esc_html( $filter['name'] ); ?>
		</h4>
		<ul class="jetpack-search-filters-widget__filter-list">
			<?php
			foreach ( $filter['buckets'] as $item ) :
				$data_str = $data_base . ' ';
				switch ( $filter['buckets'][0]['type'] ) {
					case 'taxonomy':
						$data_str .= 'data-val="' . esc_attr( $item['query_vars'][ $tax_key ] ) . '"';
						break;
					case 'post_type':
						$data_str .= 'data-val="' . esc_attr( $item['query_vars']['post_type'] ) . '"';
						break;
					case 'author':
						$data_str .= 'data-val="' . esc_attr( $item['query_vars']['author'] ) . '"';
						break;
					case 'blog_id':
						$data_str .= 'data-val="' . esc_attr( $item['query_vars']['blog_id'] ) . '"';
						break;
					case 'date_histogram':
						if ( $item['query_vars']['monthnum'] ) {
							$d = sprintf( '%d-%02d-01 00:00:00', $item['query_vars']['year'], $item['query_vars']['monthnum'] );
						} else {
							$d = sprintf( '%d-01-01 00:00:00', $item['query_vars']['year'] );
						}
						$data_str .= 'data-val="' . esc_attr( $d ) . '" ';
						break;
				}
				?>
				<li>
				<?php // TODO: Figure out how to properly escape $data_str below. ?>
				<a href="#" class="jetpack-search-filter__link" <?php echo $data_str; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>>
						<?php
							echo esc_html( $item['name'] );
							echo '&nbsp;';
							echo esc_html(
								sprintf(
									'(%s)',
									number_format_i18n( absint( $item['count'] ) )
								)
							);
						?>
					</a>
				</li>
			<?php endforeach; ?>
		</ul>
		<?php
	}

	/**
	 * Outputs the search widget's title.
	 *
	 * @since 5.8.0
	 *
	 * @param string $title        The widget's title.
	 * @param string $before_title The HTML tag to display before the title.
	 * @param string $after_title  The HTML tag to display after the title.
	 */
	public static function render_widget_title( $title, $before_title, $after_title ) {
		// This doesn't need to be escaped because it's provided by WP and goes through filters, where it is not escaped.
		echo $before_title . $title . $after_title; //phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}

	/**
	 * Responsible for rendering the search box within our widget on the frontend.
	 *
	 * @since 5.8.0
	 *
	 * @param array  $post_types Array of post types to limit search results to.
	 * @param string $orderby    How to order the search results.
	 * @param string $order      In what direction to order the search results.
	 */
	public static function render_widget_search_form( $post_types, $orderby, $order ) {
		$form = get_search_form( false );

		$fields_to_inject = array(
			'orderby' => $orderby,
			'order'   => $order,
		);

		// If the widget has specified post types to search within and IF the post types differ
		// from the default post types that would have been searched, set the selected post
		// types via hidden inputs.
		if ( Helper::post_types_differ_searchable( $post_types ) ) {
			$fields_to_inject['post_type'] = implode( ',', $post_types );
		}

		$form = self::inject_hidden_form_fields( $form, $fields_to_inject );

		echo '<div class="jetpack-search-form">';
		// TODO: Figure out how to properly escape this.
		echo $form; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '</div>';
	}

	/**
	 * Modifies an HTML form to add some additional hidden fields.
	 *
	 * @since 5.8.0
	 *
	 * @param string $form   The form HTML to modify.
	 * @param array  $fields Array of hidden fields to add. Key is field name and value is the field value.
	 *
	 * @return string The modified form HTML.
	 */
	private static function inject_hidden_form_fields( $form, $fields ) {
		$form_injection = '';

		foreach ( $fields as $field_name => $field_value ) {
			$form_injection .= sprintf(
				'<input type="hidden" name="%s" value="%s" />',
				esc_attr( $field_name ),
				esc_attr( $field_value )
			);
		}

		// This shouldn't need to be escaped since we've escaped above as we built $form_injection.
		$form = str_replace(
			'</form>',
			$form_injection . '</form>',
			$form
		);

		return $form;
	}

	/**
	 * Internal method for filtering out non-post_type filters.
	 *
	 * @since 5.8.0
	 *
	 * @param array $filter Filter object.
	 *
	 * @return bool
	 */
	private static function is_not_post_type_filter( $filter ) {
		return 'post_type' !== $filter['type'];
	}
}
