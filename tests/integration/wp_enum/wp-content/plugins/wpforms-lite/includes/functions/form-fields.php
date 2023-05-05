<?php
/**
 * Helper functions to work with form fields, generic and specific to certain field types.
 *
 * @since 1.8.0
 */

/**
 * Determine if we should show the "Show Values" toggle for checkbox, radio, or
 * select fields in form builder. Legacy.
 *
 * @since 1.5.0
 *
 * @return bool
 */
function wpforms_show_fields_options_setting() {

	return apply_filters( 'wpforms_fields_show_options_setting', false );
}

/**
 * Return field choice properties for field configured with dynamic choices.
 *
 * @since 1.4.5
 *
 * @param array $field     Field settings.
 * @param int   $form_id   Form ID.
 * @param array $form_data Form data and settings.
 *
 * @return false|array
 */
function wpforms_get_field_dynamic_choices( $field, $form_id, $form_data = [] ) {

	if ( empty( $field['dynamic_choices'] ) ) {
		return false;
	}

	$choices = [];

	if ( $field['dynamic_choices'] === 'post_type' ) {

		if ( empty( $field['dynamic_post_type'] ) ) {
			return false;
		}

		$posts = wpforms_get_hierarchical_object(
			apply_filters(
				'wpforms_dynamic_choice_post_type_args',
				[
					'post_type'      => $field['dynamic_post_type'],
					'posts_per_page' => -1,
					'orderby'        => 'title',
					'order'          => 'ASC',
				],
				$field,
				$form_id
			),
			true
		);

		foreach ( $posts as $post ) {
			$choices[] = [
				'value' => $post->ID,
				'label' => wpforms_get_post_title( $post ),
				'depth' => isset( $post->depth ) ? absint( $post->depth ) : 1,
			];
		}
	} elseif ( $field['dynamic_choices'] === 'taxonomy' ) {

		if ( empty( $field['dynamic_taxonomy'] ) ) {
			return false;
		}

		$terms = wpforms_get_hierarchical_object(
			apply_filters(
				'wpforms_dynamic_choice_taxonomy_args',
				[
					'taxonomy'   => $field['dynamic_taxonomy'],
					'hide_empty' => false,
				],
				$field,
				$form_data
			),
			true
		);

		foreach ( $terms as $term ) {
			$choices[] = [
				'value' => $term->term_id,
				'label' => wpforms_get_term_name( $term ),
				'depth' => isset( $term->depth ) ? absint( $term->depth ) : 1,
			];
		}
	}

	return $choices;
}

/**
 * Build and return either a taxonomy or post type object that is
 * nested to accommodate any hierarchy.
 *
 * @since 1.3.9
 * @since 1.5.0 Return array only. Empty array of no data.
 *
 * @param array $args Object arguments to pass to data retrieval function.
 * @param bool  $flat Preserve hierarchy or not. False by default - preserve it.
 *
 * @return array
 */
function wpforms_get_hierarchical_object( $args = [], $flat = false ) { // phpcs:ignore Generic.Metrics.CyclomaticComplexity.MaxExceeded

	if ( empty( $args['taxonomy'] ) && empty( $args['post_type'] ) ) {
		return [];
	}

	$children   = [];
	$parents    = [];
	$ref_parent = '';
	$ref_name   = '';
	$number     = 0;

	if ( ! empty( $args['post_type'] ) ) {

		$defaults   = [
			'posts_per_page' => - 1,
			'orderby'        => 'title',
			'order'          => 'ASC',
		];
		$args       = wp_parse_args( $args, $defaults );
		$items      = get_posts( $args );
		$ref_parent = 'post_parent';
		$ref_id     = 'ID';
		$ref_name   = 'post_title';
		$number     = ! empty( $args['posts_per_page'] ) ? $args['posts_per_page'] : 0;

	} elseif ( ! empty( $args['taxonomy'] ) ) {

		$defaults   = [
			'hide_empty' => false,
			'orderby'    => 'name',
			'order'      => 'ASC',
		];
		$args       = wp_parse_args( $args, $defaults );
		$items      = get_terms( $args );
		$ref_parent = 'parent';
		$ref_id     = 'term_id';
		$ref_name   = 'name';
		$number     = ! empty( $args['number'] ) ? $args['number'] : 0;
	}

	if ( empty( $items ) || is_wp_error( $items ) ) {
		return [];
	}

	foreach ( $items as $item ) {
		if ( $item->{$ref_parent} ) {
			$children[ $item->{$ref_id} ]     = $item;
			$children[ $item->{$ref_id} ]->ID = (int) $item->{$ref_id};
		} else {
			$parents[ $item->{$ref_id} ]     = $item;
			$parents[ $item->{$ref_id} ]->ID = (int) $item->{$ref_id};
		}
	}

	$children_count = count( $children );
	$is_limited     = $number > 1;

	// We can't guarantee that all children have a parent if there is a limit in the request.
	// Hence, we have to make sure that there is a parent for every child.
	if ( $is_limited && $children_count ) {
		foreach ( $children as $child ) {
			if ( ! empty( $parents[ $child->{$ref_parent} ] ) || ! empty( $children[ $child->{$ref_parent} ] ) ) {
				continue;
			}

			do {
				$current_parent = ! empty( $args['post_type'] ) ? get_post( $child->{$ref_parent} ) : get_term( $child->{$ref_parent} );

				if ( $current_parent->{$ref_parent} === 0 ) {
					$parents[ $current_parent->{$ref_id} ]     = $current_parent;
					$parents[ $current_parent->{$ref_id} ]->ID = (int) $current_parent->{$ref_id};
				} else {
					$children[ $current_parent->{$ref_id} ]     = $current_parent;
					$children[ $current_parent->{$ref_id} ]->ID = (int) $current_parent->{$ref_id};
				}
			} while ( $current_parent->{$ref_parent} > 0 );
		}
	}

	while ( $children_count >= 1 ) {
		foreach ( $children as $child ) {
			_wpforms_get_hierarchical_object_search( $child, $parents, $children, $ref_parent );

			// $children is modified by reference, so we need to recount to make sure we met the limits.
			$children_count = count( $children );
		}
	}

	// Sort nested child objects alphabetically using natural order, applies only
	// to ordering by entry title or term name.
	if ( in_array( $args['orderby'], [ 'title', 'name' ], true ) ) {
		_wpforms_sort_hierarchical_object( $parents, $args['orderby'], $args['order'] );
	}

	if ( $flat ) {
		$parents_flat = [];

		_wpforms_get_hierarchical_object_flatten( $parents, $parents_flat, $ref_name );

		$parents = $parents_flat;
	}

	return $is_limited ? array_slice( $parents, 0, $number ) : $parents;
}

/**
 * Sort a nested array of objects.
 *
 * @since 1.6.5
 *
 * @param array  $objects An array of objects to sort.
 * @param string $orderby The object field to order by.
 * @param string $order   Order direction.
 */
function _wpforms_sort_hierarchical_object( &$objects, $orderby, $order ) {

	// Map WP_Query/WP_Term_Query orderby to WP_Post/WP_Term property.
	$map = [
		'title' => 'post_title',
		'name'  => 'name',
	];

	foreach ( $objects as $object ) {
		if ( ! isset( $object->children ) ) {
			continue;
		}

		uasort(
			$object->children,
			static function ( $a, $b ) use ( $map, $orderby, $order ) {

				/**
				 * This covers most cases and works for most languages. For some – e.g. European languages
				 * that use extended latin charset (Polish, German etc) it will sort the objects into 2
				 * groups – base and extended, properly sorted within each group. Making it even more
				 * robust requires either additional PHP extensions to be installed on the server
				 * or using heavy (and slow) conversions and computations.
				 */
				return $order === 'ASC' ?
					strnatcasecmp( $a->{$map[ $orderby ]}, $b->{$map[ $orderby ]} ) :
					strnatcasecmp( $b->{$map[ $orderby ]}, $a->{$map[ $orderby ]} );
			}
		);

		_wpforms_sort_hierarchical_object( $object->children, $orderby, $order );
	}
}

/**
 * Search a given array and find the parent of the provided object.
 *
 * @since 1.3.9
 *
 * @param object $child      Current child.
 * @param array  $parents    Parents list.
 * @param array  $children   Children list.
 * @param string $ref_parent Parent reference.
 */
function _wpforms_get_hierarchical_object_search( $child, &$parents, &$children, $ref_parent ) {

	foreach ( $parents as $id => $parent ) {

		if ( $parent->ID === $child->{$ref_parent} ) {

			if ( empty( $parent->children ) ) {
				$parents[ $id ]->children = [
					$child->ID => $child,
				];
			} else {
				$parents[ $id ]->children[ $child->ID ] = $child;
			}

			unset( $children[ $child->ID ] );

		} elseif ( ! empty( $parent->children ) && is_array( $parent->children ) ) {

			_wpforms_get_hierarchical_object_search( $child, $parent->children, $children, $ref_parent );
		}
	}
}

/**
 * Flatten a hierarchical object.
 *
 * @since 1.3.9
 *
 * @param array  $array    Array to process.
 * @param array  $output   Processed output.
 * @param string $ref_name Name reference.
 * @param int    $level    Nesting level.
 */
function _wpforms_get_hierarchical_object_flatten( $array, &$output, $ref_name = 'name', $level = 0 ) {

	foreach ( $array as $key => $item ) {

		$indicator           = apply_filters( 'wpforms_hierarchical_object_indicator', '&mdash;' );
		$item->{$ref_name}   = str_repeat( $indicator, $level ) . ' ' . $item->{$ref_name};
		$item->depth         = $level + 1;
		$output[ $item->ID ] = $item;

		if ( ! empty( $item->children ) ) {

			_wpforms_get_hierarchical_object_flatten( $item->children, $output, $ref_name, $level + 1 );
			unset( $output[ $item->ID ]->children );
		}
	}
}

/**
 * Get sanitized post title or "no title" placeholder.
 *
 * The placeholder is prepended with post ID.
 *
 * @since 1.7.6
 *
 * @param WP_Post|object $post Post object.
 *
 * @return string Post title.
 */
function wpforms_get_post_title( $post ) {

	/* translators: %d - a post ID. */
	return wpforms_is_empty_string( trim( $post->post_title ) ) ? sprintf( __( '#%d (no title)', 'wpforms-lite' ), absint( $post->ID ) ) : $post->post_title;
}

/**
 * Get sanitized term name or "no name" placeholder.
 *
 * The placeholder is prepended with term ID.
 *
 * @since 1.7.6
 *
 * @param WP_Term $term Term object.
 *
 * @return string Term name.
 */
function wpforms_get_term_name( $term ) {

	/* translators: %d - a taxonomy term ID. */
	return wpforms_is_empty_string( trim( $term->name ) ) ? sprintf( __( '#%d (no name)', 'wpforms-lite' ), absint( $term->term_id ) ) : trim( $term->name );
}

/**
 * Return information about pages if the form has multiple pages.
 *
 * @since 1.3.7
 *
 * @param WP_Post|array $form Form data.
 *
 * @return false|array Page Break details or false.
 */
function wpforms_get_pagebreak_details( $form = false ) {

	if ( ! wpforms()->is_pro() ) {
		return false;
	}

	$details = [];
	$pages   = 1;

	if ( is_object( $form ) && ! empty( $form->post_content ) ) {
		$form_data = wpforms_decode( $form->post_content );
	} elseif ( is_array( $form ) ) {
		$form_data = $form;
	}

	if ( empty( $form_data['fields'] ) ) {
		return false;
	}

	foreach ( $form_data['fields'] as $field ) {

		if ( $field['type'] !== 'pagebreak' ) {
			continue;
		}

		if ( empty( $field['position'] ) ) {
			$pages ++;
			$details['total']   = $pages;
			$details['pages'][] = $field;
		} elseif ( $field['position'] === 'top' ) {
			$details['top'] = $field;
		} elseif ( $field['position'] === 'bottom' ) {
			$details['bottom'] = $field;
		}
	}

	if ( ! empty( $details ) ) {
		$details['top']     = empty( $details['top'] ) ? [] : $details['top'];
		$details['bottom']  = empty( $details['bottom'] ) ? [] : $details['bottom'];
		$details['current'] = 1;

		return $details;
	}

	return false;
}
