<?php
/**
 * Migration from Jetpack's Image Widget to WordPress' Core Image Widget.
 *
 * @since 4.9
 *
 * @package automattic/jetpack
 */

/**
 * Migrates all active instances of Jetpack's image widget to Core's media image widget.
 */
function jetpack_migrate_image_widget() {
	// Only trigger the migration from wp-admin.
	if ( ! is_admin() ) {
		return;
	}

	// Only migrate if the new widget is available and we haven't yet migrated.
	if ( ! class_exists( 'WP_Widget_Media_Image' ) || Jetpack_Options::get_option( 'image_widget_migration' ) ) {
		return;
	}

	$default_data = array(
		'attachment_id'     => 0,
		'url'               => '',
		'title'             => '',
		'size'              => 'custom',
		'width'             => 0,
		'height'            => 0,
		'align'             => 'none',
		'caption'           => '',
		'alt'               => '',
		'link_type'         => '',
		'link_url'          => '',
		'image_classes'     => '',
		'link_classes'      => '',
		'link_rel'          => '',
		'image_title'       => '',
		'link_target_blank' => false,
		'conditions'        => null,
	);

	$old_widgets      = get_option( 'widget_image', array() );
	$media_image      = get_option( 'widget_media_image', array() );
	$sidebars_widgets = wp_get_sidebars_widgets();

	// Persist old and current widgets in backup table.
	jetpack_store_migration_data( 'widget_image', maybe_serialize( $old_widgets ) );
	if ( jetpack_get_migration_data( 'widget_image' ) !== $old_widgets ) {
		return false;
	}

	jetpack_store_migration_data( 'sidebars_widgets', maybe_serialize( $sidebars_widgets ) );
	if ( jetpack_get_migration_data( 'sidebars_widgets' ) !== $sidebars_widgets ) {
		return false;
	}

	// Array to store legacy widget ids in to unregister on success.
	$widgets_to_unregister = array();

	foreach ( $old_widgets as $id => $widget ) {
		if ( is_string( $id ) ) {
			continue;
		}

		// Can be caused by instanciating but not populating a widget in the Customizer.
		if ( empty( $widget ) ) {
			continue;
		}

		// Ensure widget has no keys other than those expected.
		// Not all widgets have conditions, so lets add it in.
		$widget_copy      = array_merge( array( 'conditions' => null ), $widget );
		$non_allowed_keys = array_diff_key(
			$widget_copy,
			array(
				'title'             => '',
				'img_url'           => '',
				'alt_text'          => '',
				'img_title'         => '',
				'caption'           => '',
				'align'             => '',
				'img_width'         => '',
				'img_height'        => '',
				'link'              => '',
				'link_target_blank' => '',
				'conditions'        => '',
			)
		);

		if ( count( $non_allowed_keys ) > 0 ) {
			// skipping the widget in question.
			continue;
		}

		$media_image[ $id ] = array_merge(
			$default_data,
			$widget,
			array(
				'alt'           => $widget['alt_text'],
				'height'        => $widget['img_height'],
				'image_classes' => ! empty( $widget['align'] ) ? 'align' . $widget['align'] : '',
				'image_title'   => $widget['img_title'],
				'link_url'      => $widget['link'],
				'url'           => $widget['img_url'],
				'width'         => $widget['img_width'],
			)
		);

		// Unsetting old widget fields.
		$media_image[ $id ] = array_diff_key(
			$media_image[ $id ],
			array(
				'align'      => false,
				'alt_text'   => false,
				'img_height' => false,
				'img_title'  => false,
				'img_url'    => false,
				'img_width'  => false,
				'link'       => false,
			)
		);

		// Check if the image is in the media library.
		$image_basename = basename( $widget['img_url'] );

		if ( empty( $image_basename ) ) {
			continue;
		}

		$attachment_ids = get_posts(
			array(
				'fields'           => 'ids',
				'meta_query'       => array(
					array(
						'value'   => basename( $image_basename ),
						'compare' => 'LIKE',
						'key'     => '_wp_attachment_metadata',
					),
				),
				'post_status'      => 'inherit',
				'post_type'        => 'attachment',
				'suppress_filters' => false,
			)
		);

		foreach ( $attachment_ids as $attachment_id ) {
			$image_meta = wp_get_attachment_metadata( $attachment_id );

			// Is it a full size image?
			$image_path_pieces = explode( '/', $image_meta['file'] );
			if ( array_pop( $image_path_pieces ) === $image_basename ) {
				$media_image[ $id ]['attachment_id'] = $attachment_id;

				// Set correct size if dimensions fit.
				if (
					$media_image[ $id ]['width'] == $image_meta['width'] || // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
					$media_image[ $id ]['height'] == $image_meta['height'] // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
				) {
					$media_image[ $id ]['size'] = 'full';
				}
				break;
			}

			// Is it a down-sized image?
			foreach ( $image_meta['sizes'] as $size => $image ) {
				if ( false !== array_search( $image_basename, $image, true ) ) {
					$media_image[ $id ]['attachment_id'] = $attachment_id;

					// Set correct size if dimensions fit.
					if (
						$media_image[ $id ]['width'] == $image['width'] || // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
						$media_image[ $id ]['height'] == $image['height'] // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
					) {
						$media_image[ $id ]['size'] = $size;
					}
					break 2;
				}
			}
		}

		if ( ! empty( $widget['link'] ) ) {
			$media_image[ $id ]['link_type'] = $widget['link'] === $widget['img_url'] ? 'file' : 'custom';
		}

		foreach ( $sidebars_widgets as $sidebar => $widgets ) {
			$key = is_array( $widgets ) ? array_search( "image-{$id}", $widgets, true ) : false;

			if ( false !== $key ) {
				$sidebars_widgets[ $sidebar ][ $key ] = "media_image-{$id}";
			}
		}

		$widgets_to_unregister[] = $id;
	}

	if ( update_option( 'widget_media_image', $media_image ) ) {
		delete_option( 'widget_image' );

		// Now un-register old widgets and register new.
		foreach ( $widgets_to_unregister as $id ) {
			wp_unregister_sidebar_widget( "image-{$id}" );

			// register new widget.
			$media_image_widget = new WP_Widget_Media_Image();
			$media_image_widget->_set( $id );
			$media_image_widget->_register_one( $id );
		}

		wp_set_sidebars_widgets( $sidebars_widgets );

		// We need to refresh on widgets page for changes to take effect.
		add_action( 'current_screen', 'jetpack_refresh_on_widget_page' );
	} else {
		$widget_media_image = get_option( 'widget_media_image' );
		if ( is_array( $widget_media_image ) ) {
			delete_option( 'widget_image' );
		}
	}

	Jetpack_Options::update_option( 'image_widget_migration', true );
}
add_action( 'widgets_init', 'jetpack_migrate_image_widget' );

/**
 * Refresh the widgets page to save changes
 *
 * @param WP_Screen $current Current WP_Screen object.
 */
function jetpack_refresh_on_widget_page( $current ) {
	if ( 'widgets' === $current->base ) {
		wp_safe_redirect( admin_url( 'widgets.php' ) );
		exit;
	}
}
