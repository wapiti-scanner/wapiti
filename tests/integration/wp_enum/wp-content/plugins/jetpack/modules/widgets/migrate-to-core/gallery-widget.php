<?php
/**
 * Migration from Jetpack's Gallery Widget to WordPress' Core Gallery Widget.
 *
 * @since 5.5
 *
 * @package automattic/jetpack
 */

/**
 * Migrates all active instances of Jetpack's Gallery widget to Core's Media Gallery widget.
 */
function jetpack_migrate_gallery_widget() {
	// Only trigger the migration from wp-admin and outside unit tests.
	if ( ! is_admin() || defined( 'PHPUNIT_JETPACK_TESTSUITE' ) ) {
		return;
	}

	// Only migrate if the new widget is available and we haven't yet migrated.
	if ( ! class_exists( 'WP_Widget_Media_Gallery' ) || Jetpack_Options::get_option( 'gallery_widget_migration' ) ) {
		return;
	}

	$old_widgets      = get_option( 'widget_gallery', array() );
	$media_gallery    = get_option( 'widget_media_gallery', array() );
	$sidebars_widgets = wp_get_sidebars_widgets();

	// Array to store legacy widget ids in to unregister on success.
	$widgets_to_unregister = array();

	$old_widgets = array_filter( $old_widgets, 'jetpack_migrate_gallery_widget_is_importable' );
	foreach ( $old_widgets as $id => $widget ) {
		$new_id = $id;

		/*
		 * Try to get an unique id for the new type of widget.
		 * It may be the case that the user has already created a core Gallery Widget
		 * before the migration begins. (Maybe Jetpack was deactivated during core's upgrade).
		 */
		for ( // phpcs:ignore Generic.CodeAnalysis.ForLoopWithTestFunctionCall.NotAllowed
			$i = 0;
			$i < 10 && array_key_exists( $new_id, array( $media_gallery ) );
			$i++, $new_id++
		);

		$widget_copy = jetpack_migrate_gallery_widget_upgrade_widget( $widget );

		if ( null === $widget_copy ) {
			jetpack_migrate_gallery_widget_bump_stats( 'gallery-widget-skipped' );
			continue;
		}

		$media_gallery[ $new_id ] = $widget_copy;

		$sidebars_widgets = jetpack_migrate_gallery_widget_update_sidebars( $sidebars_widgets, $id, $new_id );

		$widgets_to_unregister[ $id ] = $new_id;
	}

	if ( update_option( 'widget_media_gallery', $media_gallery ) ) {

		// Now un-register old widgets and register new.
		foreach ( $widgets_to_unregister as $id => $new_id ) {
			wp_unregister_sidebar_widget( "gallery-{$id}" );

			// register new widget.
			$media_gallery_widget = new WP_Widget_Media_Gallery();
			$media_gallery_widget->_set( $new_id );
			$media_gallery_widget->_register_one( $new_id );
		}

		wp_set_sidebars_widgets( $sidebars_widgets );

		// Log if we migrated all, or some for this site.
		foreach ( $widgets_to_unregister as $w ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
			jetpack_migrate_gallery_widget_bump_stats( 'gallery-widget-migrated' );
		}

		/*
		 * We need to refresh on widgets page for changes to take effect.
		 * The jetpack_refresh_on_widget_page function is already defined
		 * in migrate-to-core/image-widget.php
		 */
		add_action( 'current_screen', 'jetpack_refresh_on_widget_page' );
	}
	Jetpack_Options::update_option( 'gallery_widget_migration', true );
}

/**
 * Check if the widget can be imported.
 *
 * @param array $widget One of the Jetpack Gallery widgets to be transformed into a new Core Media Gallery Widget.
 */
function jetpack_migrate_gallery_widget_is_importable( $widget ) {
	// Can be caused by instantiating but not populating a widget in the Customizer.
	if ( empty( $widget ) ) {
		return false;
	}

	/*
	 *  The array as stored in the option constains two keys and one
	 * is a string `_multiwidget` which does not represent a widget, so we skip it
	 */
	if ( ! is_array( $widget ) ) {
		return false;
	}
	return true;
}

/**
 * Returns a transformed version of the Gallery Widget.
 * Will return null if the widget is either empty, is not an array or has more keys than expected
 *
 * @param array $widget One of the Jetpack Gallery widgets to be transformed into a new Core Media Gallery Widget.
 *
 * @return array|null
 */
function jetpack_migrate_gallery_widget_upgrade_widget( $widget ) {
	$allowed_keys = array(
		'ids'        => '',
		'link'       => '',
		'title'      => '',
		'type'       => '',
		'random'     => '',
		'conditions' => '',
	);

	$default_data = array(
		'columns'        => 3,
		'ids'            => array(),
		'link_type'      => '',
		'orderby_random' => false,
		'size'           => 'thumbnail',
		'title'          => '',
		'type'           => '',
	);

	if ( ! jetpack_migrate_gallery_widget_is_importable( $widget ) ) {
		return null;
	}
	// Ensure widget has no keys other than those expected.
	// Not all widgets have conditions, so lets add it in.
	$widget_copy      = array_merge( array( 'conditions' => null ), $widget );
	$non_allowed_keys = array_diff_key( $widget_copy, $allowed_keys );
	if ( count( $non_allowed_keys ) > 0 ) {
		jetpack_migrate_gallery_widget_bump_stats( 'extra-key' );

		// Log the names of the keys not in our allowed list.
		foreach ( $non_allowed_keys as $key => $value ) {
			jetpack_migrate_gallery_widget_bump_stats( "extra-key-$key", 'migration-extra-key' );
		}
	}

	$widget_copy = array_merge(
		$default_data,
		$widget,
		array(
			// ids in Jetpack's Gallery are a string of comma-separated values.
			// Core's Media Gallery Widget stores ids in an array.
			'ids'            => explode( ',', $widget['ids'] ),
			'link_type'      => $widget['link'],
			'orderby_random' => isset( $widget['random'] ) && 'on' === $widget['random'],
		)
	);

	// Unsetting old widget fields.
	$widget_copy = array_diff_key(
		$widget_copy,
		array(
			'link'   => false,
			'random' => false,
		)
	);

	return $widget_copy;
}

/**
 * Replaces the references to Jetpack Gallery Widget in the sidebars for references to the new version of the widget
 *
 * @param array  $sidebars_widgets The sidebar widgets array to update.
 * @param string $id               Old id of the widget (basically its index in the array ).
 * @param string $new_id           New id that will be using on the sidebar as a new widget.
 *
 * @return mixed                   Updated sidebar widgets array
 */
function jetpack_migrate_gallery_widget_update_sidebars( $sidebars_widgets, $id, $new_id ) {
	foreach ( $sidebars_widgets as $sidebar => $widgets ) {
		$key = is_array( $widgets ) ? array_search( "gallery-{$id}", $widgets, true ) : false;

		if ( false !== $key ) {
			$sidebars_widgets[ $sidebar ][ $key ] = "media_gallery-{$new_id}";

			/*
			 * Check if the inactive widgets sidebar exists
			 * Related: https://core.trac.wordpress.org/ticket/14893
			 */
			if ( ! isset( $sidebars_widgets['wp_inactive_widgets'] ) || ! is_array( $sidebars_widgets['wp_inactive_widgets'] ) ) {
				$sidebars_widgets['wp_inactive_widgets'] = array();
			}
			$sidebars_widgets['wp_inactive_widgets'][ $key ] = "gallery-{$id}";
		}
	}
	return $sidebars_widgets;
}

/**
 * Will bump stat in jetpack_gallery_widget_migration group.
 *
 * @param string $bin   The bin to log into.
 * @param string $group The group name. Defaults to "widget-migration".
 */
function jetpack_migrate_gallery_widget_bump_stats( $bin, $group = 'widget-migration' ) {
	// If this is being run on .com bumps_stats_extra exists, but using the filter looks more elegant.
	if ( function_exists( 'bump_stats_extras' ) ) {
		$group = "jetpack-$group";
		do_action( 'jetpack_bump_stats_extra', $group, $bin );
	} else {
		// $group is prepended with 'jetpack-'
		$jetpack = Jetpack::init();
		$jetpack->stat( $group, $bin );
	}
}
add_action( 'widgets_init', 'jetpack_migrate_gallery_widget' );
