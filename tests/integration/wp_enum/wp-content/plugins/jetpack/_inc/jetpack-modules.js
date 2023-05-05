( function ( window, $, items, models, views, i18n, modalinfo, nonces ) {
	'use strict';

	var modules,
		list_table,
		handle_module_tag_click,
		$the_table,
		$the_filters,
		$the_search,
		$jp_frame,
		$bulk_button;

	$the_table = $( '.wp-list-table.jetpack-modules' );
	$the_filters = $( '.navbar-form' );
	$the_search = $( '#srch-term-search-input' );
	$jp_frame = $( '.jp-frame' );
	$bulk_button = $( '#doaction' );

	modules = new models.Modules( {
		items: items,
	} );

	list_table = new views.List_Table( {
		el: '#the-list',
		model: modules,
	} );

	// Kick off an initial redraw.
	modules.trigger( 'change' );

	// Handle the filtering of modules.
	handle_module_tag_click = function ( event ) {
		// Switch the item in the subsubsub list that's flagged as current.
		$( '.subsubsub' )
			.find( 'a[data-title="' + $( this ).data( 'title' ) + '"]' )
			.addClass( 'current' )
			.closest( 'li' )
			.siblings()
			.find( 'a.current' )
			.removeClass( 'current' );

		event.preventDefault();
		modules.trigger( 'change' );
	};

	$( '.subsubsub a' ).on( 'click', { modules: modules }, handle_module_tag_click );

	$the_filters.on( 'click', '.button-group .button', { modules: modules }, function ( event ) {
		event.preventDefault();
		$( this ).addClass( 'active' ).siblings( '.active' ).removeClass( 'active' );
		modules.trigger( 'change' );
	} );

	$the_search.on( 'keyup search', function ( e ) {
		// Don't trigger change on tab, since it's only used for accessibility
		// anyway, and will remove all checked boxes
		if ( e.code !== 'Tab' ) {
			modules.trigger( 'change' );
		}
	} );

	$the_search.prop( 'placeholder', i18n.search_placeholder );

	$bulk_button.on( 'click', function ( event ) {
		var selectedModules = $( '.jetpack-modules-list-table-form' ).serialize(),
			selectedAction = $( this ).siblings( 'select' ).val(),
			url;

		if ( selectedModules.length && '-1' !== selectedAction ) {
			url = 'admin.php?page=jetpack&action=' + encodeURIComponent( selectedAction );
			url += '&' + selectedModules;
			url += '&_wpnonce=' + encodeURIComponent( nonces.bulk );

			window.location.href = url;
		} else {
			// Possibly add in an alert here explaining why nothing's happening?
		}

		event.preventDefault();
	} );
} )(
	window,
	jQuery,
	window.jetpackModulesData.modules,
	window.jetpackModules.models,
	window.jetpackModules.views,
	window.jetpackModulesData.i18n,
	window.jetpackModulesData.modalinfo,
	window.jetpackModulesData.nonces
);
