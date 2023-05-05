/* globals jetpack_search_filter_admin, jQuery, analytics */

( function( $, args ) {
	var defaultFilterCount = ( 'undefined' !== typeof args && args.defaultFilterCount ) ?
		args.defaultFilterCount :
		5; // Just in case we couldn't find the defaultFiltercount arg

	$( document ).ready( function() {
		setListeners();

		window.JetpackSearch = window.JetpackSearch || {};
		window.JetpackSearch.addFilter = addFilter;

		// Initialize Tracks
		if ( 'undefined' !== typeof analytics && args.tracksUserData ) {
			analytics.initialize( args.tracksUserData.userid, args.tracksUserData.username );
		}
	} );

	function generateFilterTitlePlaceholder( container ) {
		var placeholder = null,
			isModified = null,
			isMonth = null,
			type = container.find( '.filter-select' ).val();

		if ( 'taxonomy' === type ) {
			placeholder = container.find('.taxonomy-select option:selected').text().trim();
		} else if ( 'date_histogram' === type && args && args.i18n ) {
			isModified = ( -1 !== container.find( '.date-field-select' ).val().indexOf( 'modified' ) );
			isMonth = ( 'month' === container.find( '.date-interval-select' ).val() );

			if ( isMonth ) {
				placeholder = isModified ?
					args.i18n.monthUpdated :
					args.i18n.month;
			} else {
				placeholder = isModified ?
					args.i18n.yearUpdated :
					args.i18n.year;
			}
		} else {
			placeholder = container.find('.filter-select option:selected').text().trim();
		}

		$( container ).find('.jetpack-search-filters-widget__title input').prop( 'placeholder', placeholder );
	}

	var addFilter = function( filtersContainer, args ) {
		var template = _.template(
			filtersContainer
				.closest( '.jetpack-search-filters-widget' )
				.find( '.jetpack-search-filters-widget__filter-template' )
				.html()
		);
		generateFilterTitlePlaceholder( filtersContainer.append( template( args ) ) );
	};

	var setListeners = function( widget ) {
		widget = ( 'undefined' === typeof widget ) ?
			$( '.jetpack-search-filters-widget' ):
			widget;

		var getContainer = function( el ) {
			return $( el ).closest('.jetpack-search-filters-widget__filter');
		};

		widget.on( 'change', '.filter-select', function() {
			var select = $( this ),
				selectVal = select.val(),
				eventArgs = {
					is_customizer: args.tracksEventData.is_customizer
				};

			eventArgs.type = selectVal;

			select
				.closest( '.jetpack-search-filters-widget__filter' )
				.attr( 'class', 'jetpack-search-filters-widget__filter' )
				.addClass( 'is-' + selectVal );

			generateFilterTitlePlaceholder( getContainer( this ) );

			trackAndBumpMCStats( 'changed_filter_type', eventArgs );
		} );

		// enable showing sort controls only if showing search box is enabled
		widget.on( 'change', '.jetpack-search-filters-widget__search-box-enabled', function() {
			var checkbox = $( this ),
				checkboxVal = checkbox.is(':checked'),
				filterParent = checkbox.closest( '.jetpack-search-filters-widget' ),
				sortControl = filterParent.find( '.jetpack-search-filters-widget__sort-controls-enabled' );

			filterParent.toggleClass( 'hide-post-types' );

			if ( checkboxVal ) {
				sortControl.removeAttr( 'disabled' );
				trackAndBumpMCStats( 'enabled_search_box', args.tracksEventData );
			} else {
				sortControl.prop( 'checked', false );
				sortControl.prop( 'disabled', true );
				trackAndBumpMCStats( 'disabled_search_box', args.tracksEventData );
			}
		} );

		widget.on( 'change', '.jetpack-search-filters-widget__sort-controls-enabled', function() {
			if ( $( this ).is( ':checked' ) ) {
				trackAndBumpMCStats( 'enabled_sort_controls', args.tracksEventData );
			} else {
				trackAndBumpMCStats( 'disabled_sort_controls', args.tracksEventData );
			}
		} );

		widget.on( 'click', '.jetpack-search-filters-widget__post-types-select input[type="checkbox"]', function( e ) {
			var t = $( this );
			var siblingsChecked = t.closest( '.jetpack-search-filters-widget' )
				.find( '.jetpack-search-filters-widget__post-types-select input[type="checkbox"]:checked' );

			if ( 0 === siblingsChecked.length ) {
				e.preventDefault();
				e.stopPropagation();

				trackAndBumpMCStats( 'attempted_no_post_types', args.tracksEventData );
			}
		} );

		widget.on( 'change', '.jetpack-search-filters-widget__post-types-select input[type="checkbox"]', function() {
			var t = $( this );
			var eventArgs = {
				is_customizer: args.tracksEventData.is_customizer,
				post_type:  t.val()
			};

			if ( wp && wp.customize ) {
				wp.customize.state( 'saved' ).set( false );
			}

			if ( t.is( ':checked' ) ) {
				trackAndBumpMCStats( 'added_post_type', eventArgs );
			} else {
				trackAndBumpMCStats( 'removed_post_type', eventArgs );
			}
		} );

		widget.on( 'change', '.jetpack-search-filters-widget__sort-order', function() {
			var eventArgs = {
				is_customizer: args.tracksEventData.is_customizer
			};

			eventArgs.order = $( this ).val();

			if ( wp && wp.customize ) {
				wp.customize.state( 'saved' ).set( false );
			}

			trackAndBumpMCStats( 'changed_sort_order', eventArgs );
		} );

		widget.on( 'change', '.jetpack-search-filters-widget__taxonomy-select select', function() {
			var eventArgs = {
				is_customizer: args.tracksEventData.is_customizer
			};

			eventArgs.taxonomy = $( this ).val();

			generateFilterTitlePlaceholder( getContainer( this ) );

			if ( wp && wp.customize ) {
				wp.customize.state( 'saved' ).set( false );
			}

			trackAndBumpMCStats( 'changed_taxonomy', eventArgs );
		} );

		widget.on( 'change', 'select.date-field-select', function() {
			var eventArgs = {
				is_customizer: args.tracksEventData.is_customizer
			};

			eventArgs.field = $( this ).val();

			generateFilterTitlePlaceholder( getContainer( this ) );

			if ( wp && wp.customize ) {
				wp.customize.state( 'saved' ).set( false );
			}

			trackAndBumpMCStats( 'changed_date_field', eventArgs );
		} );

		widget.on( 'change', 'select.date-interval-select', function() {
			var eventArgs = {
				is_customizer: args.tracksEventData.is_customizer
			};

			eventArgs.interval = $( this ).val();

			generateFilterTitlePlaceholder( getContainer( this ) );

			if ( wp && wp.customize ) {
				wp.customize.state( 'saved' ).set( false );
			}

			trackAndBumpMCStats( 'changed_date_interval', eventArgs );
		} );

		widget.on( 'change', 'input.filter-count', function() {
			var eventArgs = {
				is_customizer: args.tracksEventData.is_customizer
			};

			eventArgs.count = $( this ).val();

			if ( wp && wp.customize ) {
				wp.customize.state( 'saved' ).set( false );
			}

			trackAndBumpMCStats( 'changed_filter_count', eventArgs );
		} );

		// add filter button
		widget.on( 'click', '.jetpack-search-filters-widget__add-filter', function( e ) {
			e.preventDefault();

			var filtersContainer = $( this )
				.closest( '.jetpack-search-filters-widget' )
				.find( '.jetpack-search-filters-widget__filters' );

			addFilter( filtersContainer, {
				type: 'taxonomy',
				taxonomy: '',
				post_type: '',
				field: '',
				interval: '',
				count: defaultFilterCount,
				name_placeholder: '',
				name: ''
			} );

			if ( wp && wp.customize ) {
				wp.customize.state( 'saved' ).set( false );
			}

			// Trigger change event to let legacy widget admin know the widget state is "dirty"
			filtersContainer
				.find( '.jetpack-search-filters-widget__filter' )
				.find( 'input, textarea, select' )
				.change();

			trackAndBumpMCStats( 'added_filter', args.tracksEventData );
		} );

		widget.on( 'click', '.jetpack-search-filters-widget__controls .delete', function( e ) {
			e.preventDefault();
			var filter = $( this ).closest( '.jetpack-search-filters-widget__filter' ),
				eventArgs = {
					is_customizer: args.tracksEventData.is_customizer
				};

			eventArgs.type = filter.find( '.filter-select' ).val();

			switch ( eventArgs.type ) {
				case 'taxonomy':
					eventArgs.taxonomy = filter.find( '.jetpack-search-filters-widget__taxonomy-select select' ).val();
					break;
				case 'date_histogram':
					eventArgs.dateField = filter.find( '.jetpack-search-filters-widget__date-histogram-select:first select' ).val();
					eventArgs.dateInterval = filter.find( '.jetpack-search-filters-widget__date-histogram-select:nth-child( 2 ) select' ).val();
					break;
			}

			eventArgs.filterCount = filter.find( '.filter-count' ).val();

			trackAndBumpMCStats( 'deleted_filter', eventArgs );

			filter.find( 'input, textarea, select' ).change();
			filter.remove();

			if ( wp && wp.customize ) {
				wp.customize.state( 'saved' ).set( false );
			}
		} );

		// make the filters sortable
		$( '.jetpack-search-filters-widget__filters' ).sortable( {
			placeholder: 'jetpack-search-filters-widget__filter-placeholder',
			axis: 'y',
			revert: true,
			cancel: 'input,textarea,button,select,option,.jetpack-search-filters-widget__controls a',
			change: function() {
				if ( wp && wp.customize ) {
					wp.customize.state( 'saved' ).set( false );
				}
			},
			update: function( e, ui ) {
				$( ui.item ).find( 'input, textarea, select' ).change();
			}
		} )
		.disableSelection();
	};

	// When widgets are updated, remove and re-add listeners
	$( document ).on( 'widget-updated widget-added', function( e, widget ) {
		var idBase = $( widget ).find('.id_base').val(),
			isJetpackSearch = ( idBase && ( 'jetpack-search-filters' === idBase ) );

		if ( ! isJetpackSearch ) {
			 return;
		}

		// Intentionally not tracking widget additions and updates here as these events
		// seem noisy in the customizer. We'll track those via PHP.

		widget.off( 'change', '.filter-select' );
		widget.off( 'click', '.jetpack-search-filters-widget__controls .delete' );
		widget.off( 'change', '.jetpack-search-filters-widget__use-filters' );
		widget.off( 'change', '.jetpack-search-filters-widget__search-box-enabled' );
		widget.off( 'change', '.jetpack-search-filters-widget__sort-controls-enabled' );
		widget.off( 'change', '.jetpack-search-filters-widget__sort-controls-enabled' );
		widget.off( 'change', '.jetpack-search-filters-widget__post-type-selector' );
		widget.off( 'change', '.jetpack-search-filters-widget__sort-order' );
		widget.off( 'change', '.jetpack-search-filters-widget__taxonomy-select' );
		widget.off( 'change', '.jetpack-search-filters-widget__date-histogram-select:first select' );
		widget.off( 'change', '.jetpack-search-filters-widget__date-histogram-select:eq(1) select' );
		widget.off( 'click', '.jetpack-search-filters-widget__post-types-select input[type="checkbox"]' );
		widget.off( 'click', '.jetpack-search-filters-widget__add-filter');

		setListeners( widget );
	} );

	/**
	 * This function will fire both a Tracks and MC stat.
	 *
	 * Tracks: Will be prefixed by 'jetpack_widget_search_' and use underscores.
	 * MC: Will not be prefixed, and will use dashes.
	 *
	 * Logic borrowed from `idc-notice.js`.
	 *
	 * @param eventName string
	 * @param extraProps object
	 */
	function trackAndBumpMCStats( eventName, extraProps ) {
		if ( 'undefined' === typeof extraProps || 'object' !== typeof extraProps ) {
			extraProps = {};
		}

		if ( eventName && eventName.length && 'undefined' !== typeof analytics && analytics.tracks && analytics.mc ) {
			// Format for Tracks
			eventName = eventName.replace( /-/g, '_' );
			eventName = eventName.indexOf( 'jetpack_widget_search_' ) !== 0 ? 'jetpack_widget_search_' + eventName : eventName;
			analytics.tracks.recordEvent( eventName, extraProps );

			// Now format for MC stats
			eventName = eventName.replace( 'jetpack_widget_search_', '' );
			eventName = eventName.replace( /_/g, '-' );
			analytics.mc.bumpStat( 'jetpack-search-widget', eventName );
		}
	}
} )( jQuery, jetpack_search_filter_admin );
