/* global wpforms_builder_help, wpf */

/**
 * WPForms Builder Help screen module.
 *
 * @since 1.6.3
 */

'use strict';

var WPForms = window.WPForms || {};

WPForms.Admin = WPForms.Admin || {};
WPForms.Admin.Builder = WPForms.Admin.Builder || {};

WPForms.Admin.Builder.Help = WPForms.Admin.Builder.Help || ( function( document, window, $ ) {

	/**
	 * Elements holder.
	 *
	 * @since 1.6.3
	 *
	 * @type {object}
	 */
	var el;

	/**
	 * UI functions.
	 *
	 * @since 1.6.3
	 *
	 * @type {object}
	 */
	var ui;

	/**
	 * Event handlers.
	 *
	 * @since 1.6.3
	 *
	 * @type {object}
	 */
	var event;

	/**
	 * Public functions and properties.
	 *
	 * @since 1.6.3
	 *
	 * @type {object}
	 */
	var app = {

		/**
		 * Start the engine. DOM is not ready yet, use only to init something.
		 *
		 * @since 1.6.3
		 */
		init: function() {

			$( app.ready );
		},

		/**
		 * DOM is fully loaded.
		 *
		 * @since 1.6.3
		 */
		ready: function() {

			app.setup();
			app.initCategories();
			app.events();
		},

		/**
		 * Setup. Prepare some variables.
		 *
		 * @since 1.6.3
		 */
		setup: function() {

			// Cache DOM elements.
			el = {
				$builder:     $( '#wpforms-builder' ),
				$builderForm: $( '#wpforms-builder-form' ),
				$helpBtn:     $( '#wpforms-help' ),
				$help:        $( '#wpforms-builder-help' ),
				$closeBtn:    $( '#wpforms-builder-help-close' ),
				$search:      $( '#wpforms-builder-help-search' ),
				$result:      $( '#wpforms-builder-help-result' ),
				$noResult:    $( '#wpforms-builder-help-no-result' ),
				$categories:  $( '#wpforms-builder-help-categories' ),
				$footer:      $( '#wpforms-builder-help-footer' ),
			};
		},

		/**
		 * Bind events.
		 *
		 * @since 1.6.3
		 */
		events: function() {

			// Open/close help modal.
			el.$helpBtn.on( 'click', event.openHelp );
			el.$closeBtn.on( 'click', event.closeHelp );

			// Expand/collapse category.
			el.$categories.on( 'click', '.wpforms-builder-help-category header', event.toggleCategory );

			// View all Category Docs button click.
			el.$categories.on( 'click', '.wpforms-builder-help-category button.viewall', event.viewAllCategoryDocs );

			// Input into search field.
			el.$search.on( 'keyup', 'input', _.debounce( event.inputSearch, 250 ) );

			// Clear search field.
			el.$search.on( 'click', '#wpforms-builder-help-search-clear', event.clearSearch );
		},

		/**
		 * Init (generate) categories list.
		 *
		 * @since 1.6.3
		 */
		initCategories: function() {

			// Display error if docs data is not available.
			if ( wpf.empty( wpforms_builder_help.docs ) ) {
				el.$categories.html( wp.template( 'wpforms-builder-help-categories-error' ) );

				return;
			}

			var tmpl = wp.template( 'wpforms-builder-help-categories' ),
				data = {
					categories: wpforms_builder_help.categories,
					docs: app.getDocsByCategories(),
				};

			el.$categories.html( tmpl( data ) );
		},

		/**
		 * Init categories list.
		 *
		 * @since 1.6.3
		 *
		 * @returns {object} Docs arranged by category.
		 */
		getDocsByCategories: function() {

			var categories = wpforms_builder_help.categories,
				docs = wpforms_builder_help.docs || [],
				docsByCategories = {};

			_.each( categories, function( categoryTitle, categorySlug ) {
				var docsByCategory = [];
				_.each( docs, function( doc ) {
					if ( doc.categories && doc.categories.indexOf( categorySlug ) > -1 ) {
						docsByCategory.push( doc );
					}
				} );
				docsByCategories[ categorySlug ] = docsByCategory;
			} );

			return docsByCategories;
		},

		/**
		 * Get docs recommended by search term.
		 *
		 * @since 1.6.3
		 *
		 * @param {string} term Search term.
		 *
		 * @returns {Array} Recommended docs.
		 */
		getRecommendedDocs: function( term ) {

			if ( wpf.empty( term ) ) {
				return [];
			}

			term = term.toLowerCase();

			var docs = wpforms_builder_help.docs,
				recommendedDocs = [];

			if ( wpf.empty( wpforms_builder_help.context.docs[ term ] ) ) {
				return [];
			}

			_.each( wpforms_builder_help.context.docs[ term ], function( docId ) {
				if ( ! wpf.empty( docs[ docId ] ) ) {
					recommendedDocs.push( docs[ docId ] );
				}
			} );

			return recommendedDocs;
		},

		/**
		 * Get docs filtered by search term.
		 *
		 * @since 1.6.3
		 *
		 * @param {string} term Search term.
		 *
		 * @returns {Array} Filtered docs.
		 */
		getFilteredDocs: function( term ) {

			if ( wpf.empty( term ) ) {
				return [];
			}

			var docs = wpforms_builder_help.docs,
				filteredDocs = [];

			term = term.toLowerCase();

			_.each( docs, function( doc ) {
				if ( doc.title && doc.title.toLowerCase().indexOf( term ) > -1 ) {
					filteredDocs.push( doc );
				}
			} );

			return filteredDocs;
		},

		/**
		 * Get the current context (state) of the form builder.
		 *
		 * @since 1.6.3
		 *
		 * @returns {string} Builder context string. For example 'fields/add_field' or 'settings/notifications'.
		 */
		getBuilderContext: function() {

			// New (not saved) form.
			if ( wpf.empty( el.$builderForm.data( 'id' ) ) ) {
				return 'new_form';
			}

			// Determine builder panel and section.
			var panel = el.$builder.find( '#wpforms-panels-toggle button.active' ).data( 'panel' ),
				$panel = el.$builder.find( '#wpforms-panel-' + panel ),
				section = '',
				subsection = '',
				context;

			switch ( panel ) {
				case 'fields':
					section = $panel.find( '.wpforms-panel-sidebar .wpforms-tab a.active' ).parent().attr( 'id' );
					break;
				case 'setup':
					section = '';
					break;
				default:
					section = $panel.find( '.wpforms-panel-sidebar a.active' ).data( 'section' );
			}

			section = ! wpf.empty( section ) ? section.replace( /-/g, '_' ) : '';

			// Detect field type.
			if ( section === 'field_options' ) {
				subsection = $panel.find( '#wpforms-field-options .wpforms-field-option:visible .wpforms-field-option-hidden-type' ).val();
			}

			// Combine to context array.
			context = [ panel, section, subsection ].filter( function( el ) {
				return ! wpf.empty( el ) && el !== 'default';
			} );

			// Return imploded string.
			return context.join( '/' );
		},

		/**
		 * Get the search term for the current builder context.
		 *
		 * @since 1.6.3
		 *
		 * @returns {string} Builder context term string.
		 */
		getBuilderContextTerm: function() {

			return wpforms_builder_help.context.terms[ app.getBuilderContext() ] || '';
		},
	};

	/**
	 * UI functions.
	 */
	ui = {

		/**
		 * Configuration.
		 *
		 * @since 1.6.3
		 *
		 * @type {object}
		 */
		config: {
			speed: 300, // Fading/sliding duration in milliseconds.
		},

		/**
		 * Display the element by fading them to opaque using CSS.
		 *
		 * @since 1.6.3
		 *
		 * @param {jQuery} $el Element object.
		 */
		fadeIn: function( $el ) {

			if ( ! $el.length ) {
				return;
			}

			$el.css( {
				display: '',
				transition: `opacity ${ui.config.speed}ms ease-in 0s`,
			} );

			setTimeout( function() {
				$el.css( 'opacity', '1' );
			}, 0 );
		},

		/**
		 * Hide the element by fading them to transparent using CSS.
		 *
		 * @since 1.6.3
		 *
		 * @param {jQuery} $el Element object.
		 */
		fadeOut: function( $el ) {

			if ( ! $el.length ) {
				return;
			}

			$el.css( {
				opacity: '0',
				transition: `opacity ${ui.config.speed}ms ease-in 0s`,
			} );

			setTimeout( function() {
				$el.css( 'display', 'none' );
			}, ui.config.speed );
		},

		/**
		 * Collapse all categories.
		 *
		 * @since 1.6.3
		 */
		collapseAllCategories: function() {

			el.$categories.find( '.wpforms-builder-help-category' ).removeClass( 'opened' );
			el.$categories.find( '.wpforms-builder-help-docs' ).slideUp();
		},
	};

	/**
	 * Event handlers.
	 */
	event = {

		/**
		 * Open help modal.
		 *
		 * @since 1.6.3
		 *
		 * @param {object} e Event object.
		 */
		openHelp: function( e ) {

			e.preventDefault();

			var $firstCategory = el.$categories.find( '.wpforms-builder-help-category' ).first(),
				builderContextTerm = app.getBuilderContextTerm();

			if ( builderContextTerm === '' && ! $firstCategory.hasClass( 'opened' ) ) {
				$firstCategory.find( 'header' ).first().trigger( 'click' );
			} else {
				ui.collapseAllCategories();
			}

			el.$search.find( 'input' ).val( builderContextTerm ).trigger( 'keyup' );

			ui.fadeIn( el.$help );

			setTimeout( function() {

				ui.fadeIn( el.$result );
				ui.fadeIn( el.$categories );
				ui.fadeIn( el.$footer );

			}, ui.config.speed );
		},

		/**
		 * Close help modal.
		 *
		 * @since 1.6.3
		 *
		 * @param {object} e Event object.
		 */
		closeHelp: function( e ) {

			e.preventDefault();

			ui.fadeOut( el.$result );
			ui.fadeOut( el.$categories );
			ui.fadeOut( el.$footer );

			ui.fadeOut( el.$help );

		},

		/**
		 * Toggle category.
		 *
		 * @since 1.6.3
		 *
		 * @param {object} e Event object.
		 */
		toggleCategory: function( e ) {

			var $category = $( this ).parent(),
				$categoryDocs = $category.find( '.wpforms-builder-help-docs' );

			if ( ! $categoryDocs.is( ':visible' ) ) {
				$category.addClass( 'opened' );
			} else {
				$category.removeClass( 'opened' );
			}

			$categoryDocs.stop().slideToggle( ui.config.speed );
		},

		/**
		 * View All Category Docs button click.
		 *
		 * @since 1.6.3
		 *
		 * @param {object} e Event object.
		 */
		viewAllCategoryDocs: function( e ) {

			var $btn = $( this );

			$btn.prev( 'div' ).stop().slideToggle( ui.config.speed, function() {
				$btn.closest( '.wpforms-builder-help-category' ).addClass( 'viewall' );
			} );
			ui.fadeOut( $btn );
			$btn.slideUp();
		},

		/**
		 * Input into search field.
		 *
		 * @since 1.6.3
		 *
		 * @param {object} e Event object.
		 */
		inputSearch: function( e ) {

			var $input = $( this ),
				term = $input.val();

			var tmpl = wp.template( 'wpforms-builder-help-docs' ),
				recommendedDocs = app.getRecommendedDocs( term ),
				filteredDocs = event.removeDuplicates( recommendedDocs, app.getFilteredDocs( term ) ),
				resultHTML = '';

			el.$search.toggleClass( 'wpforms-empty', ! term );

			if ( ! wpf.empty( recommendedDocs ) ) {
				resultHTML += tmpl( {
					docs: recommendedDocs,
				} );
			}

			if ( ! wpf.empty( filteredDocs ) ) {
				resultHTML += tmpl( {
					docs: filteredDocs,
				} );
			}

			el.$noResult.toggle( resultHTML === '' && term !== '' );

			el.$result.html( resultHTML );

			el.$help[0].scrollTop = 0;
		},

		/**
		 * Remove duplicated items in the filtered docs.
		 *
		 * @since 1.6.3
		 *
		 * @param {Array} recommendedDocs Recommended docs.
		 * @param {Array} filteredDocs    Filtered docs.
		 *
		 * @returns {Array} Filtered docs without duplicated items in the recommended docs.
		 */
		removeDuplicates: function( recommendedDocs, filteredDocs ) {

			if ( wpf.empty( recommendedDocs ) || wpf.empty( filteredDocs ) ) {
				return filteredDocs;
			}

			var docs = [];

			for ( var i = 0; i < recommendedDocs.length, i++; ) {
				for ( var k = 0; k < filteredDocs.length, k++; ) {
					if ( filteredDocs[ k ].url !== recommendedDocs[ i ].url ) {
						docs.push( filteredDocs[ k ] );
					}
				}
			}

			return docs;
		},

		/**
		 * Clear search field.
		 *
		 * @since 1.6.3
		 *
		 * @param {object} e Event object.
		 */
		clearSearch: function( e ) {

			el.$search.find( 'input' ).val( '' ).trigger( 'keyup' );
		},
	};

	// Provide access to public functions/properties.
	return app;

}( document, window, jQuery ) );

// Initialize.
WPForms.Admin.Builder.Help.init();
