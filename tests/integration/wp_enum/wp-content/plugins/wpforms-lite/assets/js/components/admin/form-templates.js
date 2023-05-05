/* global List, wpforms_form_templates */

/**
 * Form Templates function.
 *
 * @since 1.7.7
 */

'use strict';

var WPFormsFormTemplates = window.WPFormsFormTemplates || ( function( document, window, $ ) {

	/**
	 * Runtime variables.
	 *
	 * @since 1.7.7
	 *
	 * @type {object}
	 */
	var vars = {};

	/**
	 * Public functions and properties.
	 *
	 * @since 1.7.7
	 *
	 * @type {object}
	 */
	var app = {

		/**
		 * Start the engine.
		 *
		 * @since 1.7.7
		 */
		init: function() {

			$( app.ready );
			$( window ).on( 'load', function() {

				// in case of jQuery 3.+ we need to wait for an `ready` event first.
				if ( typeof $.ready.then === 'function' ) {
					$.ready.then( app.load );
				} else {
					app.load();
				}
			} );
		},

		/**
		 * Document ready.
		 *
		 * @since 1.7.7
		 */
		ready: function() {

			app.setup();
			app.events();
		},

		/**
		 * Window load.
		 *
		 * @since 1.7.7
		 */
		load: function() {

			app.showUpgradeBanner();
		},

		/**
		 * Setup. Prepare some variables.
		 *
		 * @since 1.7.7
		 */
		setup: function() {

			// Template list object.
			vars.templateList = new List( 'wpforms-setup-templates-list', {
				valueNames: [
					'wpforms-template-name',
					'wpforms-template-desc',
					{
						name: 'slug',
						attr: 'data-slug',
					},
					{
						name: 'categories',
						attr: 'data-categories',
					},
					{
						name: 'has-access',
						attr: 'data-has-access',
					},
					{
						name: 'favorite',
						attr: 'data-favorite',
					},
				],
			} );
		},

		/**
		 * Bind events.
		 *
		 * @since 1.7.7
		 */
		events: function() {

			$( '#wpforms-setup-templates-list' )
				.on( 'click', '.wpforms-template-favorite i', app.selectFavorite );
		},

		/**
		 * Select Favorite Templates.
		 *
		 * @since 1.7.7
		 *
		 * @param {object} e Event object.
		 */
		// eslint-disable-next-line max-lines-per-function
		selectFavorite: function( e ) {

			let $heartIcon = $( this ),
				favorite = $heartIcon.hasClass( 'fa-heart-o' ),
				$favorite = $heartIcon.closest( '.wpforms-template-favorite' ),
				$template = $heartIcon.closest( '.wpforms-template' ),
				$templateName = $template.find( '.wpforms-template-name' ),
				templateSlug = $template.find( '.wpforms-template-select' ).data( 'slug' ),
				$favoritesCategory = $( '.wpforms-setup-templates-categories' ).find( '[data-category=\'favorites\']' ),
				$favoritesCount = $favoritesCategory.find( 'span' ),
				favoritesCount = parseInt( $favoritesCount.html(), 10 ),
				data = {
					action: 'wpforms_templates_favorite',
					slug: templateSlug,
					favorite: favorite,
					nonce: wpforms_form_templates.nonce,
				};

			let item = vars.templateList.get( 'slug', templateSlug )[0],
				values = item.values();

			let toggleHeartIcon = function() {

				$favorite.find( '.fa-heart-o' ).toggleClass( 'wpforms-hidden', values.favorite );
				$favorite.find( '.fa-heart' ).toggleClass( 'wpforms-hidden', ! values.favorite );
			};

			let unMarkFavorite = function() {

				values.favorite = false;
				favoritesCount = favoritesCount - 1;

				item.values( values );

				toggleHeartIcon();
				$templateName.data( 'data-favorite', 0 );
				$favoritesCount.html( favoritesCount );

				app.maybeHideFavoritesCategory();
			};

			let markFavorite = function() {

				values.favorite = true;
				favoritesCount = favoritesCount + 1;

				item.values( values );

				toggleHeartIcon();
				$templateName.data( 'data-favorite', 1 );
				$favoritesCount.html( favoritesCount );

				app.maybeHideFavoritesCategory();
			};

			$.post( wpforms_form_templates.ajaxurl, data, function( res ) {

				if ( ! res.success ) {

					if ( favorite ) {
						unMarkFavorite();

						return;
					}

					markFavorite();
				}
			} );

			if ( favorite ) {
				markFavorite();

				return;
			}

			unMarkFavorite();
		},

		/**
		 * Maybe hide favorites category if there are no templates.
		 *
		 * @since 1.7.7
		 */
		maybeHideFavoritesCategory: function() {

			let $categoriesList = $( '.wpforms-setup-templates-categories' ),
				$favoritesCategory = $categoriesList.find( '[data-category=\'favorites\']' ),
				favoritesCount = parseInt( $favoritesCategory.find( 'span' ).html(), 10 );

			$favoritesCategory.toggleClass( 'wpforms-hidden', ! favoritesCount );

			if ( $favoritesCategory.hasClass( 'active' ) ) {

				if ( ! favoritesCount ) {
					$categoriesList.find( '[data-category=\'all\']' ).trigger( 'click' );

					return;
				}

				$favoritesCategory.trigger( 'click' );
			}
		},

		/**
		 * Search template callback.
		 *
		 * @since 1.7.7
		 *
		 * @param {object} e Event object.
		 */
		searchTemplate: function( e ) {

			app.performSearch( $( this ).val() );
			app.showUpgradeBanner();
		},

		/**
		 * Perform search value.
		 *
		 * @since 1.7.7.2
		 *
		 * @param {string} query Value to search.
		 */
		performSearch( query ) {

			let searchResult = vars.templateList.search( query );

			$( '.wpforms-templates-no-results' ).toggle( ! searchResult.length );
		},

		/**
		 * Select category.
		 *
		 * @since 1.7.7
		 *
		 * @param {object} e Event object.
		 */
		selectCategory: function( e ) {

			e.preventDefault();

			let $item       = $( this ),
				$active     = $item.closest( 'ul' ).find( '.active' ),
				category    = $item.data( 'category' ),
				searchQuery = $( '#wpforms-setup-template-search' ).val();

			$active.removeClass( 'active' );
			$item.addClass( 'active' );

			vars.templateList.filter( function( item ) {

				if ( category === 'available' ) {
					return item.values()['has-access'];
				}

				if ( category === 'favorites' ) {
					return item.values().favorite;
				}

				return category === 'all' || item.values().categories.split( ',' ).indexOf( category ) > -1;
			} );

			if ( searchQuery !== '' ) {
				app.performSearch( searchQuery );
			}

			app.showUpgradeBanner();
		},

		/**
		 * Cancel button click routine.
		 *
		 * @since 1.7.7
		 */
		selectTemplateCancel: function( ) {

			let $template = $( '#wpforms-setup-templates-list' ).find( '.wpforms-template.active' ),
				$button = $template.find( '.wpforms-template-select' );

			$template.removeClass( 'active' );
			$button.html( $button.data( 'labelOriginal' ) );
		},

		/**
		 * Show upgrade banner if licence type is less than Pro.
		 *
		 * @since 1.7.7
		 */
		showUpgradeBanner: function() {

			if ( ! $( '#tmpl-wpforms-templates-upgrade-banner' ).length ) {
				return;
			}

			let template = wp.template( 'wpforms-templates-upgrade-banner' );

			if ( ! template ) {
				return;
			}

			const $templates = $( '#wpforms-setup-templates-list .wpforms-template' );

			if ( $templates.length > 5 ) {
				$templates.eq( 5 ).after( template() );

				return;
			}

			$templates.last().after( template() );
		},
	};

	// Provide access to public functions/properties.
	return app;

}( document, window, jQuery ) );

// Initialize.
WPFormsFormTemplates.init();
