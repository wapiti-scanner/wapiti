/* global wpforms_builder, Choices */

/**
 * WPForms ChoicesJS utility methods for the Admin Builder.
 *
 * @since 1.7.9
 */

'use strict';

var WPForms = window.WPForms || {};

WPForms.Admin = WPForms.Admin || {};
WPForms.Admin.Builder = WPForms.Admin.Builder || {};

WPForms.Admin.Builder.WPFormsChoicesJS = WPForms.Admin.Builder.WPFormsChoicesJS || ( function( document, window, $ ) {

	/**
	 * Public functions and properties.
	 *
	 * @since 1.7.9
	 *
	 * @type {object}
	 */
	const app = {

		/**
		 * Setup the Select Page ChoicesJS instance.
		 *
		 * @since 1.7.9
		 *
		 * @param {object}  element       DOM Element where to init ChoicesJS.
		 * @param {object}  choicesJSArgs ChoicesJS init options.
		 * @param {object}  ajaxArgs      Object containing `action` and `nonce` to perform AJAX search.
		 *
		 * @returns {Choices} ChoicesJS instance.
		 */
		setup: function( element, choicesJSArgs, ajaxArgs ) {

			choicesJSArgs.searchEnabled = true;
			choicesJSArgs.searchChoices = ajaxArgs.nonce === null; // Enable searchChoices when not using AJAX.
			choicesJSArgs.renderChoiceLimit = -1;
			choicesJSArgs.noChoicesText = wpforms_builder.no_pages_found;
			choicesJSArgs.noResultsText = wpforms_builder.no_pages_found;

			const choicesJS = new Choices( element, choicesJSArgs );

			if ( ajaxArgs.nonce === null ) {
				return choicesJS;
			}

			/*
			 * ChoicesJS doesn't handle empty string search with it's `search` event handler,
			 * so we work around it by detecting empty string search with `keyup` event.
			 */
			choicesJS.input.element.addEventListener( 'keyup', function( ev ) {

				// Only capture backspace and delete keypress that results to empty string.
				if (
					( ev.which !== 8 && ev.which !== 46 ) ||
					ev.target.value.length > 0
				) {
					return;
				}

				app.performSearch( choicesJS, '', ajaxArgs );
			} );

			choicesJS.passedElement.element.addEventListener( 'search', _.debounce( function( ev ) {

				// Make sure that the search term is actually changed.
				if ( choicesJS.input.element.value.length === 0 ) {
					return;
				}

				app.performSearch( choicesJS, ev.detail.value, ajaxArgs );
			}, 800 ) );

			return choicesJS;
		},

		/**
		 * Perform search in ChoicesJS instance.
		 *
		 * @since 1.7.9
		 *
		 * @param {Choices} choicesJS  ChoicesJS instance.
		 * @param {string}  searchTerm Search term.
		 * @param {object}  ajaxArgs   Object containing `action` and `nonce` to perform AJAX search.
		 */
		performSearch: function( choicesJS, searchTerm, ajaxArgs ) {

			if ( ! ajaxArgs.action || ! ajaxArgs.nonce ) {
				return;
			}

			app.displayLoading( choicesJS );

			const requestSearchPages = app.ajaxSearchPages( ajaxArgs.action, searchTerm, ajaxArgs.nonce );

			requestSearchPages.done( function( response ) {
				choicesJS.setChoices( response.data, 'value', 'label', true );
			} );
		},

		/**
		 * Display "Loading" in ChoicesJS instance.
		 *
		 * @since 1.7.9
		 *
		 * @param {Choices} choicesJS ChoicesJS instance.
		 */
		displayLoading: function( choicesJS ) {

			choicesJS.setChoices(
				[
					{ value: '', label: `${wpforms_builder.loading}...`, disabled: true },
				],
				'value',
				'label',
				true
			);
		},

		/**
		 * Perform AJAX search request.
		 *
		 * @since 1.7.9
		 *
		 * @param {string} action     Action to be used when doing ajax request for search.
		 * @param {string} searchTerm Search term.
		 * @param {string} nonce      Nonce to be used when doing ajax request.
		 *
		 * @returns {Promise} jQuery ajax call promise.
		 */
		ajaxSearchPages: function( action, searchTerm, nonce ) {

			return $.get(
				wpforms_builder.ajax_url,
				{
					action: action,
					search: searchTerm,
					_wpnonce: nonce,
				}
			).fail(
				function( err ) {
					console.error( err );
				}
			);
		},
	};

	// Provide access to public functions/properties.
	return app;

}( document, window, jQuery ) );
