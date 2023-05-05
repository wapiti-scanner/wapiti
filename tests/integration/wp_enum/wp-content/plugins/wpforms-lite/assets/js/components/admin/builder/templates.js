/* global WPForms, jQuery, Map, wpforms_builder, wpforms_builder_providers, _ */

var WPForms = window.WPForms || {};
WPForms.Admin = WPForms.Admin || {};
WPForms.Admin.Builder = WPForms.Admin.Builder || {};

WPForms.Admin.Builder.Templates = WPForms.Admin.Builder.Templates || ( function( document, window, $ ) {
	'use strict';

	/**
	 * Private functions and properties.
	 *
	 * @since 1.4.8
	 *
	 * @type {Object}
	 */
	var __private = {

		/**
		 * All templating functions for providers are stored here in a Map.
		 * Key is a template name, value - Underscore.js templating function.
		 *
		 * @since 1.4.8
		 *
		 * @type {Map}
		 */
		previews: new Map(),
	};

	/**
	 * Public functions and properties.
	 *
	 * @since 1.4.8
	 *
	 * @type {Object}
	 */
	var app = {

		/**
		 * Start the engine. DOM is not ready yet, use only to init something.
		 *
		 * @since 1.4.8
		 */
		init: function() {

			// Do that when DOM is ready.
			$( app.ready );
		},

		/**
		 * DOM is fully loaded.
		 *
		 * @since 1.4.8
		 */
		ready: function() {

			$( '#wpforms-panel-providers' ).trigger( 'WPForms.Admin.Builder.Templates.ready' );
		},

		/**
		 * Register and compile all templates.
		 * All data is saved in a Map.
		 *
		 * @since 1.4.8
		 *
		 * @param {string[]} templates Array of template names.
		 */
		add: function( templates ) {

			templates.forEach( function( template ) {
				if ( typeof template === 'string' ) {
					__private.previews.set( template, wp.template( template ) );
				}
			} );
		},

		/**
		 * Get a templating function (to compile later with data).
		 *
		 * @since 1.4.8
		 *
		 * @param {string} template ID of a template to retrieve from a cache.
		 *
		 * @returns {*} A callable that after compiling will always return a string.
		 */
		get: function( template ) {

			var preview = __private.previews.get( template );

			if ( typeof preview !== 'undefined' ) {
				return preview;
			}

			return function() {
				return '';
			};
		},

	};

	// Provide access to public functions/properties.
	return app;

} )( document, window, jQuery );

// Initialize.
WPForms.Admin.Builder.Templates.init();
