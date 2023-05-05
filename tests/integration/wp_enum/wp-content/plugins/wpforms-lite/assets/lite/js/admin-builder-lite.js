/* global wpforms_builder_lite, wpforms_builder */

'use strict';

var WPFormsBuilderLite = window.WPFormsBuilderLite || ( function( document, window, $ ) {

	/**
	 * Public functions and properties.
	 *
	 * @since 1.0.0
	 *
	 * @type {object}
	 */
	var app = {

		/**
		 * Start the engine.
		 *
		 * @since 1.0.0
		 */
		init: function() {

			// Document ready
			$( app.ready() );

			app.bindUIActions();
		},

		/**
		 * Document ready.
		 *
		 * @since 1.0.0
		 */
		ready: function() {},

		/**
		 * Element bindings.
		 *
		 * @since 1.0.0
		 */
		bindUIActions: function() {

			// Warn users if they disable email notifications.
			$( document ).on( 'change', '#wpforms-panel-field-settings-notification_enable', function() {

				app.formBuilderNotificationAlert( $( this ).is( ':checked' ) );
			} );
		},

		/**
		 * Warn users if they disable email notifications.
		 *
		 * @since 1.5.0
		 *
		 * @param {bool} value Whether notifications enabled or not. 0 is disabled, 1 is enabled.
		 */
		formBuilderNotificationAlert: function( value ) {

			if ( value !== false ) {
				return;
			}

			$.alert( {
				title: wpforms_builder.heads_up,
				content: wpforms_builder_lite.disable_notifications,
				icon: 'fa fa-exclamation-circle',
				type: 'orange',
				buttons: {
					confirm: {
						text: wpforms_builder.ok,
						btnClass: 'btn-confirm',
						keys: [ 'enter' ],
					},
				},
			} );
		},
	};

	// Provide access to public functions/properties.
	return app;

}( document, window, jQuery ) );

WPFormsBuilderLite.init();
