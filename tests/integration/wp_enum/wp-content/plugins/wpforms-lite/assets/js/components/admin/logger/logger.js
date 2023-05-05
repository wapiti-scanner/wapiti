/* global wpforms_admin */

/**
 * Logger scripts
 *
 * @since 1.6.3
 */

'use strict';

var WPFormsLogger = window.WPFormsLogger || ( function( document, window, $ ) {

	var app = {

		/**
		 * Start the engine.
		 *
		 * @since 1.6.3
		 */
		init: function() {

			$( app.ready );
		},

		ready: function() {

			$( app.bindPopup() );
		},

		/**
		 * Bind popup to the click on logger link.
		 *
		 * @since 1.6.3
		 */
		bindPopup: function() {

			$( '.wpforms-list-table--logs .wp-list-table' ).on( 'click', '.js-single-log-target', function( e ) {

				e.preventDefault();

				app.showPopup( $( this ).attr( 'data-log-id' ) );
			} );
		},

		/**
		 * Show popup.
		 *
		 * @since 1.6.3
		 *
		 * @param {numeric} recordId Record Id.
		 */
		showPopup: function( recordId ) {

			if ( ! recordId ) {
				return;
			}

			var popupTemplate = wp.template( 'wpforms-log-record' );

			$.dialog( {
				title: false,
				boxWidth: Math.min( 1200, $( window ).width() * 0.8 ),
				content: function() {

					var self = this;

					return $.get(
						wpforms_admin.ajax_url,
						{
							action: 'wpforms_get_log_record',
							nonce: wpforms_admin.nonce,
							recordId: recordId,
						}
					).done( function( res ) {

						if ( ! res.success || ! res.data ) {
							app.error( res.data );
							self.close();

							return;
						}
						self.setContent( popupTemplate( res.data ) );

					} ).fail( function( xhr, textStatus, e ) {

						app.error( textStatus + ' ' + xhr.responseText );
						self.close();
					} );
				},
				animation: 'scale',
				columnClass: 'medium',
				closeIcon: true,
				closeAnimation: 'scale',
				backgroundDismiss: true,
			} );
		},

		/**
		 * Output error to the console if debug mode is on.
		 *
		 * @since 1.6.4
		 *
		 * @param {string} msg Error text.
		 */
		error: function( msg ) {

			if ( ! wpforms_admin.debug ) {
				return;
			}

			msg = _.isEmpty( msg ) ? '' : ': ' + msg;
			console.log( 'WPForms Debug: Error receiving log record data' + msg );
		},

	};

	return app;

}( document, window, jQuery ) );

// Initialize.
WPFormsLogger.init();
