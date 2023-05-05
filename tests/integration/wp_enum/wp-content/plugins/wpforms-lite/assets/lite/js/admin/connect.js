/* global wpforms_admin */
/**
 * Connect functionality.
 *
 * @since 1.5.4
 */

'use strict';

var WPFormsConnect = window.WPFormsConnect || ( function( document, window, $ ) {

	/**
	 * Elements reference.
	 *
	 * @since 1.5.5
	 *
	 * @type {object}
	 */
	var el = {
		$connectBtn: $( '#wpforms-settings-connect-btn' ),
		$connectKey: $( '#wpforms-settings-upgrade-license-key' ),
	};

	/**
	 * Public functions and properties.
	 *
	 * @since 1.5.5
	 *
	 * @type {object}
	 */
	var app = {

		/**
		 * Start the engine.
		 *
		 * @since 1.5.5
		 */
		init: function() {

			$( app.ready );
		},

		/**
		 * Document ready.
		 *
		 * @since 1.5.5
		 */
		ready: function() {

			app.events();
		},

		/**
		 * Register JS events.
		 *
		 * @since 1.5.5
		 */
		events: function() {

			app.connectBtnClick();
		},

		/**
		 * Register connect button event.
		 *
		 * @since 1.5.5
		 */
		connectBtnClick: function() {

			el.$connectBtn.on( 'click', function() {

				app.gotoUpgradeUrl();
			} );
		},

		/**
		 * Get the alert arguments in case of Pro already installed.
		 *
		 * @since 1.5.5
		 *
		 * @param {object} res Ajax query result object.
		 *
		 * @returns {object} Alert arguments.
		 */
		proAlreadyInstalled: function( res ) {

			var buttons = {
				confirm: {
					text: wpforms_admin.plugin_activate_btn,
					btnClass: 'btn-confirm',
					keys: [ 'enter' ],
					action: function() {
						window.location.reload();
					},
				},
			};

			return {
				title: wpforms_admin.almost_done,
				content: res.data.message,
				icon: 'fa fa-check-circle',
				type: 'green',
				buttons: buttons,
			};
		},

		/**
		 * Go to upgrade url.
		 *
		 * @since 1.5.5
		 */
		gotoUpgradeUrl: function() {

			var data = {
				action: 'wpforms_connect_url',
				key:  el.$connectKey.val(),
				nonce: wpforms_admin.nonce,
			};

			$.post( wpforms_admin.ajax_url, data )
				.done( function( res ) {

					if ( res.success ) {
						if ( res.data.reload ) {
							$.alert( app.proAlreadyInstalled( res ) );
							return;
						}
						window.location.href = res.data.url;
						return;
					}
					$.alert( {
						title: wpforms_admin.oops,
						content: res.data.message,
						icon: 'fa fa-exclamation-circle',
						type: 'orange',
						buttons: {
							confirm: {
								text: wpforms_admin.ok,
								btnClass: 'btn-confirm',
								keys: [ 'enter' ],
							},
						},
					} );
				} )
				.fail( function( xhr ) {

					app.failAlert( xhr );
				} );
		},

		/**
		 * Alert in case of server error.
		 *
		 * @since 1.5.5
		 *
		 * @param {object} xhr XHR object.
		 */
		failAlert: function( xhr ) {

			$.alert( {
				title: wpforms_admin.oops,
				content: wpforms_admin.server_error + '<br>' + xhr.status + ' ' + xhr.statusText + ' ' + xhr.responseText,
				icon: 'fa fa-exclamation-circle',
				type: 'orange',
				buttons: {
					confirm: {
						text: wpforms_admin.ok,
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

// Initialize.
WPFormsConnect.init();
