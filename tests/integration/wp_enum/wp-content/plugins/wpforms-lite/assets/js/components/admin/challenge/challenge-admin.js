/* global wpforms_challenge_admin, ajaxurl, WPFormsBuilder */
/**
 * WPForms Challenge Admin function.
 *
 * @since 1.5.0
 * @since 1.6.2 Challenge v2
 */
'use strict';

var WPFormsChallenge = window.WPFormsChallenge || {};

WPFormsChallenge.admin = window.WPFormsChallenge.admin || ( function( document, window, $ ) {

	/**
	 * Public functions and properties.
	 *
	 * @since 1.5.0
	 *
	 * @type {object}
	 */
	var app = {

		l10n: wpforms_challenge_admin,

		/**
		 * Start the engine.
		 *
		 * @since 1.5.0
		 */
		init: function() {

			$( app.ready );
		},

		/**
		 * Document ready.
		 *
		 * @since 1.5.0
		 */
		ready: function() {

			app.events();
		},

		/**
		 * Register JS events.
		 *
		 * @since 1.5.0
		 */
		events: function() {

			$( '.wpforms-challenge-list-block' )
				.on( 'click', '.challenge-skip', app.skipChallenge )
				.on( 'click', '.challenge-cancel', app.cancelChallenge )
				.on( 'click', '.toggle-list', app.toggleList );
		},

		/**
		 * Toggle list icon click.
		 *
		 * @since 1.5.0
		 *
		 * @param {object} e Event object.
		 */
		toggleList: function( e ) {

			var $icon = $( e.target ),
				$listBlock = $( '.wpforms-challenge-list-block' );

			if ( ! $listBlock.length ||  ! $icon.length ) {
				return;
			}

			if ( $listBlock.hasClass( 'closed' ) ) {
				wpforms_challenge_admin.option.window_closed = '0';
				$listBlock.removeClass( 'closed' );

				setTimeout( function() {
					$listBlock.removeClass( 'transition-back' );
				}, 600 );
			} else {
				wpforms_challenge_admin.option.window_closed = '1';
				$listBlock.addClass( 'closed' );

				// Add `transition-back` class when the forward transition is completed.
				// It is needed to properly implement transitions order for some elements.
				setTimeout( function() {
					$listBlock.addClass( 'transition-back' );
				}, 600 );
			}
		},

		/**
		 * Skip the Challenge without starting it.
		 *
		 * @since 1.5.0
		 */
		skipChallenge: function() {

			var optionData = {
				status       : 'skipped',
				seconds_spent: 0,
				seconds_left : app.l10n.minutes_left * 60,
			};

			$( '.wpforms-challenge' ).remove();

			// In the Form Builder, we must also make the Embed button clickable.
			$( '#wpforms-embed' ).removeClass( 'wpforms-disabled' );

			app.saveChallengeOption( optionData );
		},

		/**
		 * Cancel Challenge after starting it.
		 *
		 * @since 1.6.2
		 */
		cancelChallenge: function() {

			var core = WPFormsChallenge.core;

			core.timer.pause();

			/* eslint-disable camelcase */
			var optionData = {
				status       : 'canceled',
				seconds_spent: core.timer.getSecondsSpent(),
				seconds_left : core.timer.getSecondsLeft(),
				feedback_sent: false,
			};
			/* eslint-enable */

			core.removeChallengeUI();
			core.clearLocalStorage();

			if ( typeof WPFormsBuilder !== 'undefined' ) {
				WPFormsChallenge.admin.saveChallengeOption( optionData )
					.done( function() { // Save the form before removing scripts if we're in a WPForms Builder.
						if ( localStorage.getItem( 'wpformsChallengeStep' ) !==  null ) {
							WPFormsBuilder.formSave( false );
						}
					} ).done( // Remove scripts related to challenge.
						$( '#wpforms-challenge-admin-js, #wpforms-challenge-core-js, #wpforms-challenge-admin-js-extra, #wpforms-challenge-builder-js' )
							.remove()
					);
			} else {
				WPFormsChallenge.admin.saveChallengeOption( optionData )
					.done( app.triggerPageSave ); // Assume we're on form embed page.
			}
		},

		/**
		 * Set Challenge parameter(s) to Challenge option.
		 *
		 * @since 1.5.0
		 *
		 * @param {object} optionData Query using option schema keys.
		 *
		 * @returns {promise} jQuery.post() promise interface.
		 */
		saveChallengeOption: function( optionData ) {

			var data = {
				action     : 'wpforms_challenge_save_option',
				option_data: optionData,
				_wpnonce   : app.l10n.nonce,
			};

			// Save window closed (collapsed) state as well.
			data.option_data.window_closed = wpforms_challenge_admin.option.window_closed;

			$.extend( wpforms_challenge_admin.option, optionData );

			return $.post( ajaxurl, data, function( response ) {
				if ( ! response.success ) {
					console.error( 'Error saving WPForms Challenge option.' );
				}
			} );
		},
	};

	// Provide access to public functions/properties.
	return app;

}( document, window, jQuery ) );

WPFormsChallenge.admin.init();
